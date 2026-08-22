#!/usr/bin/env python3
"""Run the frozen v3.3 PostgreSQL column-batch process campaign."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CLIENT_IMAGE = "ndabi-showdown:v3.3-local"
EXPECTED_CLIENT_IMAGE_ID = "sha256:211204c7b83c88f6a7101311663efe9893183fa4597edff37a85e606a35d5943"
EXPECTED_BINARY_SHA256 = "55eebb3e4686363ae80264a5e4cdb817a1117f34bc41304be4b8b35cd3cc1116"
POSTGRES_IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
RESULT_ROOT = ROOT / "results" / "v33"
PROCESS_COUNT = 5
ARMS = ["sequential-prepared", "native-set", "native-pipeline", "ndabi-set"]
BATCH_SIZES = [8, 32, 128]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def coefficient(values: list[float]) -> float:
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else float("inf")


def case(result: dict, batch_size: int) -> dict:
    return next(item for item in result["cases"] if item["batch_size"] == batch_size)


def measurement(result: dict, batch_size: int, arm: str) -> dict:
    return next(item for item in case(result, batch_size)["measurements"] if item["id"] == arm)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil((len(ordered) - 1) * quantile)]


def validate_result(result: dict) -> None:
    require(result.get("schema") == "ndabi-postgresql-column-batch-v3.3", "invalid schema")
    require(result.get("status") == "linux-container-relative-diagnostic", "invalid status")
    require(result.get("client_architecture") == "aarch64", "invalid client architecture")
    require(result.get("client_operating_system") == "linux", "invalid client operating system")
    require(result.get("rows") == 100_000, "invalid dataset size")
    require(isinstance(result.get("postgresql_version"), str), "invalid PostgreSQL version")
    require(result.get("borrowed_decode_allocations") == 0, "decoder allocated objects")
    require(result.get("borrowed_decode_allocated_bytes") == 0, "decoder allocated bytes")
    cases = result.get("cases")
    require(isinstance(cases, list) and len(cases) == len(BATCH_SIZES), "invalid case count")
    require(sorted(item.get("batch_size") for item in cases) == BATCH_SIZES, "invalid cases")
    for batch_size in BATCH_SIZES:
        item = case(result, batch_size)
        require(item.get("frame_bytes") == 96 + batch_size * 8, "invalid frame bytes")
        for digest_name in ("canonical_sha256", "receipt_sha256"):
            digest = item.get(digest_name)
            require(
                isinstance(digest, str)
                and len(digest) == 64
                and all(character in "0123456789abcdef" for character in digest),
                f"invalid {digest_name}",
            )
        values = item.get("measurements")
        require(isinstance(values, list) and len(values) == len(ARMS), "invalid measurements")
        require(sorted(value.get("id") for value in values) == sorted(ARMS), "invalid arms")
        for value in values:
            raw = value.get("raw_batch_ns")
            require(
                isinstance(raw, list)
                and len(raw) == 63
                and all(isinstance(sample, int) and sample > 0 for sample in raw),
                "invalid raw samples",
            )
            require(value.get("samples") == 63, "invalid sample count")
            require(value.get("operations_per_batch") == batch_size, "invalid batch size")
            require(value.get("median_batch_ns") == percentile(raw, 0.50), "invalid median")
            require(value.get("p95_batch_ns") == percentile(raw, 0.95), "invalid p95")
            require(value.get("p99_batch_ns") == percentile(raw, 0.99), "invalid p99")


def correctness_passed(result: dict) -> bool:
    if result["borrowed_decode_allocations"] != 0 or result["borrowed_decode_allocated_bytes"] != 0:
        return False
    for batch_size in BATCH_SIZES:
        checks = {item["id"]: item["passed"] for item in case(result, batch_size)["gates"]}
        if (
            checks.get("literal-result-and-receipt-equality") is not True
            or checks.get("column-frame-size") is not True
        ):
            return False
    return True


def check(identifier: str, passed: bool, observed: object, target: str) -> dict:
    return {"id": identifier, "passed": passed, "observed": observed, "target": target}


def aggregate(
    results: list[dict], exit_codes: list[int], campaign_id: str, postgres_image_id: str
) -> dict:
    cases = []
    checks = [
        check(
            "five-complete-processes",
            len(results) == PROCESS_COUNT and all(code == 0 for code in exit_codes),
            {"results": len(results), "exit_codes": exit_codes},
            "five complete results and five zero exit codes",
        ),
        check(
            "all-correctness-gates",
            all(correctness_passed(result) for result in results),
            sum(correctness_passed(result) for result in results),
            "5/5",
        ),
        check(
            "all-process-hard-gates",
            all(result.get("hard_gate_passed") is True for result in results),
            sum(result.get("hard_gate_passed") is True for result in results),
            "5/5",
        ),
        check(
            "all-linux-arm64-clients",
            all(
                result.get("client_architecture") == "aarch64"
                and result.get("client_operating_system") == "linux"
                for result in results
            ),
            [
                [result.get("client_architecture"), result.get("client_operating_system")]
                for result in results
            ],
            "5/5 aarch64 Linux",
        ),
    ]
    for batch_size in BATCH_SIZES:
        p95 = {
            arm: [measurement(result, batch_size, arm)["p95_batch_ns"] for result in results]
            for arm in ARMS
        }
        median_p95 = {arm: statistics.median(values) for arm, values in p95.items()}
        sequential_ratios = [
            measurement(result, batch_size, "sequential-prepared")["p95_batch_ns"]
            / measurement(result, batch_size, "ndabi-set")["p95_batch_ns"]
            for result in results
        ]
        native_ratios = [
            measurement(result, batch_size, "ndabi-set")["p95_batch_ns"]
            / measurement(result, batch_size, "native-set")["p95_batch_ns"]
            for result in results
        ]
        ratios = {
            "sequential_over_ndabi": median_p95["sequential-prepared"] / median_p95["ndabi-set"],
            "ndabi_over_native_set": median_p95["ndabi-set"] / median_p95["native-set"],
        }
        identities = {
            (case(result, batch_size)["canonical_sha256"], case(result, batch_size)["receipt_sha256"])
            for result in results
        }
        checks.append(
            check(
                f"batch-{batch_size}-one-result-identity",
                len(identities) == 1,
                sorted(identities),
                "one payload and receipt identity",
            )
        )
        if batch_size >= 32:
            checks.extend(
                [
                    check(
                        f"batch-{batch_size}-round-trip-removal",
                        ratios["sequential_over_ndabi"] >= 4.0,
                        ratios["sequential_over_ndabi"],
                        "at least 4.00x",
                    ),
                    check(
                        f"batch-{batch_size}-native-distance",
                        ratios["ndabi_over_native_set"] <= 1.10,
                        ratios["ndabi_over_native_set"],
                        "no more than 1.10x",
                    ),
                    check(
                        f"batch-{batch_size}-round-trip-repeatability",
                        coefficient(sequential_ratios) < 0.15,
                        {"ratios": sequential_ratios, "coefficient_of_variation": coefficient(sequential_ratios)},
                        "coefficient below 0.15",
                    ),
                    check(
                        f"batch-{batch_size}-native-distance-repeatability",
                        coefficient(native_ratios) < 0.15,
                        {"ratios": native_ratios, "coefficient_of_variation": coefficient(native_ratios)},
                        "coefficient below 0.15",
                    ),
                ]
            )
        cases.append(
            {
                "batch_size": batch_size,
                "median_process_p95_ns": median_p95,
                "ratios": ratios,
                "process_sequential_ratios": sequential_ratios,
                "process_native_distance_ratios": native_ratios,
            }
        )
    return {
        "schema": "ndabi-postgresql-column-batch-process-v3.3",
        "campaign_id": campaign_id,
        "status": "accepted" if all(item["passed"] for item in checks) else "failed",
        "binary": {"path": "/usr/local/bin/ndabi_v33", "sha256": EXPECTED_BINARY_SHA256},
        "client_image": {"reference": CLIENT_IMAGE, "id": EXPECTED_CLIENT_IMAGE_ID},
        "postgres_image": {"reference": POSTGRES_IMAGE, "id": postgres_image_id},
        "processes": PROCESS_COUNT,
        "cases": cases,
        "hard_gate": {"passed": all(item["passed"] for item in checks), "checks": checks},
    }


def command(*arguments: str, check_result: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, capture_output=True, text=True, check=check_result)


def main() -> int:
    client_image_id = command(
        "docker", "image", "inspect", "--format", "{{.Id}}", CLIENT_IMAGE
    ).stdout.strip()
    if client_image_id != EXPECTED_CLIENT_IMAGE_ID:
        raise SystemExit("the frozen v3.3 client image digest changed")
    binary_line = command(
        "docker", "run", "--rm", "--entrypoint", "sha256sum", CLIENT_IMAGE,
        "/usr/local/bin/ndabi_v33",
    ).stdout.strip()
    if binary_line.split(maxsplit=1)[0] != EXPECTED_BINARY_SHA256:
        raise SystemExit("the frozen v3.3 binary digest changed")
    campaign_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{time.time_ns()}"
    directory = RESULT_ROOT / campaign_id
    directory.mkdir(parents=True, exist_ok=False)
    container = f"ndabi-v33-postgres-{time.time_ns()}"
    network = f"ndabi-v33-network-{time.time_ns()}"
    results = []
    exit_codes = []
    try:
        command("docker", "network", "create", network)
        command(
            "docker", "run", "--detach", "--rm", "--name", container,
            "--network", network, "--env", "POSTGRES_PASSWORD=ndabi-test-only", POSTGRES_IMAGE,
        )
        for _ in range(30):
            ready = command("docker", "exec", container, "pg_isready", "-U", "postgres", check_result=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise SystemExit("the PostgreSQL container did not become ready")
        postgres_image_id = command(
            "docker", "inspect", "--format", "{{.Image}}", container
        ).stdout.strip()
        connection = (
            f"host={container} port=5432 user=postgres "
            "password=ndabi-test-only dbname=postgres"
        )
        preparation = command(
            "docker", "run", "--rm", "--network", network, CLIENT_IMAGE,
            connection, "--prepare", check_result=False,
        )
        if preparation.returncode != 0:
            raise SystemExit(f"dataset preparation failed: {preparation.stderr}")
        for index in range(PROCESS_COUNT):
            completed = command(
                "docker", "run", "--rm", "--network", network, CLIENT_IMAGE,
                connection, check_result=False,
            )
            exit_codes.append(completed.returncode)
            if completed.stderr:
                (directory / f"process-{index:02d}.stderr").write_text(completed.stderr, encoding="utf-8")
            try:
                result = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                raise SystemExit(f"process {index} did not return complete JSON: {error}") from error
            try:
                validate_result(result)
            except (TypeError, ValueError, StopIteration) as error:
                raise SystemExit(f"process {index} returned invalid evidence: {error}") from error
            (directory / f"process-{index:02d}.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
            results.append(result)
        summary = aggregate(results, exit_codes, campaign_id, postgres_image_id)
        (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        (RESULT_ROOT / "latest.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2))
        return 0 if summary["hard_gate"]["passed"] else 1
    finally:
        command("docker", "stop", container, check_result=False)
        command("docker", "network", "rm", network, check_result=False)


if __name__ == "__main__":
    raise SystemExit(main())
