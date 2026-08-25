#!/usr/bin/env python3
"""Run the frozen v3.2 PostgreSQL column-batch process campaign."""

from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v32"
EXPECTED_BINARY_SHA256 = "8a37036e62e2e2435c33ea8c5a81aa816bad64dc92047d1d568657a2e5e64a88"
IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
RESULT_ROOT = ROOT / "results" / "v32"
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


def aggregate(results: list[dict], exit_codes: list[int], campaign_id: str, image_id: str) -> dict:
    cases = []
    checks = [
        check(
            "five-complete-processes",
            len(results) == PROCESS_COUNT and all(code in (0, 1) for code in exit_codes),
            {"results": len(results), "exit_codes": exit_codes},
            "five complete results and exit status zero or local-performance one",
        ),
        check(
            "all-correctness-gates",
            all(correctness_passed(result) for result in results),
            sum(correctness_passed(result) for result in results),
            "5/5",
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
                        coefficient(sequential_ratios) < 0.20,
                        {"ratios": sequential_ratios, "coefficient_of_variation": coefficient(sequential_ratios)},
                        "coefficient below 0.20",
                    ),
                    check(
                        f"batch-{batch_size}-native-distance-repeatability",
                        coefficient(native_ratios) < 0.20,
                        {"ratios": native_ratios, "coefficient_of_variation": coefficient(native_ratios)},
                        "coefficient below 0.20",
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
        "schema": "ndabi-postgresql-column-batch-process-v3.2",
        "campaign_id": campaign_id,
        "status": "accepted" if all(item["passed"] for item in checks) else "failed",
        "binary": {"path": str(BINARY.relative_to(ROOT)), "sha256": sha256(BINARY)},
        "image": {"reference": IMAGE, "id": image_id},
        "processes": PROCESS_COUNT,
        "cases": cases,
        "hard_gate": {"passed": all(item["passed"] for item in checks), "checks": checks},
    }


def command(*arguments: str, check_result: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, capture_output=True, text=True, check=check_result)


def main() -> int:
    if sha256(BINARY) != EXPECTED_BINARY_SHA256:
        raise SystemExit("the frozen v3.2 binary digest changed")
    campaign_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{time.time_ns()}"
    directory = RESULT_ROOT / campaign_id
    directory.mkdir(parents=True, exist_ok=False)
    container = f"ndabi-v32-{time.time_ns()}"
    results = []
    exit_codes = []
    try:
        command(
            "docker", "run", "--detach", "--rm", "--name", container,
            "--env", "POSTGRES_PASSWORD=ndabi-test-only", "--publish", "127.0.0.1::5432", IMAGE,
        )
        for _ in range(30):
            ready = command("docker", "exec", container, "pg_isready", "-U", "postgres", check_result=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise SystemExit("the PostgreSQL container did not become ready")
        port_line = command("docker", "port", container, "5432/tcp").stdout.strip()
        port = port_line.rsplit(":", 1)[1]
        image_id = command("docker", "inspect", "--format", "{{.Image}}", container).stdout.strip()
        connection = f"host=127.0.0.1 port={port} user=postgres password=ndabi-test-only dbname=postgres"
        preparation = command(str(BINARY), connection, "--prepare", check_result=False)
        if preparation.returncode != 0:
            raise SystemExit(f"dataset preparation failed: {preparation.stderr}")
        for index in range(PROCESS_COUNT):
            completed = command(str(BINARY), connection, check_result=False)
            exit_codes.append(completed.returncode)
            if completed.stderr:
                (directory / f"process-{index:02d}.stderr").write_text(completed.stderr, encoding="utf-8")
            try:
                result = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                raise SystemExit(f"process {index} did not return complete JSON: {error}") from error
            (directory / f"process-{index:02d}.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
            results.append(result)
        summary = aggregate(results, exit_codes, campaign_id, image_id)
        (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        (RESULT_ROOT / "latest.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2))
        return 0 if summary["hard_gate"]["passed"] else 1
    finally:
        command("docker", "stop", container, check_result=False)


if __name__ == "__main__":
    raise SystemExit(main())
