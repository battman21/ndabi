#!/usr/bin/env python3
"""Run the frozen v3.5 paired PostgreSQL replay campaign."""

from __future__ import annotations

import json
import math
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CLIENT_IMAGE = "ndabi-showdown:v3.5-local"
EXPECTED_CLIENT_IMAGE_ID = "sha256:2ae617a01b024a8326451dd177fb5834e0085a1323ddc769d00ef4120c7f9d47"
EXPECTED_BINARY_SHA256 = "239dff20c681d9abab380ddb7361ad5d562cff73013a2d32facaa54365f4577c"
POSTGRES_IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
RESULT_ROOT = ROOT / "results" / "v35"
PROCESS_COUNT = 5
ARMS = ["native-ephemeral", "ndabi-ephemeral", "native-resumable", "ndabi-resumable"]
BATCH_SIZES = [32, 128]
CONCURRENCY_LEVELS = [1, 8, 32, 128]
REQUESTS_PER_WORKER = 63


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil((len(ordered) - 1) * quantile)]


def coefficient(values: list[float]) -> float:
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else float("inf")


def latency_case(result: dict, batch_size: int) -> dict:
    return next(item for item in result["latency_cases"] if item["batch_size"] == batch_size)


def latency_measurement(result: dict, batch_size: int, arm: str) -> dict:
    return next(item for item in latency_case(result, batch_size)["measurements"] if item["id"] == arm)


def concurrency_case(result: dict, concurrency: int) -> dict:
    return next(item for item in result["concurrency_cases"] if item["concurrency"] == concurrency)


def concurrency_measurement(result: dict, concurrency: int, arm: str) -> dict:
    return next(item for item in concurrency_case(result, concurrency)["measurements"] if item["id"] == arm)


def valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_result(result: dict) -> None:
    require(result.get("schema") == "ndabi-postgresql-paired-replay-v3.5", "invalid schema")
    require(result.get("status") == "paired-process-diagnostic", "invalid status")
    require(result.get("client_architecture") == "aarch64", "invalid client architecture")
    require(result.get("client_operating_system") == "linux", "invalid client operating system")
    require(result.get("rows") == 100_000, "invalid dataset size")
    require(result.get("correctness_gate_passed") is True, "failed process correctness gate")
    security = result.get("security")
    require(isinstance(security, dict), "invalid security proof")
    for name in (
        "restart_invalidated_old_frame",
        "killed_transaction_left_no_nonce",
        "committed_replay_refused",
    ):
        require(security.get(name) is True, f"failed security proof: {name}")
    require(security.get("borrowed_decode_allocations") == 0, "decoder allocated objects")
    require(security.get("borrowed_decode_allocated_bytes") == 0, "decoder allocated bytes")

    latency = result.get("latency_cases")
    require(isinstance(latency, list) and len(latency) == 2, "invalid latency cases")
    require(sorted(item.get("batch_size") for item in latency) == BATCH_SIZES, "invalid batch sizes")
    for batch_size in BATCH_SIZES:
        item = latency_case(result, batch_size)
        require(item.get("frame_bytes") == 96 + batch_size * 8, "invalid frame size")
        require(valid_digest(item.get("canonical_sha256")), "invalid canonical digest")
        require(valid_digest(item.get("receipt_sha256")), "invalid receipt digest")
        values = item.get("measurements")
        require(isinstance(values, list) and len(values) == 4, "invalid latency measurements")
        require(sorted(value.get("id") for value in values) == sorted(ARMS), "invalid latency arms")
        for value in values:
            raw = value.get("raw_batch_ns")
            require(
                isinstance(raw, list)
                and len(raw) == 63
                and all(isinstance(sample, int) and sample > 0 for sample in raw),
                "invalid latency samples",
            )
            require(value.get("median_batch_ns") == percentile(raw, 0.50), "invalid median")
            require(value.get("p95_batch_ns") == percentile(raw, 0.95), "invalid latency p95")
            require(value.get("p99_batch_ns") == percentile(raw, 0.99), "invalid latency p99")

    concurrent = result.get("concurrency_cases")
    require(isinstance(concurrent, list) and len(concurrent) == 4, "invalid concurrency cases")
    require(
        sorted(item.get("concurrency") for item in concurrent) == CONCURRENCY_LEVELS,
        "invalid concurrency levels",
    )
    for concurrency in CONCURRENCY_LEVELS:
        values = concurrency_case(result, concurrency).get("measurements")
        require(isinstance(values, list) and len(values) == 4, "invalid concurrency measurements")
        require(sorted(value.get("id") for value in values) == sorted(ARMS), "invalid concurrency arms")
        for value in values:
            raw = value.get("raw_request_ns")
            require(
                isinstance(raw, list)
                and len(raw) == concurrency * REQUESTS_PER_WORKER
                and all(isinstance(sample, int) and sample > 0 for sample in raw),
                "invalid paired samples",
            )
            require(value.get("completed_requests") == len(raw), "invalid completion count")
            require(value.get("p95_request_ns") == percentile(raw, 0.95), "invalid paired p95")
            require(value.get("operations_per_second", 0) > 0, "invalid paired throughput")


def check(identifier: str, passed: bool, observed: object, target: str) -> dict:
    return {"id": identifier, "passed": passed, "observed": observed, "target": target}


def ratio_gate(
    checks: list[dict], identifier: str, values: list[float], passed: bool, target: str
) -> None:
    checks.append(check(identifier, passed, values, target))
    variation = coefficient(values)
    checks.append(
        check(
            f"{identifier}-repeatability",
            variation < 0.20,
            {"ratios": values, "coefficient_of_variation": variation},
            "coefficient below 0.20",
        )
    )


def aggregate(
    results: list[dict], exit_codes: list[int], campaign_id: str, postgres_image_id: str
) -> dict:
    checks = [
        check(
            "five-complete-processes",
            len(results) == PROCESS_COUNT and len(exit_codes) == PROCESS_COUNT,
            {"results": len(results), "exit_codes": exit_codes},
            "five complete results",
        ),
        check("five-zero-exit-codes", exit_codes == [0] * PROCESS_COUNT, exit_codes, "five zero exit codes"),
        check(
            "all-process-correctness-gates",
            all(result.get("correctness_gate_passed") is True for result in results),
            sum(result.get("correctness_gate_passed") is True for result in results),
            "5/5",
        ),
    ]
    latency = []
    for batch_size in BATCH_SIZES:
        p95 = {
            arm: [latency_measurement(result, batch_size, arm)["p95_batch_ns"] for result in results]
            for arm in ARMS
        }
        median_p95 = {arm: statistics.median(values) for arm, values in p95.items()}
        ephemeral_ratio = median_p95["ndabi-ephemeral"] / median_p95["native-ephemeral"]
        resumable_ratio = median_p95["ndabi-resumable"] / median_p95["native-resumable"]
        ephemeral_process = [latency_case(result, batch_size)["ephemeral_distance"] for result in results]
        resumable_process = [latency_case(result, batch_size)["resumable_distance"] for result in results]
        ratio_gate(
            checks,
            f"batch-{batch_size}-ephemeral-distance",
            ephemeral_process,
            ephemeral_ratio <= 1.05,
            "aggregate p95 no more than 1.05x",
        )
        ratio_gate(
            checks,
            f"batch-{batch_size}-resumable-distance",
            resumable_process,
            resumable_ratio <= 1.10,
            "aggregate p95 no more than 1.10x",
        )
        identities = {
            (latency_case(result, batch_size)["canonical_sha256"], latency_case(result, batch_size)["receipt_sha256"])
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
        latency.append(
            {
                "batch_size": batch_size,
                "median_process_p95_ns": median_p95,
                "ephemeral_distance": ephemeral_ratio,
                "resumable_distance": resumable_ratio,
            }
        )

    concurrency = []
    for level in CONCURRENCY_LEVELS:
        throughput = {
            arm: [
                concurrency_measurement(result, level, arm)["operations_per_second"]
                for result in results
            ]
            for arm in ARMS
        }
        p95 = {
            arm: [concurrency_measurement(result, level, arm)["p95_request_ns"] for result in results]
            for arm in ARMS
        }
        median_throughput = {arm: statistics.median(values) for arm, values in throughput.items()}
        median_p95 = {arm: statistics.median(values) for arm, values in p95.items()}
        ephemeral_throughput = median_throughput["ndabi-ephemeral"] / median_throughput["native-ephemeral"]
        resumable_throughput = median_throughput["ndabi-resumable"] / median_throughput["native-resumable"]
        ephemeral_p95 = median_p95["ndabi-ephemeral"] / median_p95["native-ephemeral"]
        resumable_p95 = median_p95["ndabi-resumable"] / median_p95["native-resumable"]
        process_ephemeral_throughput = [
            concurrency_case(result, level)["ephemeral_throughput_ratio"] for result in results
        ]
        process_resumable_throughput = [
            concurrency_case(result, level)["resumable_throughput_ratio"] for result in results
        ]
        process_ephemeral_p95 = [
            concurrency_case(result, level)["ephemeral_p95_distance"] for result in results
        ]
        process_resumable_p95 = [
            concurrency_case(result, level)["resumable_p95_distance"] for result in results
        ]
        ratio_gate(
            checks,
            f"concurrency-{level}-ephemeral-throughput",
            process_ephemeral_throughput,
            ephemeral_throughput >= 0.90,
            "aggregate throughput at least 0.90x",
        )
        ratio_gate(
            checks,
            f"concurrency-{level}-resumable-throughput",
            process_resumable_throughput,
            resumable_throughput >= 0.90,
            "aggregate throughput at least 0.90x",
        )
        ratio_gate(
            checks,
            f"concurrency-{level}-ephemeral-p95",
            process_ephemeral_p95,
            ephemeral_p95 <= 1.15,
            "aggregate p95 no more than 1.15x",
        )
        ratio_gate(
            checks,
            f"concurrency-{level}-resumable-p95",
            process_resumable_p95,
            resumable_p95 <= 1.15,
            "aggregate p95 no more than 1.15x",
        )
        concurrency.append(
            {
                "concurrency": level,
                "median_process_operations_per_second": median_throughput,
                "median_process_p95_ns": median_p95,
                "ephemeral_throughput_ratio": ephemeral_throughput,
                "resumable_throughput_ratio": resumable_throughput,
                "ephemeral_p95_distance": ephemeral_p95,
                "resumable_p95_distance": resumable_p95,
            }
        )
    passed = all(item["passed"] for item in checks)
    return {
        "schema": "ndabi-postgresql-paired-replay-process-v3.5",
        "campaign_id": campaign_id,
        "status": "accepted" if passed else "failed",
        "binary": {"path": "/usr/local/bin/ndabi_v35", "sha256": EXPECTED_BINARY_SHA256},
        "client_image": {"reference": CLIENT_IMAGE, "id": EXPECTED_CLIENT_IMAGE_ID},
        "postgres_image": {"reference": POSTGRES_IMAGE, "id": postgres_image_id},
        "processes": PROCESS_COUNT,
        "latency": latency,
        "concurrency": concurrency,
        "hard_gate": {"passed": passed, "checks": checks},
    }


def command(*arguments: str, check_result: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, capture_output=True, text=True, check=check_result)


def main() -> int:
    client_image_id = command(
        "docker", "image", "inspect", "--format", "{{.Id}}", CLIENT_IMAGE
    ).stdout.strip()
    if client_image_id != EXPECTED_CLIENT_IMAGE_ID:
        raise SystemExit("the frozen v3.5 client image digest changed")
    binary_line = command(
        "docker", "run", "--rm", "--entrypoint", "sha256sum", CLIENT_IMAGE,
        "/usr/local/bin/ndabi_v35",
    ).stdout.strip()
    if binary_line.split(maxsplit=1)[0] != EXPECTED_BINARY_SHA256:
        raise SystemExit("the frozen v3.5 binary digest changed")
    campaign_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{time.time_ns()}"
    directory = RESULT_ROOT / campaign_id
    directory.mkdir(parents=True, exist_ok=False)
    container = f"ndabi-v35-postgres-{time.time_ns()}"
    network = f"ndabi-v35-network-{time.time_ns()}"
    results = []
    exit_codes = []
    try:
        command("docker", "network", "create", network)
        command(
            "docker", "run", "--detach", "--rm", "--name", container,
            "--network", network, "--env", "POSTGRES_PASSWORD=ndabi-test-only",
            POSTGRES_IMAGE, "-c", "max_connections=200",
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
            except (KeyError, TypeError, ValueError, StopIteration) as error:
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
