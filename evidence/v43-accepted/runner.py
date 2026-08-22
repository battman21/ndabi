#!/usr/bin/env python3
"""Run and validate the frozen local Docker NDABI v4.3 repair campaign."""

from __future__ import annotations

import json
import math
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CLIENT_IMAGE = "ndabi-showdown:v4.3-local"
EXPECTED_CLIENT_IMAGE_ID = "sha256:7dc7d9e6fdd1e207b924e4d11564eb475aaffb5f6a3bc2fa6e4636adadfcb6f6"
EXPECTED_BINARY_SHA256 = "8319e91825d7d164a73e6a87bd0b66f2e4753b690221969c4b7736432b33cdb8"
POSTGRES_IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
EXPECTED_POSTGRES_IMAGE_ID = "sha256:eb9fe6b5815523ffa3e3d8aee9db3532bd564b857634fcfa36979d76bed6ae10"
RESULT_ROOT = ROOT / "results" / "v43"
PROCESS_COUNT = 5
SAMPLES = 63
CASES = ["range-128", "predicate-64", "aggregate", "join-64", "large-range-4096"]
ARMS = ["native-prepared", "compact-json", "ndabi-embedded"]
SECURITY_CHECKS = [
    "changed_frame_refused",
    "replay_refused",
    "cross_session_refused",
    "expired_frame_refused",
    "excessive_budget_refused",
    "backend_failure_preserved_nonce",
    "arbitrary_sql_refused",
    "write_operation_refused",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil((len(ordered) - 1) * quantile)]


def case(result: dict, identifier: str) -> dict:
    return next(item for item in result["cases"] if item["id"] == identifier)


def measurement(result: dict, case_id: str, arm: str) -> dict:
    return next(item for item in case(result, case_id)["measurements"] if item["id"] == arm)


def valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_result(result: dict) -> None:
    require(result.get("schema") == "ndabi-postgresql-scale-shapes-v4.2", "invalid schema")
    require(result.get("status") == "local-docker-process-diagnostic", "invalid status")
    require(result.get("client_operating_system") == "linux", "invalid operating system")
    require(result.get("client_architecture") == "aarch64", "invalid architecture")
    require(result.get("rows") == 1_000_000, "invalid row count")
    require(result.get("correctness_gate_passed") is True, "failed correctness gate")
    require(isinstance(result.get("client_max_rss_kib"), int), "invalid client memory")
    require(result["client_max_rss_kib"] > 0, "missing client memory")
    security = result.get("security")
    require(isinstance(security, dict), "invalid security result")
    for identifier in SECURITY_CHECKS:
        require(security.get(identifier) is True, f"failed security check: {identifier}")
    reports = result.get("cases")
    require(isinstance(reports, list) and len(reports) == len(CASES), "invalid cases")
    require(sorted(item.get("id") for item in reports) == sorted(CASES), "changed cases")
    for case_id in CASES:
        report = case(result, case_id)
        require(valid_digest(report.get("result_sha256")), "invalid result digest")
        require(valid_digest(report.get("ndabi_receipt_sha256")), "invalid receipt digest")
        measurements = report.get("measurements")
        require(isinstance(measurements, list) and len(measurements) == len(ARMS), "invalid arms")
        require(sorted(item.get("id") for item in measurements) == sorted(ARMS), "changed arms")
        response_sizes = set()
        for item in measurements:
            raw_wall = item.get("raw_ns")
            raw_cpu = item.get("raw_client_cpu_ns")
            require(
                isinstance(raw_wall, list)
                and len(raw_wall) == SAMPLES
                and all(isinstance(value, int) and value > 0 for value in raw_wall),
                "invalid wall samples",
            )
            require(
                isinstance(raw_cpu, list)
                and len(raw_cpu) == SAMPLES
                and all(isinstance(value, int) and value > 0 for value in raw_cpu),
                "invalid CPU samples",
            )
            require(item.get("median_ns") == percentile(raw_wall, 0.50), "invalid median")
            require(item.get("p95_ns") == percentile(raw_wall, 0.95), "invalid p95")
            require(item.get("p99_ns") == percentile(raw_wall, 0.99), "invalid p99")
            require(
                item.get("median_client_cpu_ns") == percentile(raw_cpu, 0.50),
                "invalid CPU median",
            )
            require(item.get("mean_allocations", 0) > 0, "missing allocation count")
            require(item.get("mean_allocated_bytes", 0) > 0, "missing allocated bytes")
            response_sizes.add(item.get("response_bytes"))
        require(len(response_sizes) == 1, "changed response size")
        native = measurement(result, case_id, "native-prepared")
        json_arm = measurement(result, case_id, "compact-json")
        ndabi = measurement(result, case_id, "ndabi-embedded")
        require(native.get("request_bytes") is None, "native request bytes changed")
        require(ndabi.get("request_bytes") == 76, "NDABI frame size changed")
        require(isinstance(json_arm.get("request_bytes"), int), "missing JSON request bytes")
        require(
            math.isclose(
                report["ndabi_native_p95_distance"],
                ndabi["p95_ns"] / native["p95_ns"],
                rel_tol=1e-12,
            ),
            "changed p95 ratio",
        )
        require(
            math.isclose(
                report["ndabi_native_cpu_distance"],
                ndabi["median_client_cpu_ns"] / native["median_client_cpu_ns"],
                rel_tol=1e-12,
            ),
            "changed CPU ratio",
        )
        require(
            math.isclose(
                report["request_compression"],
                1.0 - ndabi["request_bytes"] / json_arm["request_bytes"],
                rel_tol=1e-12,
            ),
            "changed compression ratio",
        )


def check(identifier: str, passed: bool, observed: object, target: str) -> dict:
    return {"id": identifier, "passed": passed, "observed": observed, "target": target}


def aggregate(
    results: list[dict],
    exit_codes: list[int],
    campaign_id: str,
    image_ids: dict[str, str],
    postgres_memory_peak_bytes: int,
) -> dict:
    checks = [
        check("five-complete-processes", len(results) == PROCESS_COUNT, len(results), "5"),
        check("five-zero-exit-codes", exit_codes == [0] * PROCESS_COUNT, exit_codes, "five zero exits"),
        check(
            "all-correctness-gates",
            all(result["correctness_gate_passed"] for result in results),
            sum(result["correctness_gate_passed"] for result in results),
            "5/5",
        ),
        check(
            "all-security-checks",
            all(all(result["security"][name] for name in SECURITY_CHECKS) for result in results),
            sum(sum(result["security"][name] for name in SECURITY_CHECKS) for result in results),
            "40/40",
        ),
    ]
    summaries = []
    for case_id in CASES:
        median_p95 = {
            arm: statistics.median(measurement(result, case_id, arm)["p95_ns"] for result in results)
            for arm in ARMS
        }
        median_cpu = {
            arm: statistics.median(
                measurement(result, case_id, arm)["median_client_cpu_ns"] for result in results
            )
            for arm in ARMS
        }
        median_allocations = {
            arm: statistics.median(
                measurement(result, case_id, arm)["mean_allocations"] for result in results
            )
            for arm in ARMS
        }
        compression = statistics.median(case(result, case_id)["request_compression"] for result in results)
        result_identities = {case(result, case_id)["result_sha256"] for result in results}
        receipt_identities = {case(result, case_id)["ndabi_receipt_sha256"] for result in results}
        p95_distance = median_p95["ndabi-embedded"] / median_p95["native-prepared"]
        cpu_distance = median_cpu["ndabi-embedded"] / median_cpu["native-prepared"]
        allocation_distance = median_allocations["ndabi-embedded"] - median_allocations["native-prepared"]
        checks.extend(
            [
                check(f"{case_id}-p95", p95_distance <= 1.15, p95_distance, "no more than 1.15x native"),
                check(f"{case_id}-cpu", cpu_distance <= 1.25, cpu_distance, "no more than 1.25x native"),
                check(f"{case_id}-allocations", allocation_distance <= 5, allocation_distance, "no more than five added allocations"),
                check(f"{case_id}-compression", compression >= 0.70, compression, "at least 70%"),
                check(f"{case_id}-result-identity", len(result_identities) == 1, sorted(result_identities), "one identity"),
                check(f"{case_id}-receipt-identity", len(receipt_identities) == 1, sorted(receipt_identities), "one identity"),
            ]
        )
        summaries.append(
            {
                "id": case_id,
                "median_process_p95_ns": median_p95,
                "median_process_client_cpu_ns": median_cpu,
                "median_process_mean_allocations": median_allocations,
                "ndabi_native_p95_distance": p95_distance,
                "ndabi_native_cpu_distance": cpu_distance,
                "ndabi_native_added_allocations": allocation_distance,
                "request_compression": compression,
                "response_bytes": statistics.median(
                    measurement(result, case_id, "ndabi-embedded")["response_bytes"]
                    for result in results
                ),
            }
        )
    passed = all(item["passed"] for item in checks)
    return {
        "schema": "ndabi-postgresql-repaired-adapter-campaign-v4.3",
        "campaign_id": campaign_id,
        "status": "accepted" if passed else "failed",
        "binary": {"path": "/usr/local/bin/ndabi_v42", "sha256": EXPECTED_BINARY_SHA256},
        "images": image_ids,
        "processes": len(results),
        "cases": summaries,
        "client_max_rss_kib": {
            "minimum": min(result["client_max_rss_kib"] for result in results),
            "median": statistics.median(result["client_max_rss_kib"] for result in results),
            "maximum": max(result["client_max_rss_kib"] for result in results),
        },
        "postgres_memory_peak_bytes": postgres_memory_peak_bytes,
        "hard_gate": {"passed": passed, "checks": checks},
    }


def command(*arguments: str, check_result: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, capture_output=True, text=True, check=check_result)


def image_id(reference: str) -> str:
    return command("docker", "image", "inspect", "--format", "{{.Id}}", reference).stdout.strip()


def wait_for_postgres(container: str) -> None:
    for _ in range(60):
        ready = command(
            "docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "ndabi",
            check_result=False,
        )
        if ready.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("the PostgreSQL container did not become ready")


def memory_peak(container: str) -> int:
    value = command(
        "docker", "exec", container, "sh", "-c", "cat /sys/fs/cgroup/memory.peak",
        check_result=False,
    )
    return int(value.stdout.strip()) if value.returncode == 0 and value.stdout.strip().isdigit() else 0


def main() -> int:
    image_ids = {
        "client": image_id(CLIENT_IMAGE),
        "postgres": image_id(POSTGRES_IMAGE),
    }
    require(
        image_ids
        == {"client": EXPECTED_CLIENT_IMAGE_ID, "postgres": EXPECTED_POSTGRES_IMAGE_ID},
        "a frozen image identifier changed",
    )
    binary_line = command(
        "docker", "run", "--rm", "--entrypoint", "sha256sum", CLIENT_IMAGE,
        "/usr/local/bin/ndabi_v42",
    ).stdout.strip()
    require(binary_line.split(maxsplit=1)[0] == EXPECTED_BINARY_SHA256, "the binary changed")
    campaign_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{time.time_ns()}"
    directory = RESULT_ROOT / campaign_id
    directory.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    network = f"ndabi-v43-network-{suffix}"
    postgres = f"ndabi-v43-postgres-{suffix}"
    results: list[dict] = []
    exit_codes: list[int] = []
    try:
        command("docker", "network", "create", network)
        command(
            "docker", "run", "--detach", "--name", postgres, "--network", network,
            "--env", "POSTGRES_PASSWORD=ndabi-test-only", "--env", "POSTGRES_USER=postgres",
            "--env", "POSTGRES_DB=ndabi", POSTGRES_IMAGE, "-c", "max_connections=40",
        )
        wait_for_postgres(postgres)
        connection = f"host={postgres} user=postgres password=ndabi-test-only dbname=ndabi"
        preparation = command(
            "docker", "run", "--rm", "--network", network, CLIENT_IMAGE,
            "prepare", connection, check_result=False,
        )
        require(preparation.returncode == 0, "the dataset preparation failed")
        for index in range(PROCESS_COUNT):
            completed = command(
                "docker", "run", "--rm", "--network", network, CLIENT_IMAGE,
                "client", connection, check_result=False,
            )
            exit_codes.append(completed.returncode)
            if completed.returncode == 0:
                result = json.loads(completed.stdout)
                validate_result(result)
                results.append(result)
                (directory / f"process-{index:02d}.json").write_text(
                    json.dumps(result, indent=2) + "\n", encoding="utf-8"
                )
            else:
                (directory / f"process-{index:02d}.stderr").write_text(
                    completed.stderr, encoding="utf-8"
                )
        require(len(results) == PROCESS_COUNT, "one or more client processes failed")
        summary = aggregate(results, exit_codes, campaign_id, image_ids, memory_peak(postgres))
        summary_text = json.dumps(summary, indent=2) + "\n"
        (directory / "summary.json").write_text(summary_text, encoding="utf-8")
        (RESULT_ROOT / "latest.json").write_text(summary_text, encoding="utf-8")
        print(summary_text, end="")
        return 0 if summary["hard_gate"]["passed"] else 1
    finally:
        command("docker", "rm", "--force", postgres, check_result=False)
        command("docker", "network", "rm", network, check_result=False)


if __name__ == "__main__":
    raise SystemExit(main())
