#!/usr/bin/env python3
"""Run and validate the frozen local Docker NDABI gateway campaign v4.0."""

from __future__ import annotations

import json
import math
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CLIENT_IMAGE = "ndabi-showdown:v4.0-local"
EXPECTED_CLIENT_IMAGE_ID = "sha256:019c07ff2c9c0180ffeced3d92222263c4de789a3cc0d0946965d71251b6b032"
EXPECTED_BINARY_SHA256 = "02a3b070fc2737b4c994c2c82bad6dfd6c99432d787fa1c32f66cbb465f16d48"
POSTGRES_IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
EXPECTED_POSTGRES_IMAGE_ID = "sha256:eb9fe6b5815523ffa3e3d8aee9db3532bd564b857634fcfa36979d76bed6ae10"
POSTGREST_IMAGE = "postgrest/postgrest@sha256:bea1c76a856fa39d1e542d25911cf95d02fe2bf971992d033044ff209f1504b8"
EXPECTED_POSTGREST_IMAGE_ID = "sha256:367030c7d679ff6ab17bfde55017fe94863e74c30b6e160bdbe4993bbfaf545b"
RESULT_ROOT = ROOT / "results" / "v40"
PROCESS_COUNT = 5
ARMS = [
    "postgrest-json",
    "simple-sql-sequential",
    "prepared-sql-sequential",
    "native-prepared-set",
    "ndabi-gateway",
]
BATCH_SIZES = [32, 128]
CONCURRENCY_LEVELS = [1, 8, 32, 128]
LATENCY_SAMPLES = 63
CONCURRENT_REQUESTS_PER_WORKER = 21


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil((len(ordered) - 1) * quantile)]


def valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def latency_case(result: dict, batch_size: int) -> dict:
    return next(item for item in result["latency_cases"] if item["batch_size"] == batch_size)


def latency_measurement(result: dict, batch_size: int, arm: str) -> dict:
    return next(
        item for item in latency_case(result, batch_size)["measurements"] if item["id"] == arm
    )


def concurrency_case(result: dict, concurrency: int) -> dict:
    return next(
        item for item in result["concurrency_cases"] if item["concurrency"] == concurrency
    )


def concurrency_measurement(result: dict, concurrency: int, arm: str) -> dict:
    return next(
        item
        for item in concurrency_case(result, concurrency)["measurements"]
        if item["id"] == arm
    )


def require_ratio(observed: object, numerator: float, denominator: float, name: str) -> None:
    require(isinstance(observed, float), f"invalid {name}")
    require(math.isclose(observed, numerator / denominator, rel_tol=1e-12), f"changed {name}")


def validate_result(result: dict) -> None:
    require(result.get("schema") == "ndabi-postgresql-gateway-v4.0", "invalid schema")
    require(result.get("status") == "local-docker-process-diagnostic", "invalid status")
    require(result.get("client_architecture") == "aarch64", "invalid client architecture")
    require(result.get("client_operating_system") == "linux", "invalid client operating system")
    require(result.get("rows") == 100_000, "invalid dataset size")
    require(result.get("correctness_gate_passed") is True, "failed correctness gate")
    security = result.get("security")
    require(isinstance(security, dict), "invalid security proof")
    for name in (
        "changed_frame_refused",
        "replay_refused",
        "cross_session_frame_refused",
        "postgrest_write_refused",
    ):
        require(security.get(name) is True, f"failed security proof: {name}")

    latency = result.get("latency_cases")
    require(isinstance(latency, list) and len(latency) == 2, "invalid latency cases")
    require(sorted(item.get("batch_size") for item in latency) == BATCH_SIZES, "invalid batches")
    for batch_size in BATCH_SIZES:
        case = latency_case(result, batch_size)
        require(valid_digest(case.get("canonical_sha256")), "invalid canonical digest")
        require(valid_digest(case.get("receipt_sha256")), "invalid receipt digest")
        measurements = case.get("measurements")
        require(isinstance(measurements, list) and len(measurements) == 5, "invalid measurements")
        require(sorted(item.get("id") for item in measurements) == sorted(ARMS), "invalid arms")
        for measurement in measurements:
            raw_wall = measurement.get("raw_batch_ns")
            raw_cpu = measurement.get("raw_client_cpu_ns")
            require(
                isinstance(raw_wall, list)
                and len(raw_wall) == LATENCY_SAMPLES
                and all(isinstance(value, int) and value > 0 for value in raw_wall),
                "invalid latency samples",
            )
            require(
                isinstance(raw_cpu, list)
                and len(raw_cpu) == LATENCY_SAMPLES
                and all(isinstance(value, int) and value > 0 for value in raw_cpu),
                "invalid client CPU samples",
            )
            require(measurement.get("median_batch_ns") == percentile(raw_wall, 0.50), "invalid median")
            require(measurement.get("p95_batch_ns") == percentile(raw_wall, 0.95), "invalid p95")
            require(measurement.get("p99_batch_ns") == percentile(raw_wall, 0.99), "invalid p99")
            require(
                measurement.get("median_client_cpu_ns") == percentile(raw_cpu, 0.50),
                "invalid CPU median",
            )
        native = latency_measurement(result, batch_size, "native-prepared-set")
        prepared = latency_measurement(result, batch_size, "prepared-sql-sequential")
        postgrest = latency_measurement(result, batch_size, "postgrest-json")
        ndabi = latency_measurement(result, batch_size, "ndabi-gateway")
        require(ndabi.get("request_bytes") == 60, "invalid compact request size")
        require(ndabi.get("median_gateway_server_cpu_ns", 0) > 0, "missing gateway CPU")
        require(ndabi.get("mean_gateway_allocations", 0) > 0, "missing gateway allocations")
        require_ratio(case.get("gateway_native_distance"), ndabi["p95_batch_ns"], native["p95_batch_ns"], "native distance")
        require_ratio(case.get("gateway_prepared_speedup"), prepared["p95_batch_ns"], ndabi["p95_batch_ns"], "prepared speedup")
        require_ratio(case.get("gateway_postgrest_speedup"), postgrest["p95_batch_ns"], ndabi["p95_batch_ns"], "PostgREST speedup")
        require_ratio(
            1.0 - case.get("request_compression"),
            ndabi["request_bytes"],
            postgrest["request_bytes"],
            "request size distance",
        )

    concurrent = result.get("concurrency_cases")
    require(isinstance(concurrent, list) and len(concurrent) == 4, "invalid concurrency cases")
    require(
        sorted(item.get("concurrency") for item in concurrent) == CONCURRENCY_LEVELS,
        "invalid concurrency levels",
    )
    for concurrency in CONCURRENCY_LEVELS:
        case = concurrency_case(result, concurrency)
        measurements = case.get("measurements")
        require(isinstance(measurements, list) and len(measurements) == 5, "invalid concurrency measurements")
        require(sorted(item.get("id") for item in measurements) == sorted(ARMS), "invalid concurrency arms")
        expected = concurrency * CONCURRENT_REQUESTS_PER_WORKER
        for measurement in measurements:
            raw = measurement.get("raw_request_ns")
            require(
                isinstance(raw, list)
                and len(raw) == expected
                and all(isinstance(value, int) and value > 0 for value in raw),
                "invalid concurrent samples",
            )
            require(measurement.get("completed_requests") == expected, "invalid completion count")
            require(measurement.get("p95_request_ns") == percentile(raw, 0.95), "invalid concurrent p95")
            require(measurement.get("operations_per_second", 0) > 0, "invalid throughput")
        native = concurrency_measurement(result, concurrency, "native-prepared-set")
        postgrest = concurrency_measurement(result, concurrency, "postgrest-json")
        ndabi = concurrency_measurement(result, concurrency, "ndabi-gateway")
        require_ratio(case.get("gateway_native_throughput"), ndabi["operations_per_second"], native["operations_per_second"], "concurrent native throughput")
        require_ratio(case.get("gateway_native_p95_distance"), ndabi["p95_request_ns"], native["p95_request_ns"], "concurrent native p95")
        require_ratio(case.get("gateway_postgrest_throughput"), ndabi["operations_per_second"], postgrest["operations_per_second"], "concurrent PostgREST throughput")


def check(identifier: str, passed: bool, observed: object, target: str) -> dict:
    return {"id": identifier, "passed": passed, "observed": observed, "target": target}


def aggregate(
    results: list[dict],
    exit_codes: list[int],
    campaign_id: str,
    image_ids: dict[str, str],
    service_memory_peak_bytes: dict[str, int],
) -> dict:
    checks = [
        check("five-complete-processes", len(results) == PROCESS_COUNT, len(results), "5"),
        check("five-zero-exit-codes", exit_codes == [0] * PROCESS_COUNT, exit_codes, "five zero exit codes"),
        check("all-correctness-gates", all(result["correctness_gate_passed"] for result in results), sum(result["correctness_gate_passed"] for result in results), "5/5"),
    ]
    latency_summary = []
    for batch_size in BATCH_SIZES:
        median_p95 = {
            arm: statistics.median(
                latency_measurement(result, batch_size, arm)["p95_batch_ns"] for result in results
            )
            for arm in ARMS
        }
        native_distance = median_p95["ndabi-gateway"] / median_p95["native-prepared-set"]
        prepared_speedup = median_p95["prepared-sql-sequential"] / median_p95["ndabi-gateway"]
        postgrest_speedup = median_p95["postgrest-json"] / median_p95["ndabi-gateway"]
        request_compression = statistics.median(
            latency_case(result, batch_size)["request_compression"] for result in results
        )
        checks.extend(
            [
                check(f"batch-{batch_size}-native-distance", native_distance <= 1.15, native_distance, "no more than 1.15x"),
                check(f"batch-{batch_size}-prepared-speedup", prepared_speedup >= (2 if batch_size == 32 else 4), prepared_speedup, f"at least {2 if batch_size == 32 else 4}x"),
                check(f"batch-{batch_size}-postgrest-speedup", postgrest_speedup >= 2, postgrest_speedup, "at least 2x"),
                check(f"batch-{batch_size}-request-compression", request_compression >= 0.40, request_compression, "at least 40%"),
            ]
        )
        identities = {
            (latency_case(result, batch_size)["canonical_sha256"], latency_case(result, batch_size)["receipt_sha256"])
            for result in results
        }
        checks.append(check(f"batch-{batch_size}-one-identity", len(identities) == 1, sorted(identities), "one result and receipt identity"))
        latency_summary.append(
            {
                "batch_size": batch_size,
                "median_process_p95_ns": median_p95,
                "gateway_native_distance": native_distance,
                "gateway_prepared_speedup": prepared_speedup,
                "gateway_postgrest_speedup": postgrest_speedup,
                "request_compression": request_compression,
            }
        )

    concurrency_summary = []
    for concurrency in CONCURRENCY_LEVELS:
        median_throughput = {
            arm: statistics.median(
                concurrency_measurement(result, concurrency, arm)["operations_per_second"]
                for result in results
            )
            for arm in ARMS
        }
        median_p95 = {
            arm: statistics.median(
                concurrency_measurement(result, concurrency, arm)["p95_request_ns"]
                for result in results
            )
            for arm in ARMS
        }
        native_throughput = median_throughput["ndabi-gateway"] / median_throughput["native-prepared-set"]
        native_p95 = median_p95["ndabi-gateway"] / median_p95["native-prepared-set"]
        postgrest_throughput = median_throughput["ndabi-gateway"] / median_throughput["postgrest-json"]
        checks.extend(
            [
                check(f"concurrency-{concurrency}-native-throughput", native_throughput >= 0.85, native_throughput, "at least 0.85x"),
                check(f"concurrency-{concurrency}-native-p95", native_p95 <= 1.20, native_p95, "no more than 1.20x"),
                check(f"concurrency-{concurrency}-postgrest-throughput", postgrest_throughput >= 2, postgrest_throughput, "at least 2x"),
            ]
        )
        concurrency_summary.append(
            {
                "concurrency": concurrency,
                "median_process_operations_per_second": median_throughput,
                "median_process_p95_ns": median_p95,
                "gateway_native_throughput": native_throughput,
                "gateway_native_p95_distance": native_p95,
                "gateway_postgrest_throughput": postgrest_throughput,
            }
        )

    passed = all(item["passed"] for item in checks)
    return {
        "schema": "ndabi-postgresql-gateway-campaign-v4.0",
        "campaign_id": campaign_id,
        "status": "accepted" if passed else "failed",
        "binary": {"path": "/usr/local/bin/ndabi_v40", "sha256": EXPECTED_BINARY_SHA256},
        "images": image_ids,
        "processes": PROCESS_COUNT,
        "latency": latency_summary,
        "concurrency": concurrency_summary,
        "service_memory_peak_bytes": service_memory_peak_bytes,
        "hard_gate": {"passed": passed, "checks": checks},
    }


def command(*arguments: str, check_result: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, capture_output=True, text=True, check=check_result)


def image_id(reference: str) -> str:
    return command("docker", "image", "inspect", "--format", "{{.Id}}", reference).stdout.strip()


def wait_for_postgres(container: str) -> None:
    for _ in range(60):
        ready = command("docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "ndabi", check_result=False)
        if ready.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("the PostgreSQL container did not become ready")


def wait_for_log(container: str, marker: str) -> None:
    for _ in range(60):
        logs = command("docker", "logs", container, check_result=False)
        if marker in logs.stdout + logs.stderr:
            return
        time.sleep(1)
    raise RuntimeError(f"the {container} container did not become ready")


def memory_peak(container: str) -> int:
    value = command(
        "docker", "exec", container, "sh", "-c", "cat /sys/fs/cgroup/memory.peak",
        check_result=False,
    )
    return int(value.stdout.strip()) if value.returncode == 0 and value.stdout.strip().isdigit() else 0


def main() -> int:
    actual_ids = {
        "client": image_id(CLIENT_IMAGE),
        "postgres": image_id(POSTGRES_IMAGE),
        "postgrest": image_id(POSTGREST_IMAGE),
    }
    expected_ids = {
        "client": EXPECTED_CLIENT_IMAGE_ID,
        "postgres": EXPECTED_POSTGRES_IMAGE_ID,
        "postgrest": EXPECTED_POSTGREST_IMAGE_ID,
    }
    require(actual_ids == expected_ids, "a frozen image identifier changed")
    binary_line = command(
        "docker", "run", "--rm", "--entrypoint", "sha256sum", CLIENT_IMAGE,
        "/usr/local/bin/ndabi_v40",
    ).stdout.strip()
    require(binary_line.split(maxsplit=1)[0] == EXPECTED_BINARY_SHA256, "the frozen binary changed")

    campaign_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{time.time_ns()}"
    directory = RESULT_ROOT / campaign_id
    directory.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    network = f"ndabi-v40-network-{suffix}"
    postgres = f"ndabi-v40-postgres-{suffix}"
    postgrest = f"ndabi-v40-postgrest-{suffix}"
    gateway = f"ndabi-v40-gateway-{suffix}"
    results: list[dict] = []
    exit_codes: list[int] = []
    try:
        command("docker", "network", "create", network)
        command(
            "docker", "run", "--detach", "--name", postgres, "--network", network,
            "--env", "POSTGRES_PASSWORD=ndabi-test-only", "--env", "POSTGRES_USER=postgres",
            "--env", "POSTGRES_DB=ndabi", POSTGRES_IMAGE, "-c", "max_connections=450",
        )
        wait_for_postgres(postgres)
        connection = f"host={postgres} user=postgres password=ndabi-test-only dbname=ndabi"
        preparation = command(
            "docker", "run", "--rm", "--network", network, CLIENT_IMAGE,
            "prepare", connection, check_result=False,
        )
        require(preparation.returncode == 0, "the dataset preparation failed")
        command(
            "docker", "run", "--detach", "--name", postgrest, "--network", network,
            "--env", f"PGRST_DB_URI=postgresql://postgres:ndabi-test-only@{postgres}:5432/ndabi",
            "--env", "PGRST_DB_SCHEMAS=public", "--env", "PGRST_DB_ANON_ROLE=ndabi_anon",
            "--env", "PGRST_DB_POOL=150", "--env", "PGRST_LOG_LEVEL=warn", POSTGREST_IMAGE,
        )
        command(
            "docker", "run", "--detach", "--name", gateway, "--network", network,
            CLIENT_IMAGE, "gateway", "0.0.0.0:4040", connection,
        )
        wait_for_log(postgrest, "API server listening")
        wait_for_log(gateway, "ndabi-gateway-v4.0-ready")

        for index in range(PROCESS_COUNT):
            completed = command(
                "docker", "run", "--rm", "--network", network, CLIENT_IMAGE, "client",
                connection, f"{gateway}:4040", f"{postgrest}:3000", check_result=False,
            )
            exit_codes.append(completed.returncode)
            if completed.stderr:
                (directory / f"process-{index:02d}.stderr").write_text(completed.stderr, encoding="utf-8")
            result = json.loads(completed.stdout)
            validate_result(result)
            (directory / f"process-{index:02d}.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
            results.append(result)

        peaks = {
            "postgres": memory_peak(postgres),
            "postgrest": memory_peak(postgrest),
            "gateway": memory_peak(gateway),
        }
        summary = aggregate(results, exit_codes, campaign_id, actual_ids, peaks)
        (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        (RESULT_ROOT / "latest.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2))
        return 0 if summary["hard_gate"]["passed"] else 1
    finally:
        command("docker", "rm", "--force", gateway, postgrest, postgres, check_result=False)
        command("docker", "network", "rm", network, check_result=False)


if __name__ == "__main__":
    raise SystemExit(main())
