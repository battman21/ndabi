#!/usr/bin/env python3
"""Run the frozen NDABI v1.9 local Docker campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent.parent
RESULTS = ROOT / "results"
LATEST = RESULTS / "v19-docker-campaign.json"
PREREGISTRATION = REPOSITORY / "specs" / "ndabi_poc_literal_lossless_campaign_v1_9.md"
DOCKERFILE = ROOT / "docker" / "Dockerfile.v19"
IMAGE = "ndabi-showdown:v1.9-local"
REPLICAS = 3
CPUSET = "0"
EXPECTED_RESULT_SCHEMA = "ndabi-poc-result-v1.9"
RUSAGE_PATTERN = re.compile(
    r"^NDABI_RUSAGE user=(?P<user>[0-9.]+) system=(?P<system>[0-9.]+) "
    r"max_rss_kb=(?P<rss>[0-9]+) elapsed=(?P<elapsed>[0-9.:]+)$",
    re.MULTILINE,
)

CASES = [
    ("point-100k", "point", 100_000, 64, 2_000),
    ("filter-100k-64k", "filter", 100_000, 65_536, 4),
    ("filter-1m-1m", "filter", 1_000_000, 1_048_576, 1),
]

RATIO_ARMS = {
    "stateless_json_vs_fused_view": ("stateless-json", "fused-view"),
    "ndabi_vs_fused_view": ("ndabi", "fused-view"),
    "fused_view_over_direct": ("fused-view", "direct"),
}


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def command_output(arguments: list[str], timeout: int = 60) -> bytes:
    completed = subprocess.run(
        arguments,
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        timeout=timeout,
    )
    return completed.stdout


def build_image(image: str) -> None:
    subprocess.run(
        [
            "docker",
            "build",
            "--file",
            str(DOCKERFILE),
            "--tag",
            image,
            ".",
        ],
        cwd=REPOSITORY,
        check=True,
        timeout=3_600,
    )


def inspect_image(image: str) -> dict[str, object]:
    values = json.loads(command_output(["docker", "image", "inspect", image]))
    if len(values) != 1:
        raise RuntimeError("The Docker image inspection returned an invalid result.")
    return values[0]


def binary_sha256(image: str) -> str:
    output = command_output(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "sha256sum",
            image,
            "/usr/local/bin/ndabi_v19",
        ]
    ).decode()
    digest = output.split(maxsplit=1)[0]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("The release-binary digest is invalid.")
    return digest


def docker_environment(image: str) -> dict[str, object]:
    server = json.loads(
        command_output(["docker", "version", "--format", "{{json .Server}}"]).decode()
    )
    info = json.loads(
        command_output(["docker", "info", "--format", "{{json .}}"]).decode()
    )
    kernel = command_output(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "uname",
            image,
            "-a",
        ]
    ).decode().strip()
    return {
        "docker_server_version": server.get("Version", "unknown"),
        "docker_operating_system": info.get("OperatingSystem", "unknown"),
        "docker_kernel_version": info.get("KernelVersion", "unknown"),
        "docker_architecture": info.get("Architecture", "unknown"),
        "docker_cpus": info.get("NCPU", 0),
        "docker_memory_bytes": info.get("MemTotal", 0),
        "docker_storage_driver": info.get("Driver", "unknown"),
        "container_uname": kernel,
        "cpuset": CPUSET,
        "memory_limit_bytes": 4 * 1024 * 1024 * 1024,
        "network": "none",
        "root_filesystem": "read-only",
        "capabilities": "all-dropped",
        "no_new_privileges": True,
    }


def container_command(image: str, case: tuple[str, str, int, int, int]) -> list[str]:
    _, workload, records, result_bytes, operations = case
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "4g",
        "--cpuset-cpus",
        CPUSET,
        "--entrypoint",
        "/usr/bin/time",
        image,
        "--format",
        "NDABI_RUSAGE user=%U system=%S max_rss_kb=%M elapsed=%e",
        "/usr/local/bin/ndabi_v19",
        "--records",
        str(records),
        "--workload",
        workload,
        "--result-bytes",
        str(result_bytes),
        "--batches",
        "63",
        "--operations-per-batch",
        str(operations),
        "--warmup-batches",
        "5",
    ]


def parse_elapsed(value: str) -> float:
    parts = [float(part) for part in value.split(":")]
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return parts[0] * 60.0 + parts[1]
    if len(parts) == 3:
        return parts[0] * 3_600.0 + parts[1] * 60.0 + parts[2]
    raise RuntimeError("The process elapsed-time format is invalid.")


def parse_rusage(stderr: bytes) -> dict[str, float | int]:
    text = stderr.decode("utf-8", errors="replace")
    match = RUSAGE_PATTERN.search(text)
    if match is None:
        raise RuntimeError("The container did not return process resource usage.")
    return {
        "user_seconds": float(match.group("user")),
        "system_seconds": float(match.group("system")),
        "elapsed_seconds": parse_elapsed(match.group("elapsed")),
        "max_rss_kb": int(match.group("rss")),
    }


def run_case(
    image: str, case: tuple[str, str, int, int, int]
) -> tuple[dict[str, object], bytes, int, dict[str, float | int]]:
    completed = subprocess.run(
        container_command(image, case),
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        timeout=600,
    )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or "The container returned invalid JSON.") from error
    if result.get("schema") != EXPECTED_RESULT_SCHEMA:
        raise RuntimeError("The container result schema does not match.")
    return result, completed.stdout, completed.returncode, parse_rusage(completed.stderr)


def store_exclusive(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as destination:
        destination.write(value)


def store_latest(value: bytes) -> None:
    RESULTS.mkdir(exist_ok=True)
    temporary = LATEST.with_name(f".{LATEST.name}.tmp")
    temporary.write_bytes(value)
    temporary.replace(LATEST)


def arm(result: dict[str, object], identifier: str) -> dict[str, object]:
    return next(item for item in result["arms"] if item["id"] == identifier)


def ratio(result: dict[str, object], left: str, right: str) -> float:
    left_value = float(arm(result, left)["median_ns_per_operation"])
    right_value = max(float(arm(result, right)["median_ns_per_operation"]), 0.000_001)
    return left_value / right_value


def coefficient_variation(values: list[float]) -> float:
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / max(abs(mean), 0.000_001)


def aggregate_case(
    case: tuple[str, str, int, int, int],
    results: list[dict[str, object]],
    usages: list[dict[str, float | int]],
) -> dict[str, object]:
    ratios = {
        name: [ratio(result, left, right) for result in results]
        for name, (left, right) in RATIO_ARMS.items()
    }
    measurements = {}
    for identifier in [item["id"] for item in results[0]["arms"]]:
        arms = [arm(result, identifier) for result in results]
        measurements[identifier] = {
            "median_ns_per_operation": statistics.median(
                float(value["median_ns_per_operation"]) for value in arms
            ),
            "p95_ns_per_operation": statistics.median(
                float(value["p95_ns_per_operation"]) for value in arms
            ),
            "operations_per_second": statistics.median(
                float(value["operations_per_second"]) for value in arms
            ),
            "allocations_per_operation_max": max(
                float(value["allocations_per_operation"]) for value in arms
            ),
            "request_bytes": arms[0]["request_bytes"],
            "response_bytes": arms[0]["response_bytes"],
        }
    return {
        "id": case[0],
        "workload": case[1],
        "records": case[2],
        "result_bytes": case[3],
        "operations_per_batch": case[4],
        "replicas": len(results),
        "ratios": {
            name: {
                "median": statistics.median(values),
                "coefficient_of_variation": coefficient_variation(values),
                "values": values,
            }
            for name, values in ratios.items()
        },
        "measurements": measurements,
        "process_resources": {
            "median_user_seconds": statistics.median(
                float(value["user_seconds"]) for value in usages
            ),
            "median_system_seconds": statistics.median(
                float(value["system_seconds"]) for value in usages
            ),
            "median_elapsed_seconds": statistics.median(
                float(value["elapsed_seconds"]) for value in usages
            ),
            "maximum_rss_kb": max(int(value["max_rss_kb"]) for value in usages),
        },
    }


def gate(identifier: str, passed: bool, observed: object, target: str) -> dict[str, object]:
    return {
        "id": identifier,
        "passed": passed,
        "observed": observed,
        "target": target,
    }


def make_failure(
    campaign_root: Path,
    case: tuple[str, str, int, int, int],
    replica: int,
    error: Exception,
) -> None:
    value = {
        "schema": "ndabi-v19-docker-failure-v0.1",
        "case": case[0],
        "replica": replica,
        "error": str(error),
    }
    store_exclusive(
        campaign_root / "failure.json", (json.dumps(value, indent=2) + "\n").encode()
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    arguments = parser.parse_args()
    if not PREREGISTRATION.is_file() or not DOCKERFILE.is_file():
        raise RuntimeError("The NDABI v1.9 campaign contract is incomplete.")
    if arguments.build:
        build_image(IMAGE)

    image_before = inspect_image(IMAGE)
    image_id = str(image_before["Id"])
    release_binary_sha256 = binary_sha256(IMAGE)
    environment = docker_environment(IMAGE)
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns()}"
    campaign_root = RESULTS / "v19" / campaign_id
    raw_evidence = []
    grouped_results: dict[str, list[dict[str, object]]] = {
        case[0]: [] for case in CASES
    }
    grouped_usages: dict[str, list[dict[str, float | int]]] = {
        case[0]: [] for case in CASES
    }
    exit_codes = []

    for case in CASES:
        for replica in range(1, REPLICAS + 1):
            try:
                result, raw, exit_code, usage = run_case(IMAGE, case)
            except Exception as error:
                make_failure(campaign_root, case, replica, error)
                raise
            path = campaign_root / "cases" / f"{case[0]}-replica-{replica:02}.json"
            store_exclusive(path, raw)
            grouped_results[case[0]].append(result)
            grouped_usages[case[0]].append(usage)
            exit_codes.append(exit_code)
            raw_evidence.append(
                {
                    "case": case[0],
                    "replica": replica,
                    "path": str(path.relative_to(ROOT)),
                    "sha256": sha256_bytes(raw),
                    "process_exit_code": exit_code,
                    "resource_usage": usage,
                }
            )

    image_after = inspect_image(IMAGE)
    image_stable = image_after["Id"] == image_id
    source_fingerprints = {
        result["environment"]["source_fingerprint_blake3"]
        for values in grouped_results.values()
        for result in values
    }
    all_results = [result for values in grouped_results.values() for result in values]
    cases = [
        aggregate_case(case, grouped_results[case[0]], grouped_usages[case[0]])
        for case in CASES
    ]
    point_cases = [case for case in cases if case["workload"] == "point"]
    checks = [
        gate(
            "all-process-hard-gates",
            all(result["hard_gate"]["passed"] for result in all_results),
            sum(result["hard_gate"]["passed"] for result in all_results),
            "9/9",
        ),
        gate(
            "all-process-exit-codes",
            all(code == 0 for code in exit_codes),
            exit_codes,
            "all zero",
        ),
        gate(
            "measurement-calibration",
            all(result["calibration"]["passed"] for result in all_results),
            sum(result["calibration"]["passed"] for result in all_results),
            "9/9",
        ),
        gate(
            "linux-arm64",
            all(
                result["environment"]["os"] == "linux"
                and result["environment"]["architecture"] == "aarch64"
                for result in all_results
            ),
            sorted(
                {
                    f"{result['environment']['os']}/{result['environment']['architecture']}"
                    for result in all_results
                }
            ),
            "linux/aarch64 only",
        ),
        gate(
            "source-fingerprint",
            len(source_fingerprints) == 1,
            sorted(source_fingerprints),
            "one fingerprint",
        ),
        gate("image-stability", image_stable, image_id, "unchanged image identifier"),
        gate(
            "compressed-hot-allocation",
            all(
                float(arm(result, identifier)["allocations_per_operation"]) == 0.0
                for result in all_results
                for identifier in ["ndabi", "fused-view", "direct"]
            ),
            max(
                float(arm(result, identifier)["allocations_per_operation"])
                for result in all_results
                for identifier in ["ndabi", "fused-view", "direct"]
            ),
            "zero allocations per operation",
        ),
        gate(
            "point-stateless-json-to-fused-speed",
            all(
                case["ratios"]["stateless_json_vs_fused_view"]["median"] >= 11.0
                for case in point_cases
            ),
            {
                case["id"]: case["ratios"]["stateless_json_vs_fused_view"]["median"]
                for case in point_cases
            },
            "the point median is at least 11 times",
        ),
        gate(
            "point-ndabi-to-fused-speed",
            all(
                case["ratios"]["ndabi_vs_fused_view"]["median"] >= 1.35
                for case in point_cases
            ),
            {
                case["id"]: case["ratios"]["ndabi_vs_fused_view"]["median"]
                for case in point_cases
            },
            "the point median is at least 1.35 times",
        ),
        gate(
            "fused-view-direct-distance",
            all(
                0.90 <= case["ratios"]["fused_view_over_direct"]["median"] <= 1.10
                for case in cases
            ),
            {
                case["id"]: case["ratios"]["fused_view_over_direct"]["median"]
                for case in cases
            },
            "each median is between 0.90 and 1.10 times direct",
        ),
        gate(
            "registered-ratio-repeatability",
            all(
                ratio_value["coefficient_of_variation"] <= 0.10
                for case in cases
                for ratio_value in case["ratios"].values()
            ),
            {
                case["id"]: {
                    name: value["coefficient_of_variation"]
                    for name, value in case["ratios"].items()
                }
                for case in cases
            },
            "each registered coefficient at most 0.10",
        ),
    ]
    report = {
        "schema": "ndabi-v19-docker-campaign-v0.1",
        "status": "fused-view-linux-arm64-campaign",
        "campaign_id": campaign_id,
        "configuration": {
            "cases": len(CASES),
            "replicas_per_case": REPLICAS,
            "processes": len(all_results),
            "batches_per_arm": 63,
            "warmup_batches_per_arm": 5,
        },
        "environment": environment,
        "image": {
            "tag": IMAGE,
            "id": image_id,
            "os": image_before.get("Os", "unknown"),
            "architecture": image_before.get("Architecture", "unknown"),
            "release_binary_sha256": release_binary_sha256,
        },
        "source_fingerprint_blake3": next(iter(source_fingerprints), "unavailable"),
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "dockerfile_sha256": sha256_file(DOCKERFILE),
        "preregistration_sha256": sha256_file(PREREGISTRATION),
        "campaign_gate": {
            "passed": all(check["passed"] for check in checks),
            "checks": checks,
        },
        "cases": cases,
        "raw_evidence": raw_evidence,
        "limitations": [
            "This campaign uses a fixture query engine.",
            "Docker Desktop uses a LinuxKit virtual machine on Apple hardware.",
            "Virtual CPU affinity does not prove physical-core affinity.",
            "Absolute latency, energy, NUMA, and hardware counters remain unproven.",
            "The campaign does not prove White Tree, PostgreSQL, remote, or model behaviour.",
        ],
    }
    summary = (json.dumps(report, indent=2) + "\n").encode()
    store_exclusive(campaign_root / "summary.json", summary)
    store_latest(summary)
    print(summary.decode(), end="")


if __name__ == "__main__":
    main()
