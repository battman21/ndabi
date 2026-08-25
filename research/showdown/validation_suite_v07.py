#!/usr/bin/env python3
"""Run the frozen NDABI v0.7 independent-process campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PROFILE = "v07"
BINARY = ROOT / "target" / "release" / "ndabi-v07"
RESULTS_ROOT = ROOT / "results"
LATEST = RESULTS_ROOT / "v07-validation-suite.json"
EXPECTED_RESULT_SCHEMA = "ndabi-poc-result-v0.7"
SUITE_SCHEMA = "ndabi-v07-validation-suite-v0.1"
CAMPAIGN_STATUS = "controlled-local-campaign"
EXPECTED_SCHEDULER_PROFILE = "operating-system-default"
VARIABILITY_BASIS = "absolute-p95"
DIRECT_SPEEDUP_KEY = "direct_vs_stateless_json_conservative_p95_speedup"
PREPARED_SPEEDUP_KEY = "prepared_vs_stateless_json_conservative_p95_speedup"
RUNNER_FILES = [Path(__file__).resolve()]
DEFAULT_RUNS = 30
DEFAULT_ITERATIONS = 10_000
DEFAULT_WARMUP = 500


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def arm(result: dict[str, object], identifier: str) -> dict[str, object]:
    return next(item for item in result["arms"] if item["id"] == identifier)


def summary_stats(values: list[float]) -> dict[str, float]:
    if not values:
        raise ValueError("The measurement list is empty.")
    mean = statistics.fmean(values)
    deviation = statistics.pstdev(values)
    return {
        "minimum": min(values),
        "maximum": max(values),
        "mean": mean,
        "population_standard_deviation": deviation,
        "coefficient_of_variation": deviation / mean if mean else math.inf,
    }


def metric(results: list[dict[str, object]], identifier: str, key: str) -> dict[str, float]:
    return summary_stats([float(arm(result, identifier)[key]) for result in results])


def attribution_metric(results: list[dict[str, object]], key: str) -> dict[str, float]:
    return summary_stats([float(result["attribution"][key]) for result in results])


def run_once(iterations: int, warmup: int) -> tuple[dict[str, object], bytes]:
    command = [
        str(BINARY),
        "--iterations",
        str(iterations),
        "--warmup",
        str(warmup),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        timeout=180,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or "The NDABI v0.7 process failed.")
    result = json.loads(completed.stdout)
    if result.get("schema") != EXPECTED_RESULT_SCHEMA:
        raise RuntimeError(f"The NDABI {PROFILE} process returned an unknown schema.")
    return result, completed.stdout


def store_exclusive(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as destination:
        destination.write(value)


def store_latest(report: dict[str, object]) -> None:
    RESULTS_ROOT.mkdir(exist_ok=True)
    temporary = LATEST.with_name(f".{LATEST.name}.tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary.replace(LATEST)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    arguments = parser.parse_args()
    if not 1 <= arguments.runs <= 100:
        parser.error("--runs must be between 1 and 100")
    if not 40 <= arguments.iterations <= 100_000 or arguments.iterations % 40:
        parser.error("--iterations must be divisible by 40 and between 40 and 100000")
    if not 0 <= arguments.warmup <= 100_000:
        parser.error("--warmup must be between 0 and 100000")
    return arguments


def main() -> None:
    arguments = parse_args()
    if not BINARY.is_file():
        raise RuntimeError("The NDABI v0.7 release binary is absent.")
    binary_sha256 = sha256_file(BINARY)
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns()}"
    campaign_root = RESULTS_ROOT / PROFILE / campaign_id
    results: list[dict[str, object]] = []
    run_evidence = []
    for index in range(arguments.runs):
        result, raw = run_once(arguments.iterations, arguments.warmup)
        run_path = campaign_root / "runs" / f"run-{index + 1:03}.json"
        store_exclusive(run_path, raw)
        results.append(result)
        run_evidence.append(
            {
                "index": index + 1,
                "path": str(run_path.relative_to(ROOT)),
                "sha256": sha256_bytes(raw),
            }
        )
    if sha256_file(BINARY) != binary_sha256:
        raise RuntimeError("The release binary changed during the campaign.")
    fingerprints = {
        result["environment"]["source_fingerprint_blake3"] for result in results
    }
    if len(fingerprints) != 1:
        raise RuntimeError("The source fingerprint changed during the campaign.")
    scheduler_profiles = {
        result["environment"]["scheduler_profile"] for result in results
    }
    scheduler_profile_passed = scheduler_profiles == {EXPECTED_SCHEDULER_PROFILE}
    direct_p95 = metric(results, "direct-kernel", "p95_ns")
    prepared_p95 = metric(results, "prepared-wire", "p95_ns")
    direct_speedup = attribution_metric(results, DIRECT_SPEEDUP_KEY)
    prepared_speedup = attribution_metric(results, PREPARED_SPEEDUP_KEY)
    frozen_configuration = (
        arguments.runs == DEFAULT_RUNS
        and arguments.iterations == DEFAULT_ITERATIONS
        and arguments.warmup == DEFAULT_WARMUP
    )
    all_process_gates = all(result["hard_gate"]["passed"] for result in results)
    if VARIABILITY_BASIS == "absolute-p95":
        variability_passed = (
            direct_p95["coefficient_of_variation"] <= 0.10
            and prepared_p95["coefficient_of_variation"] <= 0.10
        )
    elif VARIABILITY_BASIS == "conservative-speedup":
        variability_passed = (
            direct_speedup["coefficient_of_variation"] <= 0.10
            and prepared_speedup["coefficient_of_variation"] <= 0.10
        )
    else:
        raise RuntimeError("The campaign variability basis is unknown.")
    report = {
        "schema": SUITE_SCHEMA,
        "status": CAMPAIGN_STATUS,
        "campaign_id": campaign_id,
        "generated_at_unix_seconds": int(time.time()),
        "configuration": {
            "runs": arguments.runs,
            "iterations": arguments.iterations,
            "warmup": arguments.warmup,
            "frozen_configuration": frozen_configuration,
        },
        "source_fingerprint_blake3": fingerprints.pop(),
        "release_binary_sha256": binary_sha256,
        "campaign_runner_sha256": {
            str(path.relative_to(ROOT)): sha256_file(path) for path in RUNNER_FILES
        },
        "hard_gates_passed": sum(result["hard_gate"]["passed"] for result in results),
        "campaign_gate": {
            "passed": frozen_configuration
            and all_process_gates
            and variability_passed
            and scheduler_profile_passed,
            "all_process_gates_passed": all_process_gates,
            "p95_variability_passed": variability_passed,
            "variability_basis": VARIABILITY_BASIS,
            "scheduler_profile_passed": scheduler_profile_passed,
        },
        "direct": {
            "p95_ns": direct_p95,
            "p99_ns": metric(results, "direct-kernel", "p99_ns"),
            "p999_ns": metric(results, "direct-kernel", "p999_ns"),
            "operations_per_second": metric(
                results, "direct-kernel", "operations_per_second"
            ),
            "conservative_json_speedup": direct_speedup,
        },
        "prepared": {
            "p95_ns": prepared_p95,
            "p99_ns": metric(results, "prepared-wire", "p99_ns"),
            "p999_ns": metric(results, "prepared-wire", "p999_ns"),
            "operations_per_second": metric(
                results, "prepared-wire", "operations_per_second"
            ),
            "conservative_json_speedup": prepared_speedup,
        },
        "stateless_json": {
            "p95_ns": metric(results, "stateless-json", "p95_ns"),
            "p99_ns": metric(results, "stateless-json", "p99_ns"),
            "operations_per_second": metric(
                results, "stateless-json", "operations_per_second"
            ),
        },
        "run_evidence": run_evidence,
    }
    summary = (json.dumps(report, indent=2) + "\n").encode()
    store_exclusive(campaign_root / "summary.json", summary)
    store_latest(report)
    print(summary.decode(), end="")


if __name__ == "__main__":
    main()
