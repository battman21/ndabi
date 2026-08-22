#!/usr/bin/env python3
"""Run the frozen NDABI v0.6 architectural repeatability suite."""

from __future__ import annotations

import json
import time

import server


RUNS = 4
TARGET = server.V06_VALIDATION_RESULT


def arm(result: dict[str, object], identifier: str) -> dict[str, object]:
    return next(item for item in result["arms"] if item["id"] == identifier)


def range_for(results: list[dict[str, object]], identifier: str, key: str) -> dict[str, float]:
    values = [float(arm(result, identifier)[key]) for result in results]
    return {"minimum": min(values), "maximum": max(values)}


def attribution_range(results: list[dict[str, object]], key: str) -> dict[str, float]:
    values = [float(result["attribution"][key]) for result in results]
    return {"minimum": min(values), "maximum": max(values)}


def main() -> None:
    # The v0.6 executable binds each speedup to the current frozen v0.5 result.
    if not (server.RESULTS_ROOT / "latest.json").is_file():
        server.run_benchmark(server.DEFAULT_CONFIG)
    results = [server.run_v06(server.DEFAULT_CONFIG) for _ in range(RUNS)]
    fingerprints = {
        result["environment"]["source_fingerprint_blake3"] for result in results
    }
    if len(fingerprints) != 1:
        raise RuntimeError("The NDABI v0.6 source changed during the validation suite.")
    report = {
        "schema": "ndabi-v06-validation-suite-v0.1",
        "status": "local-repeatability-measurement",
        "generated_at_unix_seconds": int(time.time()),
        "run_count": RUNS,
        "source_fingerprint_blake3": fingerprints.pop(),
        "hard_gates_passed": sum(result["hard_gate"]["passed"] for result in results),
        "overall_verdicts": [result["overall_verdict"] for result in results],
        "direct_p95_ns": range_for(results, "direct-kernel", "p95_ns"),
        "prepared_p95_ns": range_for(results, "prepared-wire", "p95_ns"),
        "direct_operations_per_second": range_for(
            results, "direct-kernel", "operations_per_second"
        ),
        "prepared_operations_per_second": range_for(
            results, "prepared-wire", "operations_per_second"
        ),
        "direct_v05_conservative_speedup": attribution_range(
            results, "direct_vs_v05_tuned_conservative_p95_speedup"
        ),
        "prepared_v05_conservative_speedup": attribution_range(
            results, "prepared_vs_v05_tuned_conservative_p95_speedup"
        ),
        "receipt_incremental_ns": {
            "minimum": min(
                result["ablations"]["receipt_incremental_median_ns"]
                for result in results
            ),
            "maximum": max(
                result["ablations"]["receipt_incremental_median_ns"]
                for result in results
            ),
        },
        "run_ids": [result["generated_at_unix_seconds"] for result in results],
    }
    server.RESULTS_ROOT.mkdir(exist_ok=True)
    server.store_named_result(report, TARGET)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
