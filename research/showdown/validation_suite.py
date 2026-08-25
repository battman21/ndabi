#!/usr/bin/env python3
"""Run the frozen NDABI v0.5 repeatability suite."""

from __future__ import annotations

import json
import time
from pathlib import Path

import server


RUNS = 4
TARGET = server.RESULTS_ROOT / "validation-suite.json"
TARGET_IDS = {
    "database": "p95-latency",
    "application": "p95-latency",
    "white_tree": "wire-p95-latency",
}


def summarise_track(results: list[dict[str, object]], track: str) -> dict[str, object]:
    tracks = [result[track] for result in results]
    target_id = TARGET_IDS[track]
    target_passes = sum(
        next(
            check["passed"]
            for check in item["rubric"]["checks"]
            if check["id"] == target_id
        )
        for item in tracks
    )
    p95 = [item["tuned_to_wire"]["p95_reduction_percent"] for item in tracks]
    cpu = [
        item["tuned_to_wire"]["thread_cpu_reduction_percent"] for item in tracks
    ]
    return {
        "hard_gates_passed": sum(item["hard_gate"]["passed"] for item in tracks),
        "interval_target_passes": target_passes,
        "p95_reduction_min_percent": min(p95),
        "p95_reduction_max_percent": max(p95),
        "thread_cpu_reduction_min_percent": min(cpu),
        "thread_cpu_reduction_max_percent": max(cpu),
        "scores": [item["rubric"]["score"] for item in tracks],
    }


def main() -> None:
    results = [server.run_benchmark(server.DEFAULT_CONFIG) for _ in range(RUNS)]
    source_hashes = {
        result["environment"]["olx_core_source_sha256"] for result in results
    }
    if len(source_hashes) != 1:
        raise RuntimeError("The White Tree source changed during the validation suite.")
    report = {
        "schema": "ndabi-validation-suite-v0.1",
        "status": "local-repeatability-measurement",
        "generated_at_unix_seconds": int(time.time()),
        "run_count": RUNS,
        "source_sha256": source_hashes.pop(),
        "overall_verdicts": [result["overall_verdict"] for result in results],
        "tracks": {
            track: summarise_track(results, track)
            for track in ("database", "application", "white_tree")
        },
        "run_ids": [result["generated_at_unix_seconds"] for result in results],
    }
    server.RESULTS_ROOT.mkdir(exist_ok=True)
    temporary = TARGET.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary.replace(TARGET)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
