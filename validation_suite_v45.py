#!/usr/bin/env python3
"""Run the frozen NDABI equal-security White Tree v4.5 campaign once."""

from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import time
from pathlib import Path

import validation_suite_v44 as shared


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v45"
RESULT_ROOT = ROOT / "results" / "v45"
PROCESS_COUNT = 5
ITERATIONS = 20_000
WARMUP = 2_000
SOURCE_PATHS = shared.SOURCE_PATHS + ("src/bin/ndabi_v45.rs",)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = ROOT / relative
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v4.5 formal campaign already exists")
    if not BINARY.is_file():
        raise SystemExit("the release v4.5 binary is absent")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    binary_digest = shared.sha256(BINARY)
    source_digest = source_sha256()
    reports = []
    for process in range(1, PROCESS_COUNT + 1):
        completed = subprocess.run(
            [str(BINARY), "--iterations", str(ITERATIONS), "--warmup", str(WARMUP)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        report.update(
            process=process,
            binary_sha256=binary_digest,
            source_sha256=source_digest,
        )
        (campaign / f"process-{process}.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        reports.append(report)

    json_p95 = [shared.arm(report, "json")["p95_ns"] for report in reports]
    ndabi_p95 = [shared.arm(report, "ndabi")["p95_ns"] for report in reports]
    median_json = statistics.median(json_p95)
    median_ndabi = statistics.median(ndabi_p95)
    all_process_gates = all(report["gates"]["passed"] for report in reports)
    median_gate = median_ndabi <= median_json * 0.95
    aggregate = {
        "campaign": "NDABI equal-security White Tree v4.5",
        "campaign_id": campaign_id,
        "process_count": PROCESS_COUNT,
        "iterations_per_process": ITERATIONS,
        "warmup_per_process": WARMUP,
        "binary_sha256": binary_digest,
        "source_sha256": source_digest,
        "json_p95_ns": json_p95,
        "ndabi_p95_ns": ndabi_p95,
        "median_json_p95_ns": median_json,
        "median_ndabi_p95_ns": median_ndabi,
        "median_speed_improvement": 1.0 - median_ndabi / median_json,
        "all_process_gates_passed": all_process_gates,
        "median_speed_gate_passed": median_gate,
        "accepted": all_process_gates and median_gate,
        "process_results": [
            str(path.relative_to(ROOT))
            for path in sorted(campaign.glob("process-*.json"))
        ],
    }
    encoded = json.dumps(aggregate, indent=2) + "\n"
    (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
    latest.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if aggregate["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
