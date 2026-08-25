#!/usr/bin/env python3
"""Run the frozen NDABI shared-session White Tree v4.4 campaign once."""

from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v44"
RESULT_ROOT = ROOT / "results" / "v44"
PROCESS_COUNT = 5
ITERATIONS = 20_000
WARMUP = 2_000
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-session/Cargo.toml",
    "crates/ndabi-session/src/lib.rs",
    "crates/ndabi-postgres/Cargo.toml",
    "crates/ndabi-postgres/src/lib.rs",
    "src/alloc.rs",
    "src/measure.rs",
    "src/wire.rs",
    "src/white_tree.rs",
    "src/v44/mod.rs",
    "src/bin/ndabi_v44.rs",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = ROOT / relative
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def arm(report: dict, arm_id: str) -> dict:
    return next(value for value in report["arms"] if value["id"] == arm_id)


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v4.4 formal campaign already exists")
    if not BINARY.is_file():
        raise SystemExit("the release v4.4 binary is absent")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    binary_digest = sha256(BINARY)
    source_digest = source_sha256()
    reports = []
    for process in range(1, PROCESS_COUNT + 1):
        completed = subprocess.run(
            [
                str(BINARY),
                "--iterations",
                str(ITERATIONS),
                "--warmup",
                str(WARMUP),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        report["process"] = process
        report["binary_sha256"] = binary_digest
        report["source_sha256"] = source_digest
        (campaign / f"process-{process}.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        reports.append(report)

    json_p95 = [arm(report, "json")["p95_ns"] for report in reports]
    ndabi_p95 = [arm(report, "ndabi")["p95_ns"] for report in reports]
    all_process_gates = all(report["gates"]["passed"] for report in reports)
    median_gate = statistics.median(ndabi_p95) <= statistics.median(json_p95)
    aggregate = {
        "campaign": "NDABI shared-session White Tree v4.4",
        "campaign_id": campaign_id,
        "process_count": PROCESS_COUNT,
        "iterations_per_process": ITERATIONS,
        "warmup_per_process": WARMUP,
        "binary_sha256": binary_digest,
        "source_sha256": source_digest,
        "json_p95_ns": json_p95,
        "ndabi_p95_ns": ndabi_p95,
        "median_json_p95_ns": statistics.median(json_p95),
        "median_ndabi_p95_ns": statistics.median(ndabi_p95),
        "all_process_gates_passed": all_process_gates,
        "median_latency_gate_passed": median_gate,
        "accepted": all_process_gates and median_gate,
        "process_results": [str(path.relative_to(ROOT)) for path in sorted(campaign.glob("process-*.json"))],
    }
    encoded = json.dumps(aggregate, indent=2) + "\n"
    (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
    latest.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if aggregate["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
