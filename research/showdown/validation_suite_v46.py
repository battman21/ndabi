#!/usr/bin/env python3
"""Run the frozen NDABI TLS and controlled-delay v4.6 campaign once."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

import validation_suite_v44 as shared


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v46"
RESULT_ROOT = ROOT / "results" / "v46"
PROCESS_COUNT = 5
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-session/Cargo.toml",
    "crates/ndabi-session/src/lib.rs",
    "src/bin/ndabi_v46.rs",
)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update((ROOT / relative).read_bytes() + b"\0")
    return digest.hexdigest()


def measurement(report: dict, condition: str, surface: str) -> dict:
    return next(
        value
        for value in report["measurements"]
        if value["condition"] == condition and value["surface"] == surface
    )


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v4.6 formal campaign already exists")
    if not BINARY.is_file():
        raise SystemExit("the release v4.6 binary is absent")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    binary_digest = shared.sha256(BINARY)
    source_digest = source_sha256()
    reports = []
    for process in range(1, PROCESS_COUNT + 1):
        completed = subprocess.run(
            [str(BINARY)], cwd=ROOT, check=True, capture_output=True, text=True
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
    aggregate = {
        "campaign": "NDABI TLS and controlled-delay v4.6",
        "campaign_id": campaign_id,
        "process_count": PROCESS_COUNT,
        "binary_sha256": binary_digest,
        "source_sha256": source_digest,
        "loopback_json_p95_ns": [measurement(report, "loopback", "json")["p95_ns"] for report in reports],
        "loopback_ndabi_p95_ns": [measurement(report, "loopback", "ndabi")["p95_ns"] for report in reports],
        "controlled_delay_json_p95_ns": [measurement(report, "controlled-delay", "json")["p95_ns"] for report in reports],
        "controlled_delay_ndabi_p95_ns": [measurement(report, "controlled-delay", "ndabi")["p95_ns"] for report in reports],
        "accepted": all(report["passed"] for report in reports),
        "process_results": [str(path.relative_to(ROOT)) for path in sorted(campaign.glob("process-*.json"))],
    }
    encoded = json.dumps(aggregate, indent=2) + "\n"
    (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
    latest.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if aggregate["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
