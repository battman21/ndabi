#!/usr/bin/env python3
"""Run the frozen MongoDB final-harness v5.7 campaign once."""

from pathlib import Path

import validation_suite_v54 as campaign
from validation_suite_v56 import ARM_IDS, case_integrity


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v57"
MONGODB_IMAGE = campaign.MONGODB_IMAGE
RESULT_ROOT = ROOT / "results" / "v57"
PROCESS_COUNT = campaign.PROCESS_COUNT
BATCH_SIZES = campaign.BATCH_SIZES
CAMPAIGN_LABEL = "NDABI MongoDB final harness v5.7"
RUN_COMMAND = "run-v57"
VERSION = "v5.7"
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-session/Cargo.toml",
    "crates/ndabi-session/src/lib.rs",
    "crates/ndabi-mongodb/Cargo.toml",
    "crates/ndabi-mongodb/src/lib.rs",
    "src/bin/ndabi_v53.rs",
    "src/bin/ndabi_v57.rs",
    "validation_suite_v54.py",
    "validation_suite_v56.py",
    "validation_suite_v57.py",
    "../../specs/ndabi_mongodb_final_harness_campaign_v5_7.md",
)

aggregate_case = campaign.aggregate_case


def process_integrity(report: dict) -> bool:
    audit = report.get("single_batch_audit")
    cases = report.get("cases", [])
    batch_sizes = [case.get("batch_size") for case in cases]
    return (
        report.get("campaign") == CAMPAIGN_LABEL
        and report.get("dataset_rows") == 1_000_000
        and report.get("frame_bytes") == 76
        and report.get("refusals") == "8/8"
        and report.get("passed") is True
        and audit is not None
        and audit.get("passed") is True
        and audit.get("find_commands") == 1
        and audit.get("get_more_commands") == 0
        and len(batch_sizes) == len(BATCH_SIZES)
        and all(isinstance(size, int) for size in batch_sizes)
        and sorted(batch_sizes) == list(BATCH_SIZES)
        and all(case.get("passed") is True and case_integrity(case) for case in cases)
    )


def main() -> int:
    campaign.BINARY = BINARY
    campaign.RESULT_ROOT = RESULT_ROOT
    campaign.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    campaign.RUN_COMMAND = RUN_COMMAND
    campaign.VERSION = VERSION
    campaign.SOURCE_PATHS = SOURCE_PATHS
    campaign.process_integrity = process_integrity
    return campaign.main()


if __name__ == "__main__":
    raise SystemExit(main())
