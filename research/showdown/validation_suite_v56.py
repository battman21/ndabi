#!/usr/bin/env python3
"""Run the frozen MongoDB closed-evidence v5.6 campaign once."""

from pathlib import Path

import validation_suite_v54 as campaign


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v56"
MONGODB_IMAGE = campaign.MONGODB_IMAGE
RESULT_ROOT = ROOT / "results" / "v56"
PROCESS_COUNT = campaign.PROCESS_COUNT
BATCH_SIZES = campaign.BATCH_SIZES
CAMPAIGN_LABEL = "NDABI MongoDB closed evidence v5.6"
RUN_COMMAND = "run-v56"
VERSION = "v5.6"
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-session/Cargo.toml",
    "crates/ndabi-session/src/lib.rs",
    "crates/ndabi-mongodb/Cargo.toml",
    "crates/ndabi-mongodb/src/lib.rs",
    "src/bin/ndabi_v53.rs",
    "src/bin/ndabi_v56.rs",
    "validation_suite_v54.py",
    "validation_suite_v56.py",
    "../../specs/ndabi_mongodb_closed_evidence_campaign_v5_6.md",
)

aggregate_case = campaign.aggregate_case
ARM_IDS = (
    "native-sequential",
    "json-sequential",
    "json-set",
    "native-set",
    "ndabi-typed",
    "ndabi-raw",
)


def case_integrity(case: dict) -> bool:
    arms = case.get("arms", [])
    arm_ids = [arm.get("id") for arm in arms]
    return (
        case.get("exact_results") is True
        and len(arm_ids) == len(ARM_IDS)
        and all(isinstance(identifier, str) for identifier in arm_ids)
        and sorted(arm_ids) == sorted(ARM_IDS)
        and all(arm.get("deterministic_encoding") is True for arm in arms)
    )


def process_integrity(report: dict) -> bool:
    audit = report.get("single_batch_audit")
    cases = report.get("cases", [])
    batch_sizes = [case.get("batch_size") for case in cases]
    return (
        report.get("campaign") == CAMPAIGN_LABEL
        and report.get("dataset_rows") == 1_000_000
        and report.get("frame_bytes") == 76
        and report.get("refusals") == "8/8"
        and audit is not None
        and audit.get("passed") is True
        and audit.get("find_commands") == 1
        and audit.get("get_more_commands") == 0
        and len(batch_sizes) == len(BATCH_SIZES)
        and all(isinstance(size, int) for size in batch_sizes)
        and sorted(batch_sizes) == list(BATCH_SIZES)
        and all(case_integrity(case) for case in cases)
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
