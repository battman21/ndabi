#!/usr/bin/env python3
"""Run the frozen MongoDB literal single-batch v5.5 campaign once."""

from pathlib import Path

import validation_suite_v54 as campaign


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v55"
MONGODB_IMAGE = campaign.MONGODB_IMAGE
RESULT_ROOT = ROOT / "results" / "v55"
PROCESS_COUNT = campaign.PROCESS_COUNT
BATCH_SIZES = campaign.BATCH_SIZES
CAMPAIGN_LABEL = "NDABI MongoDB literal single batch v5.5"
RUN_COMMAND = "run-v55"
VERSION = "v5.5"
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-session/Cargo.toml",
    "crates/ndabi-session/src/lib.rs",
    "crates/ndabi-mongodb/Cargo.toml",
    "crates/ndabi-mongodb/src/lib.rs",
    "src/bin/ndabi_v53.rs",
    "src/bin/ndabi_v54.rs",
    "src/bin/ndabi_v55.rs",
    "validation_suite_v54.py",
    "validation_suite_v55.py",
    "../../specs/ndabi_mongodb_literal_single_batch_campaign_v5_5.md",
)

aggregate_case = campaign.aggregate_case
process_integrity = campaign.process_integrity


def main() -> int:
    campaign.BINARY = BINARY
    campaign.RESULT_ROOT = RESULT_ROOT
    campaign.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    campaign.RUN_COMMAND = RUN_COMMAND
    campaign.VERSION = VERSION
    campaign.SOURCE_PATHS = SOURCE_PATHS
    return campaign.main()


if __name__ == "__main__":
    raise SystemExit(main())
