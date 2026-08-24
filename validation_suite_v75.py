#!/usr/bin/env python3
"""Run the build-exclusive Supavisor concurrency campaign v7.5."""

from pathlib import Path

import validation_suite_v73 as campaign


ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "results" / "v75"
CAMPAIGN_NAME = "NDABI Supavisor concurrency campaign v7.5"
CAMPAIGN_LABEL = "v7.5"
TENANT_ID = "ndabi-v75"
SESSION_PROOF_LABEL = "ndabi-v75-session-proof"
SESSION_PROOF_EXPECTED = "75"
MINIMUM_HOST_IDLE_PERCENT = 0.0
SOURCE_PATHS = campaign.SOURCE_PATHS + (
    "validation_suite_v75.py",
    "requirements-v75.txt",
    "../../specs/ndabi_supavisor_concurrency_campaign_v7_5.md",
)


def configure() -> None:
    campaign.RESULT_ROOT = RESULT_ROOT
    campaign.CAMPAIGN_NAME = CAMPAIGN_NAME
    campaign.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    campaign.TENANT_ID = TENANT_ID
    campaign.SESSION_PROOF_LABEL = SESSION_PROOF_LABEL
    campaign.SESSION_PROOF_EXPECTED = SESSION_PROOF_EXPECTED
    campaign.MINIMUM_HOST_IDLE_PERCENT = MINIMUM_HOST_IDLE_PERCENT
    campaign.SOURCE_PATHS = SOURCE_PATHS


if __name__ == "__main__":
    configure()
    raise SystemExit(campaign.main())
