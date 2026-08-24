#!/usr/bin/env python3
"""Run the repaired local Supavisor concurrency campaign v7.4."""

from pathlib import Path

import validation_suite_v73 as campaign


ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "results" / "v74"
CAMPAIGN_NAME = "NDABI Supavisor concurrency campaign v7.4"
CAMPAIGN_LABEL = "v7.4"
TENANT_ID = "ndabi-v74"
SESSION_PROOF_LABEL = "ndabi-v74-session-proof"
SESSION_PROOF_EXPECTED = "74"
MINIMUM_HOST_IDLE_PERCENT = 50.0
SOURCE_PATHS = campaign.SOURCE_PATHS + (
    "validation_suite_v74.py",
    "requirements-v74.txt",
    "../../specs/ndabi_supavisor_concurrency_campaign_v7_4.md",
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
