#!/usr/bin/env python3
"""Run the repaired local Supavisor concurrency campaign v7.4."""

from pathlib import Path

import validation_suite_v73 as campaign


ROOT = Path(__file__).resolve().parent
campaign.RESULT_ROOT = ROOT / "results" / "v74"
campaign.CAMPAIGN_NAME = "NDABI Supavisor concurrency campaign v7.4"
campaign.CAMPAIGN_LABEL = "v7.4"
campaign.TENANT_ID = "ndabi-v74"
campaign.SESSION_PROOF_LABEL = "ndabi-v74-session-proof"
campaign.SESSION_PROOF_EXPECTED = "74"
campaign.MINIMUM_HOST_IDLE_PERCENT = 50.0
campaign.SOURCE_PATHS = campaign.SOURCE_PATHS + (
    "validation_suite_v74.py",
    "requirements-v74.txt",
    "../../specs/ndabi_supavisor_concurrency_campaign_v7_4.md",
)


if __name__ == "__main__":
    raise SystemExit(campaign.main())
