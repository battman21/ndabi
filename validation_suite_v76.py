#!/usr/bin/env python3
"""Run the duration-stable Supavisor concurrency campaign v7.6."""

from pathlib import Path

import validation_suite_v75 as repair


campaign = repair.campaign
ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "results" / "v76"
CAMPAIGN_NAME = "NDABI Supavisor concurrency campaign v7.6"
CAMPAIGN_LABEL = "v7.6"
TENANT_ID = "ndabi-v76"
SESSION_PROOF_LABEL = "ndabi-v76-session-proof"
SESSION_PROOF_EXPECTED = "76"
SAMPLES_BY_ARM = {"ndabi": 4_095, "postgrest": 127}
MINIMUM_ARM_DURATION_NS = 1_000_000_000
MONITOR_BUILD_PROCESSES_DURING_ARM = True
SOURCE_PATHS = repair.SOURCE_PATHS + (
    "validation_suite_v76.py",
    "requirements-v76.txt",
    "../../specs/ndabi_supavisor_concurrency_campaign_v7_6.md",
)


def configure() -> None:
    repair.configure()
    campaign.RESULT_ROOT = RESULT_ROOT
    campaign.CAMPAIGN_NAME = CAMPAIGN_NAME
    campaign.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    campaign.TENANT_ID = TENANT_ID
    campaign.SESSION_PROOF_LABEL = SESSION_PROOF_LABEL
    campaign.SESSION_PROOF_EXPECTED = SESSION_PROOF_EXPECTED
    campaign.SAMPLES_BY_ARM = SAMPLES_BY_ARM
    campaign.MINIMUM_ARM_DURATION_NS = MINIMUM_ARM_DURATION_NS
    campaign.MONITOR_BUILD_PROCESSES_DURING_ARM = MONITOR_BUILD_PROCESSES_DURING_ARM
    campaign.SOURCE_PATHS = SOURCE_PATHS


if __name__ == "__main__":
    configure()
    raise SystemExit(campaign.main())
