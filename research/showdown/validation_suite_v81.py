#!/usr/bin/env python3
"""Run the duration-corrected NDABI Supabase production campaign."""

from __future__ import annotations

from pathlib import Path

import validation_suite_v80 as production


ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "results" / "v81"
CAMPAIGN_NAME = "NDABI Supabase production stack v8.1"
CAMPAIGN_LABEL = "v8.1 stack"
FORMAL_CAMPAIGN_NAME = "NDABI Supabase production campaign v8.1"
CAMPAIGN_VERSION = "v8.1"
TENANT_ID = "ndabi-v81"
SESSION_PROOF_LABEL = "ndabi-v81-session-proof"
SESSION_PROOF_EXPECTED = "81"
SAMPLES_BY_ARM = {
    "native": 8_191,
    "ndabi": 8_191,
    "postgrest_rpc": 2_047,
    "postgrest": 255,
}
SOURCE_PATHS = production.SOURCE_PATHS + (
    "validation_suite_v81.py",
    "requirements-v81.txt",
    "tests/test_validation_v81.py",
    "../../specs/ndabi_supabase_production_campaign_v8_1.md",
)
BASE_CONFIGURE = production.configure


def configure(
    *,
    build_binary: bool = True,
    functional: bool = False,
    result_root: Path | None = None,
) -> None:
    """Apply the v8.1 identity and duration correction."""
    target_root = result_root or RESULT_ROOT
    BASE_CONFIGURE(
        build_binary=build_binary,
        functional=functional,
        result_root=target_root,
    )
    production.RESULT_ROOT = RESULT_ROOT
    production.CAMPAIGN_NAME = CAMPAIGN_NAME
    production.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    production.FORMAL_CAMPAIGN_NAME = FORMAL_CAMPAIGN_NAME
    production.CAMPAIGN_VERSION = CAMPAIGN_VERSION
    production.ENTRYPOINT = Path(__file__).resolve()
    production.TENANT_ID = TENANT_ID
    production.SESSION_PROOF_LABEL = SESSION_PROOF_LABEL
    production.SESSION_PROOF_EXPECTED = SESSION_PROOF_EXPECTED
    production.SAMPLES_BY_ARM = SAMPLES_BY_ARM
    production.SOURCE_PATHS = SOURCE_PATHS
    production.campaign.RESULT_ROOT = target_root
    production.campaign.CAMPAIGN_NAME = CAMPAIGN_NAME
    production.campaign.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    production.campaign.TENANT_ID = TENANT_ID
    production.campaign.SESSION_PROOF_LABEL = SESSION_PROOF_LABEL
    production.campaign.SESSION_PROOF_EXPECTED = SESSION_PROOF_EXPECTED
    production.campaign.SAMPLES_BY_ARM = (
        production.FUNCTIONAL_SAMPLES_BY_ARM if functional else SAMPLES_BY_ARM
    )
    production.campaign.SMOKE_RESULT_PATH = (
        RESULT_ROOT / "functional-latest.json"
        if functional
        else RESULT_ROOT / "performance-smoke-latest.json"
    )
    production.campaign.SOURCE_PATHS = SOURCE_PATHS


production.configure = configure
production.RESULT_ROOT = RESULT_ROOT
production.FORMAL_CAMPAIGN_NAME = FORMAL_CAMPAIGN_NAME
production.CAMPAIGN_VERSION = CAMPAIGN_VERSION
production.ENTRYPOINT = Path(__file__).resolve()


if __name__ == "__main__":
    raise SystemExit(production.main())
