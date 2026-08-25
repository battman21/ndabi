#!/usr/bin/env python3
"""Run the frozen NDABI v0.9 paired local campaign."""

from pathlib import Path

import validation_suite_v07 as campaign


campaign.PROFILE = "v09"
campaign.BINARY = campaign.ROOT / "target" / "release" / "ndabi-v09"
campaign.LATEST = campaign.RESULTS_ROOT / "v09-validation-suite.json"
campaign.EXPECTED_RESULT_SCHEMA = "ndabi-poc-result-v0.9"
campaign.SUITE_SCHEMA = "ndabi-v09-validation-suite-v0.1"
campaign.CAMPAIGN_STATUS = "paired-local-campaign"
campaign.EXPECTED_SCHEDULER_PROFILE = "operating-system-default"
campaign.VARIABILITY_BASIS = "conservative-speedup"
campaign.DIRECT_SPEEDUP_KEY = "direct_vs_stateless_json_paired_p95_speedup_low"
campaign.PREPARED_SPEEDUP_KEY = "prepared_vs_stateless_json_paired_p95_speedup_low"
campaign.RUNNER_FILES = [Path(campaign.__file__).resolve(), Path(__file__).resolve()]


if __name__ == "__main__":
    campaign.main()
