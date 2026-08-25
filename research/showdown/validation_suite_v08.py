#!/usr/bin/env python3
"""Run the frozen NDABI v0.8 scheduler-controlled campaign."""

from pathlib import Path

import validation_suite_v07 as campaign


campaign.PROFILE = "v08"
campaign.BINARY = campaign.ROOT / "target" / "release" / "ndabi-v08"
campaign.LATEST = campaign.RESULTS_ROOT / "v08-validation-suite.json"
campaign.EXPECTED_RESULT_SCHEMA = "ndabi-poc-result-v0.8"
campaign.SUITE_SCHEMA = "ndabi-v08-validation-suite-v0.1"
campaign.CAMPAIGN_STATUS = "scheduler-controlled-local-campaign"
campaign.EXPECTED_SCHEDULER_PROFILE = "macos-user-interactive"
campaign.RUNNER_FILES = [Path(campaign.__file__).resolve(), Path(__file__).resolve()]


if __name__ == "__main__":
    campaign.main()
