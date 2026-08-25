#!/usr/bin/env python3
"""Run the frozen MongoDB fixed-identity v4.9 campaign once."""

from pathlib import Path

import validation_suite_v48 as compatibility


class Campaign(compatibility.Campaign):
    """Keep v4.9 isolated from the preserved v4.8 profile."""

    CAMPAIGN_NAME = "NDABI MongoDB fixed-identity v4.9"
    RESULT_ROOT = Path(__file__).resolve().parent / "results" / "v49"


campaign = Campaign


if __name__ == "__main__":
    raise SystemExit(campaign.main())
