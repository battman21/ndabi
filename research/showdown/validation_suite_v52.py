#!/usr/bin/env python3
"""Run the frozen backend-class binding v5.2 campaign once."""

from pathlib import Path

import validation_suite_v51 as campaign


campaign.CAMPAIGN_NAME = "NDABI backend-class binding v5.2"
campaign.RESULT_ROOT = Path(__file__).resolve().parent / "results" / "v52"


if __name__ == "__main__":
    raise SystemExit(campaign.main())
