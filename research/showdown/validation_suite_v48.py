#!/usr/bin/env python3
"""Run the frozen MongoDB 6.0.26 compatibility v4.8 campaign once."""

from pathlib import Path

import validation_suite_v47 as base


class Campaign:
    """Keep one immutable campaign profile without module-global aliasing."""

    CAMPAIGN_NAME = "NDABI MongoDB compatibility v4.8"
    MONGODB_IMAGE = "mongo@sha256:0a83b2f824b29c94c5284a49b018db2e3166d9879d1edda5cce545d899ef2bbb"
    RESULT_ROOT = Path(__file__).resolve().parent / "results" / "v48"
    PROCESS_COUNT = base.PROCESS_COUNT

    @classmethod
    def main(cls) -> int:
        return base.main(
            campaign_name=cls.CAMPAIGN_NAME,
            mongodb_image=cls.MONGODB_IMAGE,
            result_root=cls.RESULT_ROOT,
        )


campaign = Campaign


if __name__ == "__main__":
    raise SystemExit(campaign.main())
