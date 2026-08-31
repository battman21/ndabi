from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


CAMPAIGN_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CAMPAIGN_DIR))
SPEC = importlib.util.spec_from_file_location(
    "operand_bundle_v02", CAMPAIGN_DIR / "operand_bundle_v02.py"
)
campaign = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(campaign)


def measured_arms() -> dict[str, dict[str, object]]:
    return {
        "fused_native": {
            "wall_p95_ns": 6_747_917,
            "wall_mean_ns": 5_793_793,
            "cpu_mean_ns": 242_950,
            "allocated_bytes": 361_374,
        },
        "ndabi_graph": {
            "wall_p95_ns": 6_874_750,
            "wall_mean_ns": 5_900_040,
            "cpu_mean_ns": 314_440,
            "allocated_bytes": 344_984,
        },
        "ndabi_bundle": {
            "wall_p95_ns": 6_779_375,
            "wall_mean_ns": 5_933_650,
            "cpu_mean_ns": 291_620,
            "allocated_bytes": 344_984,
            "request_reduction_percent": 74.232536,
            "bundle_decodes": [1],
        },
    }


class OperandBundleCampaignV02Tests(unittest.TestCase):
    def test_the_floor_adjusted_gates_accept_the_existing_smoke_cell(self) -> None:
        result = campaign.evaluate_cell(measured_arms(), 1_024)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["floor_adjusted"]["graph_cpu_excess_ns"], 71_490)
        self.assertEqual(result["floor_adjusted"]["bundle_cpu_excess_ns"], 48_670)

    def test_complete_cpu_and_allocation_regressions_still_fail(self) -> None:
        arms = measured_arms()
        arms["ndabi_bundle"]["cpu_mean_ns"] = 400_000
        arms["ndabi_bundle"]["allocated_bytes"] = 400_000
        result = campaign.evaluate_cell(arms, 1_024)
        self.assertFalse(result["accepted"])
        self.assertFalse(result["gates"]["complete_cpu_floor"])
        self.assertFalse(result["gates"]["allocation_non_regression"])

    def test_repeatability_requires_five_low_variation_repetitions(self) -> None:
        reports = []
        for repetition in range(5):
            for item_count, concurrency in campaign.FORMAL_CELLS:
                arms = {
                    arm: {"wall_mean_ns": 100 + repetition, "wall_p95_ns": 120 + repetition}
                    for arm in campaign.base.ARMS
                }
                reports.append(
                    {
                        "repetition": repetition + 1,
                        "item_count": item_count,
                        "concurrency": concurrency,
                        "arms": arms,
                    }
                )
        self.assertTrue(campaign.evaluate_repeatability(reports)["accepted"])
        reports.pop()
        self.assertFalse(campaign.evaluate_repeatability(reports)["accepted"])


if __name__ == "__main__":
    unittest.main()
