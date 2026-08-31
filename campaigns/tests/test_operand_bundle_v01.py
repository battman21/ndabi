from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


CAMPAIGN_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CAMPAIGN_DIR))
SPEC = importlib.util.spec_from_file_location(
    "operand_bundle_v01", CAMPAIGN_DIR / "operand_bundle_v01.py"
)
campaign = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(campaign)


class OperandBundleCampaignTests(unittest.TestCase):
    def test_the_frozen_gates_accept_only_complete_improvements(self) -> None:
        arms = {
            "fused_native": {
                "wall_p95_ns": 100,
                "wall_mean_ns": 100,
                "cpu_mean_ns": 100,
                "allocated_bytes": 100,
            },
            "ndabi_graph": {
                "wall_p95_ns": 110,
                "wall_mean_ns": 110,
                "cpu_mean_ns": 100,
                "allocated_bytes": 100,
            },
            "ndabi_bundle": {
                "wall_p95_ns": 104,
                "wall_mean_ns": 102,
                "cpu_mean_ns": 74,
                "allocated_bytes": 50,
                "request_reduction_percent": 74.0,
                "bundle_decodes": [1, 1],
            },
        }
        result = campaign.evaluate_cell(arms, 1024)
        self.assertTrue(result["accepted"])

        arms["ndabi_bundle"]["wall_p95_ns"] = 106
        result = campaign.evaluate_cell(arms, 1024)
        self.assertFalse(result["accepted"])
        self.assertFalse(result["gates"]["p95_floor"])

    def test_small_cells_do_not_claim_an_impossible_byte_reduction(self) -> None:
        arms = {
            "fused_native": {
                "wall_p95_ns": 100,
                "wall_mean_ns": 100,
                "cpu_mean_ns": 100,
                "allocated_bytes": 100,
            },
            "ndabi_graph": {
                "wall_p95_ns": 100,
                "wall_mean_ns": 100,
                "cpu_mean_ns": 100,
                "allocated_bytes": 100,
            },
            "ndabi_bundle": {
                "wall_p95_ns": 100,
                "wall_mean_ns": 100,
                "cpu_mean_ns": 70,
                "allocated_bytes": 40,
                "request_reduction_percent": 10.0,
                "bundle_decodes": [1],
            },
        }
        self.assertTrue(campaign.evaluate_cell(arms, 8)["accepted"])


if __name__ == "__main__":
    unittest.main()
