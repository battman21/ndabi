"""Test the semantic batch campaign gates without Docker."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "semantic_batch_v02.py"
SPEC = importlib.util.spec_from_file_location("semantic_batch_v02", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
campaign = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = campaign
SPEC.loader.exec_module(campaign)


def measurement(arm: str, wall: list[int], cpu: list[int], worker_id: int = 1) -> dict:
    return {
        "measured_arm": arm,
        "coordinated": True,
        "exact_results": True,
        "receipt_verified": True,
        "worker_id": worker_id,
        "raw_samples": {
            "wall_ns": {
                "repeated_native": wall if arm == "repeated_native" else [],
                "fused_native": wall if arm == "fused_native" else [],
                "ndabi_graph": wall if arm == "ndabi_graph" else [],
            },
            "client_thread_cpu_ns": {
                "repeated_native": cpu if arm == "repeated_native" else [],
                "fused_native": cpu if arm == "fused_native" else [],
                "ndabi_graph": cpu if arm == "ndabi_graph" else [],
            },
        },
    }


class SemanticBatchCampaignTests(unittest.TestCase):
    def test_raw_samples_aggregate_without_losing_values(self) -> None:
        reports = [
            measurement("ndabi_graph", [10, 30], [2, 4], 1),
            measurement("ndabi_graph", [20, 40], [3, 5], 2),
        ]
        value = campaign.aggregate_samples(reports, "ndabi_graph")
        self.assertEqual(value["samples"], 4)
        self.assertEqual(value["mean_ns"], 25)
        self.assertEqual(value["p95_ns"], 30)
        self.assertEqual(value["client_cpu_ns"], 14)

    def test_arm_order_rotates_every_cell_and_repetition(self) -> None:
        self.assertEqual(campaign.arm_order(0, 0), campaign.ARMS)
        self.assertEqual(
            campaign.arm_order(1, 0),
            ("fused_native", "ndabi_graph", "repeated_native"),
        )
        self.assertEqual(
            campaign.arm_order(0, 2),
            ("ndabi_graph", "repeated_native", "fused_native"),
        )

    def test_conflicting_builds_refuse_without_matching_the_runner(self) -> None:
        text = """
        100 1 90.0 /usr/bin/cargo cargo build --release
        101 1 20.0 /usr/bin/python3 python3 validation_suite_v99.py
        102 1 10.0 /usr/bin/python3 python3 campaigns/semantic_batch_v02.py --formal
        """
        value = campaign.conflicting_processes(text, 102)
        self.assertEqual([item["pid"] for item in value], [100, 101])

    def test_comparison_uses_complete_stack_cpu_and_rss(self) -> None:
        values = {
            "repeated_native": {
                "p95_ns": 20_000,
                "mean_ns": 18_000,
                "complete_stack_cpu_ns": 10_000,
                "logical_operations": 10,
                "maximum_complete_stack_rss_bytes": 100,
                "request_compression_percent": 65.0,
                "result_bytes": 22,
            },
            "fused_native": {
                "p95_ns": 100,
                "mean_ns": 100,
                "complete_stack_cpu_ns": 1_000,
                "logical_operations": 10,
                "maximum_complete_stack_rss_bytes": 100,
                "request_compression_percent": 65.0,
                "result_bytes": 22,
            },
            "ndabi_graph": {
                "p95_ns": 102,
                "mean_ns": 101,
                "complete_stack_cpu_ns": 1_100,
                "logical_operations": 10,
                "maximum_complete_stack_rss_bytes": 104,
                "request_compression_percent": 65.0,
                "result_bytes": 22,
            },
        }
        result = campaign.compare_arms(values)
        self.assertGreater(result["repeated_vs_ndabi_p95_speedup"], 100)
        self.assertAlmostEqual(result["ndabi_stack_cpu_reduction_vs_repeated"], 0.89)
        self.assertAlmostEqual(result["ndabi_rss_ratio_vs_fused"], 1.04)

    def test_invalid_raw_evidence_refuses(self) -> None:
        report = measurement("ndabi_graph", [10], [2])
        report["receipt_verified"] = False
        with self.assertRaises(campaign.CampaignError):
            campaign.aggregate_samples([report], "ndabi_graph")

    def test_duplicate_worker_authorities_refuse(self) -> None:
        reports = [
            measurement("ndabi_graph", [10], [2], 1),
            measurement("ndabi_graph", [20], [3], 1),
        ]
        with self.assertRaises(campaign.CampaignError):
            campaign.aggregate_samples(reports, "ndabi_graph")


if __name__ == "__main__":
    unittest.main()
