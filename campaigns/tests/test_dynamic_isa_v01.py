from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


CAMPAIGN_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CAMPAIGN_DIR))
SPEC = importlib.util.spec_from_file_location(
    "dynamic_isa_v01", CAMPAIGN_DIR / "dynamic_isa_v01.py"
)
campaign = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(campaign)


def measured_arms() -> dict[str, dict[str, object]]:
    common = {
        "full_request_bytes": 436,
        "cached_request_bytes": 120,
        "request_reduction_percent": 72.477064,
        "result_fingerprint": "6a4f7c031c582177",
    }
    return {
        "governed_native": {
            **common,
            "wall_p95_ns": 500_000,
            "wall_mean_ns": 400_000,
            "cpu_mean_ns": 100_000,
            "allocated_bytes": 20_000,
            "throughput_ops_s": 2_500.0,
        },
        "dynamic_full": {
            **common,
            "wall_p95_ns": 510_000,
            "wall_mean_ns": 405_000,
            "cpu_mean_ns": 112_000,
            "allocated_bytes": 24_000,
            "throughput_ops_s": 2_450.0,
        },
        "dynamic_cached": {
            **common,
            "wall_p95_ns": 510_000,
            "wall_mean_ns": 408_000,
            "cpu_mean_ns": 110_000,
            "allocated_bytes": 23_000,
            "throughput_ops_s": 2_430.0,
        },
    }


class DynamicIsaCampaignTests(unittest.TestCase):
    def test_the_frozen_gates_accept_a_qualified_cell(self) -> None:
        self.assertTrue(campaign.evaluate_cell(measured_arms())["accepted"])

    def test_each_material_regression_fails_its_gate(self) -> None:
        cases = {
            "request_reduction": ("request_reduction_percent", 69.9),
            "p95_floor": ("wall_p95_ns", 526_000),
            "mean_floor": ("wall_mean_ns", 413_000),
            "client_cpu_floor": ("cpu_mean_ns", 116_000),
            "allocation_non_regression": ("allocated_bytes", 24_001),
            "throughput_floor": ("throughput_ops_s", 2_374.0),
        }
        for gate, (metric, value) in cases.items():
            with self.subTest(gate=gate):
                arms = measured_arms()
                arms["dynamic_cached"][metric] = value
                result = campaign.evaluate_cell(arms)
                self.assertFalse(result["accepted"])
                self.assertFalse(result["gates"][gate])

    def test_repeatability_requires_five_low_variation_repetitions(self) -> None:
        reports = []
        for repetition in range(5):
            for result_rows, concurrency in campaign.FORMAL_CELLS:
                arms = {
                    arm: {
                        "wall_mean_ns": 100 + repetition,
                        "wall_p95_ns": 120 + repetition,
                    }
                    for arm in campaign.ARMS
                }
                reports.append(
                    {
                        "repetition": repetition + 1,
                        "result_rows": result_rows,
                        "concurrency": concurrency,
                        "arms": arms,
                    }
                )
        self.assertTrue(campaign.evaluate_repeatability(reports)["accepted"])
        reports.pop()
        self.assertFalse(campaign.evaluate_repeatability(reports)["accepted"])

    def test_concurrent_throughput_uses_the_complete_synchronised_interval(self) -> None:
        reports = []
        for started_ns, ended_ns in (
            (1_000_000_000, 2_000_000_000),
            (1_500_000_000, 3_000_000_000),
        ):
            reports.append(
                {
                    "result_fingerprint": "same",
                    "full_request_bytes": 436,
                    "cached_request_bytes": 120,
                    "request_reduction_percent": 72.477064,
                    "wall": {"mean_ns": 10, "p95_ns": 12, "p99_ns": 14},
                    "client_thread_cpu": {"mean_ns": 5},
                    "allocation": {"allocations": 2, "allocated_bytes": 64},
                    "throughput_ops_s": 999_999.0,
                    "iterations": 100,
                    "measurement_elapsed_ns": ended_ns - started_ns,
                    "measurement_started_monotonic_ns": started_ns,
                    "measurement_ended_monotonic_ns": ended_ns,
                    "barrier_synchronised": True,
                }
            )
        aggregate = campaign.aggregate_arm(reports)
        self.assertEqual(aggregate["throughput_ops_s"], 100.0)
        self.assertEqual(aggregate["measurement_elapsed_ns"], 2_000_000_000)
        self.assertEqual(
            aggregate["measurement_started_monotonic_ns"], 1_000_000_000
        )
        self.assertEqual(aggregate["measurement_ended_monotonic_ns"], 3_000_000_000)


if __name__ == "__main__":
    unittest.main()
