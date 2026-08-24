import copy
import unittest

import validation_suite_v73 as campaign
import validation_suite_v76 as duration_repair
from tests.test_validation_v73 import validated_measurement, worker


class SupavisorDurationStableCampaignTests(unittest.TestCase):
    def test_repair_retains_the_workload_and_performance_gates(self):
        self.assertEqual(duration_repair.campaign.CONCURRENCY_LEVELS, (1, 8, 32))
        self.assertEqual(duration_repair.campaign.OPERATIONS, 16)
        self.assertEqual(
            duration_repair.SAMPLES_BY_ARM,
            {"ndabi": 4_095, "postgrest": 127},
        )
        self.assertEqual(duration_repair.MINIMUM_ARM_DURATION_NS, 1_000_000_000)

    def test_source_custody_covers_the_v76_contract(self):
        paths = set(duration_repair.SOURCE_PATHS)
        self.assertIn("validation_suite_v76.py", paths)
        self.assertIn("requirements-v76.txt", paths)
        self.assertIn(
            "../../specs/ndabi_supavisor_concurrency_campaign_v7_6.md", paths
        )

    def test_arm_specific_worker_counts_validate(self):
        previous = campaign.SAMPLES_BY_ARM
        try:
            campaign.SAMPLES_BY_ARM = duration_repair.SAMPLES_BY_ARM
            for arm in ("ndabi", "postgrest"):
                report = worker(arm, 0)
                samples = duration_repair.SAMPLES_BY_ARM[arm]
                report["samples"] = samples
                report["logical_operations"] = samples * campaign.OPERATIONS
                report["raw_ns"] = list(range(1, samples + 1))
                report["p50_ns"] = campaign.percentile(report["raw_ns"], 50)
                report["p95_ns"] = campaign.percentile(report["raw_ns"], 95)
                report["p99_ns"] = campaign.percentile(report["raw_ns"], 99)
                campaign.validate_worker(report, arm, 0)
        finally:
            campaign.SAMPLES_BY_ARM = previous

    def test_arm_specific_query_counts_are_exact(self):
        previous = campaign.SAMPLES_BY_ARM
        try:
            campaign.SAMPLES_BY_ARM = duration_repair.SAMPLES_BY_ARM
            self.assertEqual(campaign.expected_data_queries("ndabi", 1), 4_098)
            self.assertEqual(campaign.expected_data_queries("postgrest", 1), 2_080)
            self.assertEqual(campaign.expected_data_queries("ndabi", 32), 131_136)
            self.assertEqual(campaign.expected_data_queries("postgrest", 32), 66_560)
        finally:
            campaign.SAMPLES_BY_ARM = previous

    def test_duration_gate_rejects_a_short_arm(self):
        previous = campaign.MINIMUM_ARM_DURATION_NS
        try:
            campaign.MINIMUM_ARM_DURATION_NS = 1_000_000_001
            report = copy.deepcopy(validated_measurement("ndabi"))
            with self.assertRaisesRegex(ValueError, "duration is too short"):
                campaign.validate_arm_measurement(report, "ndabi", 1)
        finally:
            campaign.MINIMUM_ARM_DURATION_NS = previous

    def test_build_monitor_evidence_is_mandatory(self):
        previous = campaign.MONITOR_BUILD_PROCESSES_DURING_ARM
        try:
            campaign.MONITOR_BUILD_PROCESSES_DURING_ARM = True
            report = copy.deepcopy(validated_measurement("ndabi"))
            with self.assertRaisesRegex(ValueError, "build process contaminated"):
                campaign.validate_arm_measurement(report, "ndabi", 1)
        finally:
            campaign.MONITOR_BUILD_PROCESSES_DURING_ARM = previous


if __name__ == "__main__":
    unittest.main()
