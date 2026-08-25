import copy
import gzip
import json
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

    def test_accepted_evidence_revalidates(self):
        aggregate = json.loads((duration_repair.RESULT_ROOT / "latest.json").read_text())
        evidence = duration_repair.RESULT_ROOT / aggregate["campaign_id"]
        stored = json.loads((evidence / "aggregate.json").read_text())
        self.assertEqual(aggregate, stored)
        self.assertEqual(
            aggregate["source_commit"],
            "2e65c31ac28a53343ec44837e509e98341ed498f",
        )
        self.assertTrue(aggregate["source_custody_passed"])
        self.assertTrue(aggregate["security_passed"])
        self.assertEqual(len(aggregate["security"]), 17)
        self.assertTrue(all(aggregate["security"].values()))
        self.assertTrue(aggregate["repeatability_passed"])
        self.assertTrue(all(item["passed"] for item in aggregate["repeatability"]))
        self.assertTrue(aggregate["accepted"])
        self.assertEqual(aggregate["samples_per_worker"], duration_repair.SAMPLES_BY_ARM)
        self.assertTrue(aggregate["build_process_monitor_enabled"])
        self.assertEqual(
            aggregate["minimum_arm_duration_ns"],
            duration_repair.MINIMUM_ARM_DURATION_NS,
        )
        previous = (
            campaign.SAMPLES_BY_ARM,
            campaign.MINIMUM_ARM_DURATION_NS,
            campaign.MONITOR_BUILD_PROCESSES_DURING_ARM,
        )
        try:
            duration_repair.configure()
            for process in range(1, aggregate["process_count"] + 1):
                with gzip.open(
                    evidence / f"process-{process}.json.gz", "rt", encoding="utf-8"
                ) as source:
                    report = json.load(source)
                campaign.validate_process_report(report)
                self.assertTrue(report["passed"])
                for case in report["cases"]:
                    for measurement in case["measurements"].values():
                        self.assertEqual(
                            measurement["observed_data_queries"],
                            measurement["expected_data_queries"],
                        )
                        self.assertEqual(
                            measurement["active_build_processes_during_arm"], []
                        )
                        self.assertEqual(measurement["build_monitor_errors"], [])
                        self.assertGreaterEqual(
                            measurement["total_elapsed_ns"],
                            duration_repair.MINIMUM_ARM_DURATION_NS,
                        )
        finally:
            (
                campaign.SAMPLES_BY_ARM,
                campaign.MINIMUM_ARM_DURATION_NS,
                campaign.MONITOR_BUILD_PROCESSES_DURING_ARM,
            ) = previous


if __name__ == "__main__":
    unittest.main()
