import copy
import unittest

import validation_suite_v73 as campaign


def worker(arm: str, identifier: int, digest: str = "11" * 32) -> dict:
    raw = list(range(1_000, 32_000, 1_000))
    return {
        "schema": "ndabi-supavisor-load-worker-v7.3",
        "arm": {
            "ndabi": "ndabi-indexed-batch-session",
            "postgrest": "postgrest-user-jwt",
        }[arm],
        "worker": identifier,
        "operations": campaign.OPERATIONS,
        "rows_per_operation": campaign.ROWS_PER_OPERATION,
        "warmups": campaign.WARMUPS,
        "samples": campaign.SAMPLES,
        "logical_operations": campaign.SAMPLES * campaign.OPERATIONS,
        "result_bytes": 10_950,
        "result_sha256": digest,
        "measured_start_monotonic_ns": 1_000_000,
        "measured_end_monotonic_ns": 2_000_000,
        "total_elapsed_ns": 1_000_000,
        "total_cpu_ns": 500_000,
        "p50_ns": campaign.percentile(raw, 50),
        "p95_ns": campaign.percentile(raw, 95),
        "p99_ns": campaign.percentile(raw, 99),
        "mean_allocations": 10.0,
        "mean_allocated_bytes": 1_000.0,
        "peak_additional_live_bytes": 2_000,
        "raw_ns": raw,
        "passed": True,
    }


def measurement(arm: str, throughput: float, p95: int) -> dict:
    return {
        "arm": arm,
        "concurrency": 1,
        "workers": [worker(arm, 0)],
        "errors": [],
        "completed_workers": 1,
        "completed_requests": campaign.SAMPLES,
        "logical_operations": campaign.SAMPLES * campaign.OPERATIONS,
        "total_elapsed_ns": 1_000_000,
        "logical_operations_per_second": throughput,
        "p50_request_ns": p95 // 2,
        "p95_request_ns": p95,
        "p99_request_ns": p95 * 2,
        "total_client_cpu_ns": 500_000,
        "mean_allocations": 10.0,
        "mean_allocated_bytes": 1_000.0,
        "peak_additional_live_bytes": 2_000,
        "observed_data_queries": 34 if arm == "ndabi" else 544,
        "expected_data_queries": 34 if arm == "ndabi" else 544,
        "query_gate_passed": True,
        "complete": True,
        "host_idle_preflight": {
            "minimum_idle_percent": 90.0,
            "observations": [90.0, 91.0, 92.0],
            "active_build_processes": [],
            "passed": True,
        },
    }


def validated_measurement(arm: str) -> dict:
    report = worker(arm, 0)
    query_count = 34 if arm == "ndabi" else 544
    return {
        "arm": arm,
        "concurrency": 1,
        "workers": [report],
        "errors": [],
        "completed_workers": 1,
        "completed_requests": campaign.SAMPLES,
        "logical_operations": campaign.SAMPLES * campaign.OPERATIONS,
        "total_elapsed_ns": 1_000_000,
        "logical_operations_per_second": 496_000.0,
        "p50_request_ns": campaign.percentile(report["raw_ns"], 50),
        "p95_request_ns": campaign.percentile(report["raw_ns"], 95),
        "p99_request_ns": campaign.percentile(report["raw_ns"], 99),
        "total_client_cpu_ns": 500_000,
        "mean_allocations": 10.0,
        "mean_allocated_bytes": 1_000.0,
        "peak_additional_live_bytes": 2_000,
        "observed_data_queries": query_count,
        "expected_data_queries": query_count,
        "query_gate_passed": True,
        "complete": True,
        "host_idle_preflight": {
            "minimum_idle_percent": 90.0,
            "observations": [90.0, 91.0, 92.0],
            "active_build_processes": [],
            "passed": True,
        },
    }


class SupavisorConcurrencyCampaignTests(unittest.TestCase):
    def test_campaign_shape_is_frozen(self):
        self.assertEqual(campaign.PROCESS_COUNT, 5)
        self.assertEqual(campaign.CONCURRENCY_LEVELS, (1, 8, 32))
        self.assertEqual(campaign.OPERATIONS, 16)
        self.assertEqual(campaign.SAMPLES, 31)
        self.assertEqual(campaign.POOL_SIZE, 64)

    def test_source_custody_covers_the_worker_and_contract(self):
        paths = set(campaign.SOURCE_PATHS)
        self.assertIn("src/bin/ndabi_v71.rs", paths)
        self.assertIn("validation_suite_v73.py", paths)
        self.assertIn(
            "../../specs/ndabi_supavisor_concurrency_campaign_v7_3.md", paths
        )

    def test_host_idle_parser_uses_the_last_sample(self):
        output = "CPU usage: 50.0% user, 10.0% sys, 40.0% idle\nCPU usage: 5.0% user, 5.0% sys, 90.0% idle\n"
        self.assertEqual(campaign.parse_host_idle(output), 90.0)

    def test_worker_validation_recomputes_percentiles(self):
        report = worker("ndabi", 0)
        campaign.validate_worker(report, "ndabi", 0)
        report["p95_ns"] += 1
        with self.assertRaisesRegex(ValueError, "invalid worker p95"):
            campaign.validate_worker(report, "ndabi", 0)

    def test_arm_comparison_accepts_fast_exact_ndabi(self):
        ndabi = measurement("ndabi", 12_000.0, 1_000_000)
        postgrest = measurement("postgrest", 3_000.0, 4_000_000)
        result = campaign.compare_arms(ndabi, postgrest)
        self.assertTrue(result["passed"])
        self.assertEqual(result["ndabi_throughput_over_postgrest"], 4.0)
        self.assertEqual(result["ndabi_p95_to_postgrest"], 0.25)

    def test_arm_comparison_rejects_result_drift(self):
        ndabi = measurement("ndabi", 12_000.0, 1_000_000)
        postgrest = measurement("postgrest", 3_000.0, 4_000_000)
        postgrest = copy.deepcopy(postgrest)
        postgrest["workers"][0]["result_sha256"] = "22" * 32
        result = campaign.compare_arms(ndabi, postgrest)
        self.assertFalse(result["canonical_results_equal"])
        self.assertFalse(result["passed"])

    def test_arm_comparison_rejects_query_drift(self):
        ndabi = measurement("ndabi", 12_000.0, 1_000_000)
        postgrest = measurement("postgrest", 3_000.0, 4_000_000)
        ndabi["query_gate_passed"] = False
        self.assertFalse(campaign.compare_arms(ndabi, postgrest)["passed"])

    def test_measurement_validation_recomputes_group_values(self):
        report = validated_measurement("ndabi")
        campaign.validate_arm_measurement(report, "ndabi", 1)
        report["logical_operations_per_second"] += 1
        with self.assertRaisesRegex(ValueError, "invalid logical throughput"):
            campaign.validate_arm_measurement(report, "ndabi", 1)


if __name__ == "__main__":
    unittest.main()
