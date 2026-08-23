import unittest
import hashlib

import validation_suite_v61


class CanonicalPostgresBatchCampaignTests(unittest.TestCase):
    def valid_report(self):
        cases = []
        for count, targets in validation_suite_v61.CASES.items():
            expected = validation_suite_v61.expected_result(count)
            sequential_wall = 20_000 if count == 32 else 50_000
            batch_wall = 1_000
            native_wall = 900
            sequential_cpu = 16_000 if count == 32 else 40_000
            batch_cpu = 800
            native_cpu = 700

            def measurement(arm, wall, cpu, allocations, allocated_bytes):
                return {
                    "arm": arm,
                    "p50_ns": wall,
                    "p95_ns": wall,
                    "p99_ns": wall,
                    "p50_cpu_ns": cpu,
                    "mean_allocations": allocations,
                    "mean_allocated_bytes": allocated_bytes,
                    "peak_additional_live_bytes": 1,
                    "raw_ns": [wall] * validation_suite_v61.SAMPLES,
                    "raw_cpu_ns": [cpu] * validation_suite_v61.SAMPLES,
                }

            measurements = [
                measurement("sequential-canonical", sequential_wall, sequential_cpu, 100.0, 1_000.0),
                measurement("batch-canonical", batch_wall, batch_cpu, 10.0, 300.0),
                measurement("native-fused", native_wall, native_cpu, 5.0, 200.0),
            ]
            sequential_bytes = 160 * count
            batch_bytes = 160 + 20 * count
            cases.append(
                {
                    "operation_count": count,
                    "sequential_frame_bytes": sequential_bytes,
                    "batch_frame_bytes": batch_bytes,
                    "request_compression": 1.0 - batch_bytes / sequential_bytes,
                    "response_bytes": len(expected),
                    "result_sha256": hashlib.sha256(expected).hexdigest(),
                    "measurements": measurements,
                    "sequential_data_queries": (validation_suite_v61.SAMPLES + validation_suite_v61.WARMUPS) * count,
                    "batch_data_queries": validation_suite_v61.SAMPLES + validation_suite_v61.WARMUPS,
                    "p95_speedup": sequential_wall / batch_wall,
                    "cpu_p50_speedup": sequential_cpu / batch_cpu,
                    "batch_native_p95_distance": batch_wall / native_wall,
                    "batch_native_cpu_distance": batch_cpu / native_cpu,
                    "allocation_reduction": 0.9,
                    "allocated_bytes_reduction": 0.7,
                    "receipts_valid": True,
                    "speed_target": targets["speed"],
                    "cpu_target": targets["cpu"],
                    "passed": True,
                }
            )
        return {
            "campaign": "NDABI canonical PostgreSQL batch v6.1",
            "samples": validation_suite_v61.SAMPLES,
            "warmups": validation_suite_v61.WARMUPS,
            "cases": cases,
            "security": {
                "replay_refused": True,
                "mutation_refused": True,
                "inadequate_budget_refused_before_query": True,
                "noncanonical_order_refused_before_query": True,
                "successful_data_queries": 1,
                "passed": True,
            },
            "passed": True,
        }

    def test_campaign_uses_five_processes_and_a_pinned_engine(self):
        self.assertEqual(validation_suite_v61.PROCESS_COUNT, 5)
        self.assertIn("@sha256:", validation_suite_v61.POSTGRES_IMAGE)

    def test_source_custody_covers_protocol_adapter_binary_and_runner(self):
        paths = set(validation_suite_v61.SOURCE_PATHS)
        self.assertIn("crates/ndabi-protocol/src/batch.rs", paths)
        self.assertIn("crates/ndabi-postgres-v1/src/lib.rs", paths)
        self.assertIn("src/bin/ndabi_v61.rs", paths)
        self.assertIn("validation_suite_v61.py", paths)

    def test_campaign_retains_the_frozen_case_targets(self):
        self.assertEqual(validation_suite_v61.CASES[32], {"speed": 10.0, "cpu": 8.0})
        self.assertEqual(validation_suite_v61.CASES[128], {"speed": 25.0, "cpu": 20.0})
        self.assertEqual(validation_suite_v61.SAMPLES, 31)
        self.assertEqual(validation_suite_v61.WARMUPS, 5)

    def test_percentile_uses_the_frozen_ceiling_rank(self):
        values = list(range(1, 32))
        self.assertEqual(validation_suite_v61.percentile(values, 0.95), 30)

    def test_closed_validator_accepts_a_complete_report(self):
        validation_suite_v61.validate_report(self.valid_report())

    def test_closed_validator_refuses_unbound_results_and_receipts(self):
        report = self.valid_report()
        report["cases"][0]["result_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            validation_suite_v61.validate_report(report)
        report = self.valid_report()
        report["cases"][0]["receipts_valid"] = False
        with self.assertRaises(ValueError):
            validation_suite_v61.validate_report(report)


if __name__ == "__main__":
    unittest.main()
