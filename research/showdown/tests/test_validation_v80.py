import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import validation_suite_v80 as production


def measurement(arm: str, throughput: float, p50: int, p95: int, cpu_per_operation: float) -> dict:
    operations = 160
    return {
        "arm": arm,
        "complete": True,
        "concurrency": 1,
        "logical_operations": operations,
        "logical_operations_per_second": throughput,
        "p50_request_ns": p50,
        "p95_request_ns": p95,
        "query_gate_passed": True,
        "total_client_cpu_ns": int(cpu_per_operation * operations),
        "workers": [
            {
                "result_bytes": 10_950,
                "result_sha256": "11" * 32,
                "worker": 0,
            }
        ],
    }


def passing_measurements() -> dict[str, dict]:
    return {
        "native": measurement("native", 100_000, 1_000, 2_000, 100),
        "ndabi": measurement("ndabi", 90_000, 1_100, 2_100, 120),
        "postgrest_rpc": measurement("postgrest_rpc", 50_000, 2_000, 3_000, 400),
        "postgrest": measurement("postgrest", 10_000, 10_000, 20_000, 1_000),
    }


class SupabaseProductionCampaignTests(unittest.TestCase):
    def test_contract_has_four_attribution_arms(self):
        self.assertEqual(
            production.ARMS,
            ("native", "ndabi", "postgrest_rpc", "postgrest"),
        )
        self.assertEqual(production.PROCESS_COUNT, 5)
        self.assertEqual(production.MINIMUM_ARM_DURATION_NS, 2_000_000_000)
        self.assertEqual(production.QUERY_MULTIPLIERS["postgrest"], 16)
        self.assertEqual(production.QUERY_MULTIPLIERS["postgrest_rpc"], 1)

    def test_latin_rotation_changes_the_first_arm(self):
        orders = [production.arm_order(process, 0) for process in range(1, 5)]
        self.assertEqual({order[0] for order in orders}, set(production.ARMS))
        self.assertTrue(all(set(order) == set(production.ARMS) for order in orders))

    def test_comparison_accepts_fast_exact_ndabi(self):
        result = production.compare_measurements(passing_measurements(), 1)
        self.assertTrue(result["passed"])
        self.assertEqual(result["ndabi_throughput_over_native"], 0.9)
        self.assertEqual(result["ndabi_throughput_over_postgrest"], 9.0)

    def test_comparison_refuses_result_drift(self):
        measurements = passing_measurements()
        measurements = copy.deepcopy(measurements)
        measurements["postgrest_rpc"]["workers"][0]["result_sha256"] = "22" * 32
        result = production.compare_measurements(measurements, 1)
        self.assertFalse(result["canonical_results_equal"])
        self.assertFalse(result["passed"])

    def test_comparison_refuses_native_distance_and_query_drift(self):
        measurements = passing_measurements()
        measurements["ndabi"]["p50_request_ns"] = 1_201
        self.assertFalse(production.compare_measurements(measurements, 1)["passed"])
        measurements = passing_measurements()
        measurements["native"]["query_gate_passed"] = False
        self.assertFalse(production.compare_measurements(measurements, 1)["passed"])

    def test_functional_mode_cannot_enforce_or_claim_performance(self):
        previous = production.ENFORCE_PERFORMANCE
        try:
            production.ENFORCE_PERFORMANCE = False
            measurements = passing_measurements()
            measurements["ndabi"]["logical_operations_per_second"] = 1
            result = production.compare_measurements(measurements, 1)
            self.assertTrue(result["passed"])
            self.assertFalse(result["performance_gates_enforced"])
            self.assertFalse(result["performance_gates_passed"])
        finally:
            production.ENFORCE_PERFORMANCE = previous

    def test_functional_configuration_is_explicit_and_reversible(self):
        try:
            production.configure(functional=True)
            self.assertEqual(production.campaign.MEASUREMENT_MODE, "functional-only")
            self.assertFalse(production.campaign.PERFORMANCE_GATES_ENFORCED)
            self.assertFalse(production.campaign.REQUIRE_QUIET_HOST)
            self.assertEqual(
                production.campaign.SAMPLES_BY_ARM,
                production.FUNCTIONAL_SAMPLES_BY_ARM,
            )
        finally:
            production.restore_legacy_campaign()
        self.assertEqual(production.campaign.MEASUREMENT_MODE, "performance")
        self.assertTrue(production.campaign.PERFORMANCE_GATES_ENFORCED)

    def test_source_custody_includes_the_production_contract(self):
        paths = set(production.SOURCE_PATHS)
        self.assertIn("validation_suite_v80.py", paths)
        self.assertIn("evidence_manifest_v80.py", paths)
        self.assertIn(
            "../../specs/ndabi_supabase_production_campaign_v8_0.md", paths
        )

    def test_cross_stack_repeatability_requires_three_complete_stacks(self):
        def process(identifier: int) -> dict:
            return {
                "process": identifier,
                "cases": [
                    {
                        "comparison": {
                            "ndabi_p95_to_native": 1.05,
                            "ndabi_throughput_over_native": 0.95,
                        },
                        "concurrency": concurrency,
                    }
                    for concurrency in production.campaign.CONCURRENCY_LEVELS
                ],
            }

        stacks = [
            [process(identifier) for identifier in range(1, 6)] for _ in range(3)
        ]
        evidence, passed = production.cross_stack_repeatability(stacks)
        self.assertTrue(passed)
        self.assertTrue(all(item["passed"] for item in evidence))
        with self.assertRaisesRegex(ValueError, "cold-stack count"):
            production.cross_stack_repeatability(stacks[:2])

    def test_summary_exposes_the_native_cpu_and_p50_gates(self):
        processes = []
        for process in range(1, production.PROCESS_COUNT + 1):
            cases = []
            for concurrency in production.campaign.CONCURRENCY_LEVELS:
                measurements = passing_measurements()
                for value in measurements.values():
                    value["concurrency"] = concurrency
                    value["workers"] = [
                        {
                            "result_bytes": 10_950,
                            "result_sha256": "11" * 32,
                            "worker": worker,
                        }
                        for worker in range(concurrency)
                    ]
                comparison = production.compare_measurements(measurements, concurrency)
                cases.append(
                    {
                        "comparison": comparison,
                        "concurrency": concurrency,
                        "measurements": measurements,
                        "passed": comparison["passed"],
                    }
                )
            processes.append({"cases": cases, "process": process})
        summary = production.campaign_summary(processes)
        self.assertTrue(all(item["all_repetitions_passed"] for item in summary))
        self.assertEqual(summary[0]["median_ndabi_cpu_to_native"], 1.2)
        self.assertEqual(summary[0]["median_ndabi_p50_to_native"], 1.1)

    def test_stack_shard_root_cannot_escape_the_result_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary) / "outside"
            with self.assertRaisesRegex(SystemExit, "outside"):
                production._validate_shard_root(str(outside))

    def test_stack_shard_preserves_a_structured_validation_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "stack"
            with mock.patch.object(
                production.campaign,
                "main",
                side_effect=ValueError("controlled validation failure"),
            ):
                self.assertEqual(production.run_stack_shard(root), 1)
            failure = json.loads(
                (root / "shard-failure.json").read_text(encoding="utf-8")
            )
            self.assertEqual(failure["error_type"], "ValueError")
            self.assertEqual(failure["error"], "controlled validation failure")

    def test_container_resource_snapshot_requires_the_complete_stack(self):
        names = (
            "ndabi-v80-postgres-123",
            "ndabi-v80-postgrest-123",
            "ndabi-v80-supavisor-123",
        )
        records = [
            {
                "BlockIO": "0B / 0B",
                "CPUPerc": "0.10%",
                "MemUsage": "10MiB / 1GiB",
                "Name": name,
                "NetIO": "1kB / 1kB",
                "PIDs": "10",
            }
            for name in reversed(names)
        ]
        output = "\n".join(json.dumps(record) for record in records)
        with mock.patch.object(
            production.campaign,
            "command",
            return_value=SimpleNamespace(returncode=0, stdout=output),
        ):
            snapshot = production.container_resource_snapshot(names[0])
        production.validate_container_resource_snapshot(snapshot)
        self.assertEqual(
            [record["Name"] for record in snapshot["containers"]],
            sorted(names),
        )

    def test_request_byte_evidence_marks_native_wire_size_unavailable(self):
        native = {
            "workers": [
                {
                    "request_application_bytes": None,
                    "request_bytes_kind": "unavailable-postgresql-driver-wire",
                }
            ]
        }
        production.validate_request_byte_evidence(native, "native")
        native["workers"][0]["request_application_bytes"] = 1
        with self.assertRaisesRegex(ValueError, "must remain unavailable"):
            production.validate_request_byte_evidence(native, "native")


if __name__ == "__main__":
    unittest.main()
