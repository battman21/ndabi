import copy
import unittest

import validation_suite_v80 as production
import validation_suite_v82 as attribution
import validation_suite_v83 as cumulative


def cpu_snapshot(value: int) -> dict:
    return {
        "captured_unix_ns": 1,
        "containers": sorted(
            [
                {
                    "Name": f"stack-{name}-1",
                    "Source": "cgroup-v2-usage-usec",
                    "UsageNS": value,
                }
                for name in ("postgrest", "postgres", "supavisor")
            ],
            key=lambda item: item["Name"],
        ),
    }


def measurement(
    arm: str,
    throughput: float,
    p50: int,
    p95: int,
    client_cpu: int,
    container_cpu: int,
) -> dict:
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
        "total_client_cpu_ns": client_cpu * operations,
        "total_measured_stack_cpu_ns": (client_cpu + container_cpu) * operations,
        "workers": [
            {"result_bytes": 10_950, "result_sha256": "11" * 32, "worker": 0}
        ],
    }


def passing_measurements() -> dict[str, dict]:
    return {
        "native": measurement("native", 100_000, 1_000, 2_000, 100, 100),
        "ndabi_fixed": measurement(
            "ndabi_fixed", 98_000, 1_050, 2_100, 105, 100
        ),
        "ndabi": measurement("ndabi", 90_000, 1_100, 2_200, 120, 100),
        "postgrest_rpc": measurement(
            "postgrest_rpc", 50_000, 2_000, 3_000, 250, 250
        ),
        "postgrest": measurement("postgrest", 10_000, 10_000, 20_000, 500, 500),
    }


class SupabaseCumulativeCpuTests(unittest.TestCase):
    def tearDown(self):
        production.configure = attribution.BASE_CONFIGURE
        production.restore_legacy_campaign()

    def test_cgroup_v2_and_v1_counters_are_exact(self):
        self.assertEqual(
            cumulative.parse_cpu_usage("usage_usec 123\nuser_usec 80\n"),
            (123_000, "cgroup-v2-usage-usec"),
        )
        self.assertEqual(
            cumulative.parse_cpu_usage("456\n"),
            (456, "cgroup-v1-cpuacct-ns"),
        )
        with self.assertRaisesRegex(ValueError, "counter is invalid"):
            cumulative.parse_cpu_usage("usage_usec invalid")

    def test_container_delta_refuses_a_counter_reset(self):
        before = cpu_snapshot(1_000)
        after = cpu_snapshot(1_500)
        delta = cumulative.container_cpu_delta(before, after)
        self.assertEqual(delta["total_usage_ns"], 1_500)
        changed = copy.deepcopy(after)
        changed["containers"][0]["UsageNS"] = 999
        with self.assertRaisesRegex(ValueError, "moved backwards"):
            cumulative.container_cpu_delta(before, changed)

    def test_comparison_accepts_all_frozen_cpu_gates(self):
        result = cumulative.compare_measurements(passing_measurements(), 1)
        self.assertTrue(result["passed"])
        self.assertEqual(result["fixed_client_cpu_to_legacy"], 0.875)
        self.assertEqual(result["ndabi_stack_cpu_to_native"], 1.025)
        self.assertEqual(result["ndabi_stack_cpu_to_postgrest_rpc"], 0.41)

    def test_comparison_refuses_each_new_cpu_regression(self):
        measurements = passing_measurements()
        measurements["ndabi_fixed"]["total_client_cpu_ns"] = 111 * 160
        self.assertFalse(cumulative.compare_measurements(measurements, 1)["passed"])

        measurements = passing_measurements()
        measurements["ndabi_fixed"]["total_measured_stack_cpu_ns"] = 221 * 160
        self.assertFalse(cumulative.compare_measurements(measurements, 1)["passed"])

        measurements = passing_measurements()
        measurements["postgrest_rpc"]["total_measured_stack_cpu_ns"] = 300 * 160
        self.assertFalse(cumulative.compare_measurements(measurements, 1)["passed"])

    def test_comparison_refuses_result_drift(self):
        measurements = copy.deepcopy(passing_measurements())
        measurements["ndabi_fixed"]["workers"][0]["result_sha256"] = "22" * 32
        result = cumulative.compare_measurements(measurements, 1)
        self.assertFalse(result["canonical_results_equal"])
        self.assertFalse(result["passed"])

    def test_functional_mode_cannot_claim_performance(self):
        previous = production.ENFORCE_PERFORMANCE
        try:
            production.ENFORCE_PERFORMANCE = False
            measurements = passing_measurements()
            measurements["ndabi_fixed"]["total_measured_stack_cpu_ns"] = 1_000 * 160
            result = cumulative.compare_measurements(measurements, 1)
            self.assertTrue(result["passed"])
            self.assertFalse(result["performance_gates_passed"])
        finally:
            production.ENFORCE_PERFORMANCE = previous

    def test_configuration_freezes_the_v83_identity_and_runner(self):
        cumulative.configure(build_binary=False, functional=True)
        self.assertEqual(production.campaign.ARMS, cumulative.ARMS)
        self.assertEqual(production.campaign.SECURITY_CHECK_COUNT, 17)
        self.assertIs(production.campaign.run_process, cumulative.run_process)
        self.assertEqual(production.ENTRYPOINT.name, "validation_suite_v83.py")
        self.assertIn("validation_suite_v83.py", production.campaign.SOURCE_PATHS)
        self.assertEqual(
            production.campaign.SMOKE_RESULT_PATH.name,
            "functional-latest.json",
        )


if __name__ == "__main__":
    unittest.main()
