import copy
import unittest

import validation_suite_v80 as production
import validation_suite_v82 as attribution
import validation_suite_v85 as equal_security


def measurement(
    arm: str,
    throughput: float,
    p95: int,
    client_cpu: int,
    stack_cpu: int,
    allocations: float,
    request_bytes: int | None,
) -> dict:
    operations = 160
    kinds = equal_security.REQUEST_BYTES_KINDS
    return {
        "arm": arm,
        "complete": True,
        "concurrency": 1,
        "logical_operations": operations,
        "logical_operations_per_second": throughput,
        "mean_allocations": allocations,
        "p95_request_ns": p95,
        "query_gate_passed": True,
        "total_client_cpu_ns": client_cpu * operations,
        "total_measured_stack_cpu_ns": stack_cpu * operations,
        "total_relevant_stack_cpu_ns": stack_cpu * operations,
        "workers": [
            {
                "request_application_bytes": request_bytes,
                "request_bytes_kind": kinds[arm],
                "result_bytes": 10_950,
                "result_sha256": "11" * 32,
                "worker": 0,
            }
        ],
    }


def passing_measurements() -> dict[str, dict]:
    return {
        "native": measurement("native", 100_000, 2_000, 90, 190, 2.0, None),
        "governed_native": measurement(
            "governed_native", 98_000, 2_050, 100, 200, 3.0, None
        ),
        "ndabi_v85": measurement(
            "ndabi_v85", 96_000, 2_100, 104, 208, 4.0, 480
        ),
        "postgrest_rpc": measurement(
            "postgrest_rpc", 50_000, 4_000, 250, 500, 20.0, 2_500
        ),
        "postgrest": measurement(
            "postgrest", 10_000, 20_000, 500, 1_000, 40.0, 5_000
        ),
    }


def component_report() -> dict:
    return {
        "schema": "ndabi-component-probe-v8.5",
        "operations": production.campaign.OPERATIONS,
        "rows": production.campaign.OPERATIONS
        * production.campaign.ROWS_PER_OPERATION,
        "result_bytes": 10_950,
        "result_sha256": "11" * 32,
        "warmups": 3,
        "samples": equal_security.COMPONENT_SAMPLES,
        "components": {
            key: {"wall_ns": 100, "cpu_ns": 90}
            for key in equal_security.COMPONENT_KEYS
        },
        "fixed_profiles": [
            {
                "result_bytes": result_bytes,
                "samples": equal_security.COMPONENT_SAMPLES,
                "components": {
                    key: {"wall_ns": 100, "cpu_ns": 90}
                    for key in equal_security.FIXED_COMPONENT_KEYS
                },
                "passed": True,
            }
            for result_bytes in equal_security.FIXED_RESULT_BYTES
        ],
        "passed": True,
    }


class SupabaseEqualSecurityCpuTests(unittest.TestCase):
    def tearDown(self):
        equal_security.restore_configuration_mutations()
        production.configure = attribution.BASE_CONFIGURE
        production.restore_legacy_campaign()

    def test_comparison_accepts_all_frozen_gates(self):
        result = equal_security.compare_measurements(passing_measurements(), 1)
        self.assertTrue(result["passed"])
        self.assertLessEqual(result["ndabi_p95_to_governed"], 1.03)
        self.assertGreaterEqual(result["ndabi_request_reduction_to_json"], 0.80)

    def test_comparison_refuses_each_equal_security_regression(self):
        fields = (
            ("p95_request_ns", 2_200),
            ("total_client_cpu_ns", 106 * 160),
            ("total_relevant_stack_cpu_ns", 211 * 160),
            ("mean_allocations", 4.1),
        )
        for field, value in fields:
            with self.subTest(field=field):
                measurements = passing_measurements()
                measurements["ndabi_v85"][field] = value
                self.assertFalse(
                    equal_security.compare_measurements(measurements, 1)["passed"]
                )

    def test_failed_gate_names_are_explicit(self):
        comparison = equal_security.compare_measurements(passing_measurements(), 1)
        self.assertEqual(equal_security.failed_performance_gates(comparison), [])
        comparison["ndabi_p95_to_governed"] = 1.04
        self.assertEqual(
            equal_security.failed_performance_gates(comparison),
            ["ndabi_p95_to_governed"],
        )

    def test_comparison_refuses_result_drift(self):
        measurements = copy.deepcopy(passing_measurements())
        measurements["governed_native"]["workers"][0]["result_sha256"] = "22" * 32
        self.assertFalse(
            equal_security.compare_measurements(measurements, 1)["passed"]
        )

    def test_configuration_freezes_both_connection_boundaries(self):
        equal_security.configure(build_binary=False, functional=True)
        self.assertEqual(equal_security.BOUNDARIES, ("direct", "supavisor"))
        self.assertEqual(production.campaign.ARMS, equal_security.ARMS)
        self.assertEqual(production.campaign.SECURITY_CHECK_COUNT, 24)
        self.assertEqual(
            production.campaign.MINIMUM_ARM_DURATION_NS,
            0,
        )
        self.assertIs(production.campaign.v72.security_checks, equal_security.security_checks)
        self.assertIs(production.campaign.run_process, equal_security.run_process)
        self.assertEqual(production.ENTRYPOINT.name, "validation_suite_v85.py")

    def test_relevant_cpu_excludes_an_unrelated_container(self):
        postgres = "ndabi-v85-postgres-1"
        measurement_value = measurement(
            "ndabi_v85", 96_000, 2_100, 104, 208, 4.0, 480
        )
        measurement_value["container_cpu_delta"] = {
            "containers": [
                {"Name": postgres, "UsageNS": 1_000},
                {"Name": "ndabi-v85-postgrest-1", "UsageNS": 9_000},
                {"Name": "ndabi-v85-supavisor-1", "UsageNS": 2_000},
            ]
        }
        equal_security.add_relevant_stack_cpu(
            measurement_value, postgres, "direct", "ndabi_v85"
        )
        self.assertEqual(measurement_value["relevant_container_cpu_ns"], 1_000)
        self.assertEqual(
            measurement_value["total_relevant_stack_cpu_ns"],
            measurement_value["total_client_cpu_ns"] + 1_000,
        )

    def test_formal_configuration_requires_five_second_arms(self):
        equal_security.configure(build_binary=False, functional=False)
        self.assertEqual(
            production.campaign.MINIMUM_ARM_DURATION_NS,
            equal_security.MINIMUM_ARM_DURATION_NS,
        )

    def test_formal_configuration_allows_the_frozen_rest_workload_to_finish(self):
        equal_security.configure(build_binary=False, functional=False)
        self.assertEqual(
            production.campaign.WORKER_TIMEOUT_SECONDS,
            equal_security.WORKER_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            equal_security.cumulative.worker_timeout_seconds(),
            equal_security.WORKER_TIMEOUT_SECONDS,
        )

    def test_component_report_refuses_missing_and_empty_intervals(self):
        report = component_report()
        equal_security.validate_component_report(report)
        missing = copy.deepcopy(report)
        missing["components"].pop("replay_admission")
        with self.assertRaisesRegex(ValueError, "component set changed"):
            equal_security.validate_component_report(missing)
        empty = copy.deepcopy(report)
        empty["components"]["database_execution"]["cpu_ns"] = 0
        with self.assertRaisesRegex(ValueError, "interval is invalid"):
            equal_security.validate_component_report(empty)

    def test_summary_retains_component_evidence(self):
        cases = []
        for boundary in equal_security.BOUNDARIES:
            for concurrency in production.campaign.CONCURRENCY_LEVELS:
                measurements = passing_measurements()
                for measurement_value in measurements.values():
                    measurement_value["concurrency"] = concurrency
                cases.append(
                    {
                        "boundary": boundary,
                        "concurrency": concurrency,
                        "comparison": equal_security.compare_measurements(
                            measurements, concurrency
                        ),
                        "measurements": measurements,
                        "passed": True,
                    }
                )
        processes = [
            {
                "cases": cases,
                "component_profiles": {
                    boundary: component_report()
                    for boundary in equal_security.BOUNDARIES
                },
                "process": 1,
            }
        ]
        summary = equal_security.campaign_summary(processes)
        self.assertEqual(len(summary), 6)
        self.assertEqual(
            set(summary[0]["component_cpu_ns_per_sample"]),
            equal_security.COMPONENT_KEYS,
        )
        self.assertEqual(
            set(summary[0]["fixed_component_cpu_ns_per_sample"]),
            {str(value) for value in equal_security.FIXED_RESULT_BYTES},
        )

    def test_repeatability_refuses_one_boundary_variation(self):
        processes = []
        for process in range(1, production.PROCESS_COUNT + 1):
            cases = []
            for boundary in equal_security.BOUNDARIES:
                for concurrency in production.campaign.CONCURRENCY_LEVELS:
                    comparison = {"ndabi_p95_to_governed": 1.0}
                    if process == production.PROCESS_COUNT and boundary == "supavisor":
                        comparison["ndabi_p95_to_governed"] = 1.11
                    cases.append(
                        {
                            "boundary": boundary,
                            "concurrency": concurrency,
                            "comparison": comparison,
                            "passed": True,
                        }
                    )
            processes.append({"process": process, "cases": cases})
        evidence, passed = equal_security.repeatability(processes)
        self.assertFalse(passed)
        self.assertEqual(sum(not item["passed"] for item in evidence), 3)


if __name__ == "__main__":
    unittest.main()
