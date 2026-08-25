import copy
import json
import unittest
from types import SimpleNamespace
from unittest import mock

import validation_suite_v80 as production
import validation_suite_v82 as attribution


def measurement(arm: str, throughput: float, p50: int, p95: int, cpu: float) -> dict:
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
        "total_client_cpu_ns": int(cpu * operations),
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
        "ndabi_incremental": measurement(
            "ndabi_incremental", 95_000, 1_050, 2_100, 105
        ),
        "ndabi_incremental_server": measurement(
            "ndabi_incremental_server", 100_000, 1_000, 2_000, 100
        ),
        "ndabi": measurement("ndabi", 90_000, 1_100, 2_200, 120),
        "postgrest_rpc": measurement("postgrest_rpc", 50_000, 2_000, 3_000, 400),
        "postgrest": measurement("postgrest", 10_000, 10_000, 20_000, 1_000),
    }


class SupabaseCpuAttributionTests(unittest.TestCase):
    def tearDown(self):
        production.configure = attribution.BASE_CONFIGURE
        production.restore_legacy_campaign()

    def test_contract_has_two_incremental_attribution_arms(self):
        self.assertEqual(len(attribution.ARMS), 6)
        self.assertIn("ndabi_incremental", attribution.ARMS)
        self.assertIn("ndabi_incremental_server", attribution.ARMS)
        self.assertEqual(attribution.SECURITY_CHECK_COUNT, 23)

    def test_comparison_accepts_a_material_cpu_reduction(self):
        result = attribution.compare_measurements(passing_measurements(), 1)
        self.assertTrue(result["passed"])
        self.assertEqual(result["ndabi_cpu_to_native"], 1.05)
        self.assertEqual(result["ndabi_incremental_server_cpu_to_native"], 1.0)
        self.assertEqual(result["incremental_cpu_to_legacy"], 0.875)

    def test_comparison_refuses_each_cpu_regression(self):
        measurements = passing_measurements()
        measurements["ndabi_incremental"]["total_client_cpu_ns"] = 126 * 160
        self.assertFalse(attribution.compare_measurements(measurements, 1)["passed"])

        measurements = passing_measurements()
        measurements["ndabi_incremental_server"]["total_client_cpu_ns"] = 111 * 160
        self.assertFalse(attribution.compare_measurements(measurements, 1)["passed"])

        measurements = passing_measurements()
        measurements["ndabi"]["total_client_cpu_ns"] = 110 * 160
        self.assertFalse(attribution.compare_measurements(measurements, 1)["passed"])

    def test_comparison_refuses_any_result_drift(self):
        measurements = copy.deepcopy(passing_measurements())
        measurements["ndabi_incremental_server"]["workers"][0]["result_sha256"] = "22" * 32
        result = attribution.compare_measurements(measurements, 1)
        self.assertFalse(result["canonical_results_equal"])
        self.assertFalse(result["passed"])

    def test_functional_mode_cannot_claim_performance(self):
        previous = production.ENFORCE_PERFORMANCE
        try:
            production.ENFORCE_PERFORMANCE = False
            measurements = passing_measurements()
            measurements["ndabi_incremental"]["total_client_cpu_ns"] = 1_000 * 160
            result = attribution.compare_measurements(measurements, 1)
            self.assertTrue(result["passed"])
            self.assertFalse(result["performance_gates_passed"])
        finally:
            production.ENFORCE_PERFORMANCE = previous

    def test_configuration_freezes_the_v82_identity_and_sources(self):
        attribution.configure(build_binary=False, functional=True)
        self.assertEqual(production.campaign.ARMS, attribution.ARMS)
        self.assertEqual(
            production.campaign.SECURITY_CHECK_COUNT,
            attribution.SECURITY_CHECK_COUNT,
        )
        self.assertEqual(production.ENTRYPOINT.name, "validation_suite_v82.py")
        self.assertIn("validation_suite_v82.py", production.campaign.SOURCE_PATHS)
        self.assertEqual(
            production.campaign.SMOKE_RESULT_PATH.name,
            "functional-latest.json",
        )

    def test_incremental_security_probe_adds_six_checks(self):
        report = {
            "changed_frame_refused": True,
            "changed_result_refused": True,
            "invalid_receipt_refused": True,
            "replay_refused_before_query": True,
            "valid_result_accepted": True,
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(report),
        )
        token_paths = {"valid": attribution.ROOT / "valid.jwt"}
        base = {f"base-{index}": True for index in range(17)}
        with mock.patch.object(attribution, "BASE_SECURITY_CHECKS", return_value=base), mock.patch.object(
            production.campaign, "command", return_value=completed
        ):
            security = attribution.security_checks(
                "connection",
                "endpoint",
                token_paths,
                attribution.ROOT / "public.pem",
                "token",
            )
        self.assertEqual(len(security), 23)
        self.assertTrue(all(security.values()))


if __name__ == "__main__":
    unittest.main()
