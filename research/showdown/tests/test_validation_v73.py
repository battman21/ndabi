import copy
import gzip
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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
    def test_process_evidence_is_deterministic_compressed_and_exact(self):
        value = {"raw_ns": [1_000] * 20_000, "passed": True}
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.json.gz"
            second = Path(temporary) / "second.json.gz"
            campaign.write_process_evidence(first, value)
            campaign.write_process_evidence(second, value)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(campaign.read_process_evidence(first), value)
            uncompressed = len((json.dumps(value) + "\n").encode("utf-8"))
            self.assertLess(first.stat().st_size, uncompressed * 0.25)

    def test_process_evidence_refuses_a_decompression_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "process.json.gz"
            path.write_bytes(gzip.compress(b"{}"))
            with patch.object(campaign, "MAX_DECOMPRESSED_PROCESS_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "decompressed"):
                    campaign.read_process_evidence(path)

    def test_disk_gate_refuses_insufficient_capacity(self):
        with patch.object(
            campaign.shutil,
            "disk_usage",
            return_value=SimpleNamespace(free=99),
        ):
            with self.assertRaisesRegex(RuntimeError, "free disk"):
                campaign.require_free_disk(Path.cwd(), minimum_bytes=100)

    def test_worker_diagnostics_are_bounded_and_redact_connection_material(self):
        connection = "host=127.0.0.1 password=private dbname=ndabi"
        report = campaign.redacted_worker_stream(
            "x" * 5_000 + connection,
            (connection,),
        )
        self.assertNotIn("private", report["excerpt"])
        self.assertIn("[redacted]", report["excerpt"])
        self.assertTrue(report["truncated"])
        self.assertEqual(len(report["sha256"]), 64)

    def test_timeout_diagnostics_terminate_and_capture_every_worker(self):
        class Process:
            returncode = None

            def __init__(self):
                self.terminated = False

            def poll(self):
                return self.returncode

            def terminate(self):
                self.terminated = True
                self.returncode = -15

            def communicate(self, timeout):
                self.assert_timeout = timeout
                return "ready", "password=private"

        processes = [Process(), Process()]
        diagnostics = campaign.terminate_worker_diagnostics(processes, ("private",))
        self.assertTrue(all(process.terminated for process in processes))
        self.assertEqual(len(diagnostics), 2)
        self.assertTrue(
            all("private" not in item["stderr"]["excerpt"] for item in diagnostics)
        )

    def test_worker_connection_is_absent_from_process_arguments(self):
        connection = "host=127.0.0.1 password=private dbname=ndabi"
        argument, environment = campaign.worker_connection_transport(connection)
        self.assertNotIn(connection, argument)
        self.assertEqual(argument, f"env:{campaign.WORKER_CONNECTION_ENV}")
        self.assertEqual(environment[campaign.WORKER_CONNECTION_ENV], connection)

    def test_worker_startup_retry_accepts_only_a_later_clean_attempt(self):
        attempts = []

        def run(attempt):
            attempts.append(attempt)
            if attempt < 3:
                raise campaign.WorkerStartupFailure(
                    "worker-exited-before-release",
                    [{"worker": 0, "exit_code": 1}],
                )
            return {"complete": True}

        result, discarded = campaign.run_with_worker_startup_retries(run)
        self.assertEqual(result, {"complete": True})
        self.assertEqual(attempts, [1, 2, 3])
        self.assertEqual(len(discarded), 2)

    def test_worker_startup_retry_refuses_the_third_failure(self):
        def run(_attempt):
            raise campaign.WorkerStartupFailure(
                "worker-readiness-timeout",
                [],
            )

        with self.assertRaisesRegex(RuntimeError, "worker_startup_failures"):
            campaign.run_with_worker_startup_retries(run)

    def test_worker_startup_retry_does_not_hide_another_failure(self):
        attempts = []

        def run(attempt):
            attempts.append(attempt)
            raise ValueError("result changed")

        with self.assertRaisesRegex(ValueError, "result changed"):
            campaign.run_with_worker_startup_retries(run)
        self.assertEqual(attempts, [1])

    def test_container_cleanup_removes_anonymous_volumes(self):
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(campaign, "command", return_value=completed) as command:
            campaign.remove_container("campaign-postgres")
        command.assert_called_once_with(
            "docker",
            "rm",
            "--force",
            "--volumes",
            "campaign-postgres",
            check=False,
        )

    def test_container_cleanup_refuses_a_docker_failure(self):
        completed = subprocess.CompletedProcess([], 1, "", "daemon unavailable")
        with patch.object(campaign, "command", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "could not remove"):
                campaign.remove_container("campaign-postgres")

    def test_campaign_cleanup_attempts_every_target_before_refusal(self):
        network_result = subprocess.CompletedProcess([], 0, "", "")
        with (
            patch.object(
                campaign,
                "remove_container",
                side_effect=[RuntimeError("first failed"), None, None],
            ) as remove,
            patch.object(campaign, "command", return_value=network_result) as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "first failed"):
                campaign.cleanup_campaign(("first", "second", "third"), "network")
        self.assertEqual(
            [call.args[0] for call in remove.call_args_list],
            ["first", "second", "third"],
        )
        command.assert_called_once_with(
            "docker", "network", "rm", "network", check=False
        )

    def test_campaign_shape_is_frozen(self):
        self.assertEqual(campaign.PROCESS_COUNT, 5)
        self.assertEqual(campaign.CONCURRENCY_LEVELS, (1, 8, 32))
        self.assertEqual(campaign.OPERATIONS, 16)
        self.assertEqual(campaign.SAMPLES, 31)
        self.assertEqual(campaign.POOL_SIZE, 64)

    def test_source_custody_covers_the_worker_and_contract(self):
        paths = set(campaign.SOURCE_PATHS)
        self.assertIn("../../.cargo/config.toml", paths)
        self.assertIn("src/bin/ndabi_v71.rs", paths)
        self.assertIn("validation_suite_v73.py", paths)
        self.assertIn(
            "../../specs/ndabi_supavisor_concurrency_campaign_v7_3.md", paths
        )

    def test_binary_uses_the_shared_repository_target(self):
        self.assertEqual(
            campaign.BINARY,
            campaign.repository_root() / "target" / "release" / "ndabi_v71",
        )

    def test_source_path_resolves_standalone_repository_crates(self):
        path = campaign.source_path("crates/ndabi-protocol/Cargo.toml")
        self.assertEqual(path, campaign.repository_root() / "crates/ndabi-protocol/Cargo.toml")

    def test_source_path_refuses_a_missing_registered_file(self):
        with self.assertRaisesRegex(FileNotFoundError, "registered source file"):
            campaign.source_path("crates/does-not-exist/Cargo.toml")

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
