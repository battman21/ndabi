#!/usr/bin/env python3
"""Run the fixed-buffer and cumulative-CPU Supabase campaign."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import subprocess
import threading
import time
from pathlib import Path

import validation_suite_v80 as production
import validation_suite_v82 as attribution


ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "results" / "v83"
CAMPAIGN_NAME = "NDABI Supabase cumulative CPU stack v8.3"
CAMPAIGN_LABEL = "v8.3 stack"
FORMAL_CAMPAIGN_NAME = "NDABI Supabase cumulative CPU campaign v8.3"
CAMPAIGN_VERSION = "v8.3"
TENANT_ID = "ndabi-v83"
SESSION_PROOF_LABEL = "ndabi-v83-session-proof"
SESSION_PROOF_EXPECTED = "83"
ARMS = ("native", "ndabi_fixed", "ndabi", "postgrest_rpc", "postgrest")
ARM_IDENTIFIERS = {
    "native": "native-indexed-batch-session",
    "ndabi_fixed": "ndabi-fixed-buffer-session",
    "ndabi": "ndabi-indexed-batch-session",
    "postgrest_rpc": "postgrest-rpc-user-jwt",
    "postgrest": "postgrest-user-jwt",
}
QUERY_MULTIPLIERS = {
    "native": 1,
    "ndabi_fixed": 1,
    "ndabi": 1,
    "postgrest_rpc": 1,
    "postgrest": production.campaign.OPERATIONS,
}
SAMPLES_BY_ARM = {
    "native": 8_191,
    "ndabi_fixed": 8_191,
    "ndabi": 8_191,
    "postgrest_rpc": 2_047,
    "postgrest": 255,
}
FUNCTIONAL_SAMPLES_BY_ARM = {arm: 3 for arm in ARMS}
REQUEST_BYTES_KINDS = {
    "native": "unavailable-postgresql-driver-wire",
    "ndabi_fixed": "exact-ndabi-frame",
    "ndabi": "exact-ndabi-frame",
    "postgrest_rpc": "exact-json-body",
    "postgrest": "calculated-http-lower-bound",
}
WORKER_SCHEMA = "ndabi-supavisor-load-worker-v8.3"
SECURITY_CHECK_COUNT = 17
SOURCE_PATHS = attribution.SOURCE_PATHS + (
    "validation_suite_v83.py",
    "requirements-v83.txt",
    "tests/test_validation_v83.py",
    "../../specs/ndabi_supabase_cumulative_cpu_campaign_v8_3.md",
)
BASE_CONFIGURE = attribution.configure
BASE_SECURITY_CHECKS = production.LEGACY_SECURITY_CHECKS


def ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else math.inf


def parse_cpu_usage(output: str) -> tuple[int, str]:
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "usage_usec" and fields[1].isdigit():
            return int(fields[1]) * 1_000, "cgroup-v2-usage-usec"
    stripped = output.strip()
    if stripped.isdigit():
        return int(stripped), "cgroup-v1-cpuacct-ns"
    raise ValueError("the container CPU counter is invalid")


def container_cpu_snapshot(postgres: str) -> dict:
    records = []
    for name in production.container_names(postgres):
        completed = production.campaign.command(
            "docker",
            "exec",
            name,
            "cat",
            "/sys/fs/cgroup/cpu.stat",
            check=False,
        )
        if completed.returncode != 0:
            completed = production.campaign.command(
                "docker",
                "exec",
                name,
                "cat",
                "/sys/fs/cgroup/cpuacct/cpuacct.usage",
                check=False,
            )
        production.require(completed.returncode == 0, "the container CPU probe failed")
        usage_ns, source = parse_cpu_usage(completed.stdout)
        records.append({"Name": name, "Source": source, "UsageNS": usage_ns})
    records.sort(key=lambda item: item["Name"])
    return {"captured_unix_ns": time.time_ns(), "containers": records}


def validate_container_cpu_snapshot(value: object) -> None:
    production.require(isinstance(value, dict), "the container CPU snapshot is absent")
    production.require(
        isinstance(value.get("captured_unix_ns"), int)
        and value["captured_unix_ns"] > 0,
        "the container CPU timestamp is invalid",
    )
    records = value.get("containers")
    production.require(
        isinstance(records, list) and len(records) == 3,
        "the container CPU set is invalid",
    )
    names = []
    for record in records:
        production.require(
            isinstance(record, dict)
            and set(record) == {"Name", "Source", "UsageNS"},
            "the container CPU record changed",
        )
        production.require(
            isinstance(record["Name"], str)
            and record["Name"]
            and record["Source"]
            in {"cgroup-v1-cpuacct-ns", "cgroup-v2-usage-usec"}
            and isinstance(record["UsageNS"], int)
            and record["UsageNS"] >= 0,
            "the container CPU record is invalid",
        )
        names.append(record["Name"])
    production.require(names == sorted(set(names)), "the container CPU names changed")


def container_cpu_delta(before: dict, after: dict) -> dict:
    validate_container_cpu_snapshot(before)
    validate_container_cpu_snapshot(after)
    before_records = {record["Name"]: record for record in before["containers"]}
    after_records = {record["Name"]: record for record in after["containers"]}
    production.require(
        set(before_records) == set(after_records),
        "the container CPU set changed during the arm",
    )
    records = []
    for name in sorted(before_records):
        first = before_records[name]
        last = after_records[name]
        production.require(first["Source"] == last["Source"], "the CPU source changed")
        production.require(
            last["UsageNS"] >= first["UsageNS"],
            "a container CPU counter moved backwards",
        )
        records.append(
            {
                "Name": name,
                "Source": first["Source"],
                "UsageNS": last["UsageNS"] - first["UsageNS"],
            }
        )
    total = sum(record["UsageNS"] for record in records)
    production.require(total > 0, "the measured container CPU total is empty")
    return {"containers": records, "total_usage_ns": total}


def run_load_arm_attributed(
    arm: str,
    concurrency: int,
    connection: str,
    endpoint: str,
    token_path: Path,
    public_key: Path,
    custody: Path,
    postgres: str,
) -> dict:
    campaign = production.campaign
    samples = campaign.samples_for(arm)
    ready_paths = [
        custody / f"{arm}-{concurrency}-{worker}.ready" for worker in range(concurrency)
    ]
    release_path = custody / f"{arm}-{concurrency}.release"
    processes: list[subprocess.Popen] = []
    monitor_stop = threading.Event()
    monitored_build_processes: set[str] = set()
    build_monitor_errors: list[str] = []
    cpu_before = None
    cpu_after = None

    def monitor_build_processes() -> None:
        while not monitor_stop.wait(campaign.BUILD_MONITOR_INTERVAL_SECONDS):
            try:
                monitored_build_processes.update(campaign.active_build_processes())
            except RuntimeError as error:
                build_monitor_errors.append(str(error))
                return

    monitor = None
    if campaign.MONITOR_BUILD_PROCESSES_DURING_ARM:
        monitor = threading.Thread(target=monitor_build_processes, daemon=True)
        monitor.start()
    try:
        for worker, ready_path in enumerate(ready_paths):
            start = 1_000 + worker * 3_000
            arguments = [
                str(campaign.BINARY),
                "--load-worker",
                arm,
                connection,
                endpoint,
                str(token_path),
                str(public_key),
                campaign.v72.v71.KEY_ID,
                campaign.v72.v71.ISSUER,
                campaign.v72.v71.AUDIENCE,
                str(start),
                str(campaign.OPERATIONS),
                str(samples),
                str(worker),
                str(ready_path),
                str(release_path),
                WORKER_SCHEMA,
            ]
            processes.append(
                subprocess.Popen(
                    arguments,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        ready_started = time.monotonic()
        while not all(path.is_file() for path in ready_paths):
            failed = [process.returncode for process in processes if process.poll() is not None]
            if failed:
                raise RuntimeError(f"a load worker exited before release: {failed}")
            if time.monotonic() - ready_started > 90:
                raise RuntimeError("the load workers did not become ready")
            time.sleep(0.002)
        cpu_before = container_cpu_snapshot(postgres)
        with release_path.open("x", encoding="utf-8"):
            pass
        reports = []
        errors = []
        for worker, process in enumerate(processes):
            try:
                stdout, stderr = process.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
                errors.append({"worker": worker, "error": "timeout"})
                continue
            if process.returncode != 0:
                errors.append(
                    {
                        "worker": worker,
                        "exit_code": process.returncode,
                        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                    }
                )
                continue
            try:
                report = json.loads(stdout)
                campaign.validate_worker(report, arm, worker)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
                errors.append({"worker": worker, "error": str(error)})
                continue
            reports.append(report)
        cpu_after = container_cpu_snapshot(postgres)
    finally:
        campaign.stop_workers(processes)
        if monitor is not None:
            try:
                monitored_build_processes.update(campaign.active_build_processes())
            except RuntimeError as error:
                build_monitor_errors.append(str(error))
            monitor_stop.set()
            monitor.join(timeout=2)
            if monitor.is_alive():
                build_monitor_errors.append("the build-process monitor did not stop")
    production.require(cpu_before is not None and cpu_after is not None, "CPU evidence is absent")
    cpu_delta = container_cpu_delta(cpu_before, cpu_after)
    raw_ns = [value for report in reports for value in report["raw_ns"]]
    complete = len(reports) == concurrency and not errors
    total_elapsed_ns = 0
    if reports:
        total_elapsed_ns = max(
            report["measured_end_monotonic_ns"] for report in reports
        ) - min(report["measured_start_monotonic_ns"] for report in reports)
    logical_operations = sum(report["logical_operations"] for report in reports)
    throughput = (
        logical_operations * 1_000_000_000 / total_elapsed_ns
        if total_elapsed_ns
        else 0.0
    )
    total_client_cpu_ns = sum(report["total_cpu_ns"] for report in reports)
    return {
        "active_build_processes_during_arm": sorted(monitored_build_processes),
        "arm": arm,
        "build_monitor_errors": build_monitor_errors,
        "completed_requests": len(raw_ns),
        "completed_workers": len(reports),
        "complete": complete,
        "concurrency": concurrency,
        "container_cpu_after": cpu_after,
        "container_cpu_before": cpu_before,
        "container_cpu_delta": cpu_delta,
        "errors": errors,
        "logical_operations": logical_operations,
        "logical_operations_per_second": throughput,
        "mean_allocated_bytes": statistics.mean(
            [report["mean_allocated_bytes"] for report in reports]
        )
        if reports
        else 0.0,
        "mean_allocations": statistics.mean(
            [report["mean_allocations"] for report in reports]
        )
        if reports
        else 0.0,
        "p50_request_ns": campaign.percentile(raw_ns, 50) if raw_ns else 0,
        "p95_request_ns": campaign.percentile(raw_ns, 95) if raw_ns else 0,
        "p99_request_ns": campaign.percentile(raw_ns, 99) if raw_ns else 0,
        "peak_additional_live_bytes": max(
            (report["peak_additional_live_bytes"] for report in reports), default=0
        ),
        "total_client_cpu_ns": total_client_cpu_ns,
        "total_elapsed_ns": total_elapsed_ns,
        "total_measured_stack_cpu_ns": total_client_cpu_ns + cpu_delta["total_usage_ns"],
        "workers": reports,
    }


def cpu_per_operation(measurement: dict, field: str) -> float:
    operations = measurement["logical_operations"]
    return measurement[field] / operations if operations else math.inf


def compare_measurements(measurements: dict[str, dict], concurrency: int) -> dict:
    production.require(set(measurements) == set(ARMS), "the comparison arms changed")
    production.require(
        all(item["concurrency"] == concurrency for item in measurements.values()),
        "the comparison concurrency changed",
    )
    identities = [production._identity(measurements[arm]) for arm in ARMS]
    exact = all(identity == identities[0] for identity in identities[1:])
    exact &= len(identities[0]) == concurrency
    native = measurements["native"]
    fixed = measurements["ndabi_fixed"]
    legacy = measurements["ndabi"]
    rpc = measurements["postgrest_rpc"]
    repeated = measurements["postgrest"]
    fixed_client_cpu = cpu_per_operation(fixed, "total_client_cpu_ns")
    native_client_cpu = cpu_per_operation(native, "total_client_cpu_ns")
    legacy_client_cpu = cpu_per_operation(legacy, "total_client_cpu_ns")
    fixed_stack_cpu = cpu_per_operation(fixed, "total_measured_stack_cpu_ns")
    native_stack_cpu = cpu_per_operation(native, "total_measured_stack_cpu_ns")
    rpc_stack_cpu = cpu_per_operation(rpc, "total_measured_stack_cpu_ns")
    repeated_stack_cpu = cpu_per_operation(repeated, "total_measured_stack_cpu_ns")
    throughput_native = ratio(
        fixed["logical_operations_per_second"], native["logical_operations_per_second"]
    )
    p50_native = ratio(fixed["p50_request_ns"], native["p50_request_ns"])
    p95_native = ratio(fixed["p95_request_ns"], native["p95_request_ns"])
    client_cpu_native = ratio(fixed_client_cpu, native_client_cpu)
    client_cpu_legacy = ratio(fixed_client_cpu, legacy_client_cpu)
    stack_cpu_native = ratio(fixed_stack_cpu, native_stack_cpu)
    stack_cpu_rpc = ratio(fixed_stack_cpu, rpc_stack_cpu)
    stack_cpu_repeated = ratio(fixed_stack_cpu, repeated_stack_cpu)
    performance = (
        throughput_native >= 0.95
        and p50_native <= 1.15
        and client_cpu_native <= 1.10
        and client_cpu_legacy <= 0.95
        and stack_cpu_native <= 1.10
        and stack_cpu_rpc <= 0.60
        and stack_cpu_repeated <= 0.60
        and fixed["p95_request_ns"] <= 25_000_000
    )
    passed = (
        all(measurement["complete"] for measurement in measurements.values())
        and all(measurement["query_gate_passed"] for measurement in measurements.values())
        and exact
        and (performance or not production.ENFORCE_PERFORMANCE)
    )
    return {
        "canonical_results_equal": exact,
        "concurrency": concurrency,
        "fixed_client_cpu_to_legacy": client_cpu_legacy,
        "fixed_client_cpu_to_legacy_limit": 0.95,
        "ndabi_client_cpu_to_native": client_cpu_native,
        "ndabi_client_cpu_to_native_limit": 1.10,
        "ndabi_p50_to_native": p50_native,
        "ndabi_p50_to_native_limit": 1.15,
        "ndabi_p95_limit_ns": 25_000_000,
        "ndabi_p95_to_native": p95_native,
        "ndabi_stack_cpu_to_native": stack_cpu_native,
        "ndabi_stack_cpu_to_native_limit": 1.10,
        "ndabi_stack_cpu_to_postgrest": stack_cpu_repeated,
        "ndabi_stack_cpu_to_postgrest_limit": 0.60,
        "ndabi_stack_cpu_to_postgrest_rpc": stack_cpu_rpc,
        "ndabi_stack_cpu_to_postgrest_rpc_limit": 0.60,
        "ndabi_throughput_over_native": throughput_native,
        "ndabi_throughput_over_native_minimum": 0.95,
        "performance_gates_enforced": production.ENFORCE_PERFORMANCE,
        "performance_gates_passed": performance,
        "passed": passed,
    }


def run_process(
    process: int,
    postgres: str,
    pooled_connection: str,
    endpoint: str,
    token_path: Path,
    public_key: Path,
    custody: Path,
) -> dict:
    cases = []
    for concurrency_index, concurrency in enumerate(production.campaign.CONCURRENCY_LEVELS):
        order = production.arm_order(process, concurrency_index)
        measurements = {}
        for arm in order:
            resources_before = production.container_resource_snapshot(postgres)
            host_idle = production.campaign.await_quiet_host()
            production.campaign.v72.psql(postgres, "SELECT pg_stat_statements_reset()")
            measurement = run_load_arm_attributed(
                arm,
                concurrency,
                pooled_connection,
                endpoint,
                token_path,
                public_key,
                custody,
                postgres,
            )
            resources_after = production.container_resource_snapshot(postgres)
            observed_queries = production.campaign.v72.data_queries(postgres)
            expected_queries = production.campaign.expected_data_queries(arm, concurrency)
            measurement["observed_data_queries"] = observed_queries
            measurement["expected_data_queries"] = expected_queries
            measurement["query_gate_passed"] = observed_queries == expected_queries
            measurement["host_idle_preflight"] = host_idle
            measurement["container_resources_before"] = resources_before
            measurement["container_resources_after"] = resources_after
            production.campaign.validate_arm_measurement(measurement, arm, concurrency)
            production.validate_container_resource_snapshot(resources_before)
            production.validate_container_resource_snapshot(resources_after)
            production.validate_request_byte_evidence(measurement, arm)
            validate_container_cpu_snapshot(measurement["container_cpu_before"])
            validate_container_cpu_snapshot(measurement["container_cpu_after"])
            measurements[arm] = measurement
        comparison = compare_measurements(measurements, concurrency)
        cases.append(
            {
                "arm_order": order,
                "comparison": comparison,
                "concurrency": concurrency,
                "measurements": measurements,
                "passed": comparison["passed"],
            }
        )
    return {
        "cases": cases,
        "passed": all(case["passed"] for case in cases),
        "process": process,
    }


def validate_process_report(report: dict) -> None:
    process = report.get("process")
    production.require(
        isinstance(process, int) and 1 <= process <= production.PROCESS_COUNT,
        "the process identifier is invalid",
    )
    cases = report.get("cases")
    production.require(
        isinstance(cases, list)
        and len(cases) == len(production.campaign.CONCURRENCY_LEVELS),
        "the process cases are invalid",
    )
    for concurrency_index, concurrency in enumerate(production.campaign.CONCURRENCY_LEVELS):
        case = next((item for item in cases if item.get("concurrency") == concurrency), None)
        production.require(isinstance(case, dict), "a concurrency case is absent")
        production.require(
            case.get("arm_order") == production.arm_order(process, concurrency_index),
            "the arm order changed",
        )
        measurements = case.get("measurements")
        production.require(
            isinstance(measurements, dict) and set(measurements) == set(ARMS),
            "the measurement arms changed",
        )
        for arm in ARMS:
            measurement = measurements[arm]
            production.campaign.validate_arm_measurement(measurement, arm, concurrency)
            production.validate_container_resource_snapshot(
                measurement.get("container_resources_before")
            )
            production.validate_container_resource_snapshot(
                measurement.get("container_resources_after")
            )
            production.validate_request_byte_evidence(measurement, arm)
            delta = container_cpu_delta(
                measurement.get("container_cpu_before"),
                measurement.get("container_cpu_after"),
            )
            production.require(
                measurement.get("container_cpu_delta") == delta,
                "the container CPU delta changed",
            )
            production.require(
                measurement.get("total_measured_stack_cpu_ns")
                == measurement["total_client_cpu_ns"] + delta["total_usage_ns"],
                "the measured stack CPU total changed",
            )
        expected = compare_measurements(measurements, concurrency)
        comparison = case.get("comparison")
        production.require(isinstance(comparison, dict), "the comparison is absent")
        for key, value in expected.items():
            if isinstance(value, float):
                production.require(
                    math.isclose(comparison.get(key, math.inf), value, rel_tol=1e-12),
                    f"the comparison changed: {key}",
                )
            else:
                production.require(comparison.get(key) == value, f"changed: {key}")
        production.require(case.get("passed") is expected["passed"], "changed verdict")
    production.require(
        report.get("passed") is all(case["passed"] for case in cases),
        "the process verdict changed",
    )


def campaign_summary(processes: list[dict]) -> list[dict]:
    summary = []
    for concurrency in production.campaign.CONCURRENCY_LEVELS:
        cases = [
            next(case for case in process["cases"] if case["concurrency"] == concurrency)
            for process in processes
        ]
        comparisons = [case["comparison"] for case in cases]
        fixed = [case["measurements"]["ndabi_fixed"] for case in cases]
        summary.append(
            {
                "all_repetitions_passed": all(case["passed"] for case in cases),
                "concurrency": concurrency,
                "median_fixed_client_cpu_to_legacy": statistics.median(
                    item["fixed_client_cpu_to_legacy"] for item in comparisons
                ),
                "median_ndabi_client_cpu_to_native": statistics.median(
                    item["ndabi_client_cpu_to_native"] for item in comparisons
                ),
                "median_ndabi_p50_to_native": statistics.median(
                    item["ndabi_p50_to_native"] for item in comparisons
                ),
                "median_ndabi_p95_ns": int(
                    statistics.median(item["p95_request_ns"] for item in fixed)
                ),
                "median_ndabi_p95_to_native": statistics.median(
                    item["ndabi_p95_to_native"] for item in comparisons
                ),
                "median_ndabi_stack_cpu_to_native": statistics.median(
                    item["ndabi_stack_cpu_to_native"] for item in comparisons
                ),
                "median_ndabi_stack_cpu_to_postgrest": statistics.median(
                    item["ndabi_stack_cpu_to_postgrest"] for item in comparisons
                ),
                "median_ndabi_stack_cpu_to_postgrest_rpc": statistics.median(
                    item["ndabi_stack_cpu_to_postgrest_rpc"] for item in comparisons
                ),
                "median_ndabi_throughput_over_native": statistics.median(
                    item["ndabi_throughput_over_native"] for item in comparisons
                ),
            }
        )
    return summary


def configure(
    *,
    build_binary: bool = True,
    functional: bool = False,
    result_root: Path | None = None,
) -> None:
    target_root = result_root or RESULT_ROOT
    BASE_CONFIGURE(
        build_binary=build_binary,
        functional=functional,
        result_root=target_root,
    )
    production.RESULT_ROOT = RESULT_ROOT
    production.CAMPAIGN_NAME = CAMPAIGN_NAME
    production.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    production.FORMAL_CAMPAIGN_NAME = FORMAL_CAMPAIGN_NAME
    production.CAMPAIGN_VERSION = CAMPAIGN_VERSION
    production.ENTRYPOINT = Path(__file__).resolve()
    production.TENANT_ID = TENANT_ID
    production.SESSION_PROOF_LABEL = SESSION_PROOF_LABEL
    production.SESSION_PROOF_EXPECTED = SESSION_PROOF_EXPECTED
    production.ARMS = ARMS
    production.ARM_IDENTIFIERS = ARM_IDENTIFIERS
    production.QUERY_MULTIPLIERS = QUERY_MULTIPLIERS
    production.SAMPLES_BY_ARM = SAMPLES_BY_ARM
    production.FUNCTIONAL_SAMPLES_BY_ARM = FUNCTIONAL_SAMPLES_BY_ARM
    production.REQUEST_BYTES_KINDS = REQUEST_BYTES_KINDS
    production.WORKER_SCHEMA = WORKER_SCHEMA
    production.SOURCE_PATHS = SOURCE_PATHS
    production.compare_measurements = compare_measurements
    production.campaign_summary = campaign_summary

    campaign = production.campaign
    campaign.RESULT_ROOT = target_root
    campaign.CAMPAIGN_NAME = CAMPAIGN_NAME
    campaign.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    campaign.TENANT_ID = TENANT_ID
    campaign.SESSION_PROOF_LABEL = SESSION_PROOF_LABEL
    campaign.SESSION_PROOF_EXPECTED = SESSION_PROOF_EXPECTED
    campaign.ARMS = ARMS
    campaign.ARM_IDENTIFIERS = ARM_IDENTIFIERS
    campaign.QUERY_MULTIPLIERS = QUERY_MULTIPLIERS
    campaign.SAMPLES_BY_ARM = FUNCTIONAL_SAMPLES_BY_ARM if functional else SAMPLES_BY_ARM
    campaign.WORKER_SCHEMA = WORKER_SCHEMA
    campaign.SOURCE_PATHS = SOURCE_PATHS
    campaign.SECURITY_CHECK_COUNT = SECURITY_CHECK_COUNT
    campaign.v72.security_checks = BASE_SECURITY_CHECKS
    campaign.run_process = run_process
    campaign.validate_process_report = validate_process_report
    campaign.campaign_summary = campaign_summary
    campaign.SMOKE_RESULT_PATH = (
        RESULT_ROOT / "functional-latest.json"
        if functional
        else RESULT_ROOT / "performance-smoke-latest.json"
    )


production.RESULT_ROOT = RESULT_ROOT
production.FORMAL_CAMPAIGN_NAME = FORMAL_CAMPAIGN_NAME
production.CAMPAIGN_VERSION = CAMPAIGN_VERSION
production.ENTRYPOINT = Path(__file__).resolve()


if __name__ == "__main__":
    production.configure = configure
    raise SystemExit(production.main())
