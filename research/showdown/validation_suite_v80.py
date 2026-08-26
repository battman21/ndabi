#!/usr/bin/env python3
"""Run one fair-control NDABI Supabase production stack."""

from __future__ import annotations

import math
import hashlib
import json
import subprocess
import statistics
import sys
import time
from pathlib import Path

import evidence_manifest_v80
import validation_suite_v76 as duration_repair


campaign = duration_repair.campaign
ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "results" / "v80"
CAMPAIGN_NAME = "NDABI Supabase production stack v8.0"
CAMPAIGN_LABEL = "v8.0 stack"
FORMAL_CAMPAIGN_NAME = "NDABI Supabase production campaign v8.0"
CAMPAIGN_VERSION = "v8.0"
ENTRYPOINT = Path(__file__).resolve()
TENANT_ID = "ndabi-v80"
SESSION_PROOF_LABEL = "ndabi-v80-session-proof"
SESSION_PROOF_EXPECTED = "80"
ACCEPTANCE_REPETITIONS = 5
QUALIFICATION_STACKS = 3
PROCESS_COUNT = ACCEPTANCE_REPETITIONS
MAX_QUALIFICATION_EVIDENCE_BYTES = 1024 * 1024 * 1024
ARMS = ("native", "ndabi", "postgrest_rpc", "postgrest")
ARM_IDENTIFIERS = {
    "native": "native-indexed-batch-session",
    "ndabi": "ndabi-indexed-batch-session",
    "postgrest_rpc": "postgrest-rpc-user-jwt",
    "postgrest": "postgrest-user-jwt",
}
QUERY_MULTIPLIERS = {
    "native": 1,
    "ndabi": 1,
    "postgrest_rpc": 1,
    "postgrest": campaign.OPERATIONS,
}
SAMPLES_BY_ARM = {
    "native": 8_191,
    "ndabi": 8_191,
    "postgrest_rpc": 1_023,
    "postgrest": 127,
}
MINIMUM_ARM_DURATION_NS = 2_000_000_000
WORKER_SCHEMA = "ndabi-supavisor-load-worker-v8.0"
FUNCTIONAL_SAMPLES_BY_ARM = {arm: 3 for arm in ARMS}
ENFORCE_PERFORMANCE = True
QUIET_HOST_PROBE = campaign.await_quiet_host
LEGACY_RUN_PROCESS = campaign.run_process
LEGACY_VALIDATE_PROCESS_REPORT = campaign.validate_process_report
LEGACY_CAMPAIGN_SUMMARY = campaign.campaign_summary
LEGACY_REPEATABILITY = campaign.repeatability
LEGACY_SECURITY_CHECKS = campaign.v72.security_checks
LEGACY_ARMS = campaign.ARMS
LEGACY_ARM_IDENTIFIERS = campaign.ARM_IDENTIFIERS
LEGACY_QUERY_MULTIPLIERS = campaign.QUERY_MULTIPLIERS
LEGACY_WORKER_SCHEMA = campaign.WORKER_SCHEMA
LEGACY_STATE = {
    name: getattr(campaign, name)
    for name in (
        "BUILD_BINARY",
        "CAMPAIGN_LABEL",
        "CAMPAIGN_NAME",
        "CONCURRENCY_LEVELS",
        "MEASUREMENT_MODE",
        "MINIMUM_ARM_DURATION_NS",
        "MINIMUM_HOST_IDLE_PERCENT",
        "MONITOR_BUILD_PROCESSES_DURING_ARM",
        "PERFORMANCE_GATES_ENFORCED",
        "PROCESS_COUNT",
        "REQUIRE_QUIET_HOST",
        "RESULT_ROOT",
        "SECURITY_CHECK_COUNT",
        "SAMPLES_BY_ARM",
        "SMOKE_PROCESS_COUNT",
        "SMOKE_REPEATABILITY",
        "SESSION_PROOF_EXPECTED",
        "SESSION_PROOF_LABEL",
        "SMOKE_RESULT_PATH",
        "SOURCE_PATHS",
        "TENANT_ID",
    )
}
REQUEST_BYTES_KINDS = {
    "native": "unavailable-postgresql-driver-wire",
    "ndabi": "exact-ndabi-frame",
    "postgrest_rpc": "exact-json-body",
    "postgrest": "calculated-http-lower-bound",
}
SOURCE_PATHS = duration_repair.SOURCE_PATHS + (
    "validation_suite_v80.py",
    "requirements-v80.txt",
    "evidence_manifest_v80.py",
    "tests/test_validation_v80.py",
    "tests/test_evidence_manifest_v80.py",
    "../../specs/ndabi_supabase_production_campaign_v8_0.md",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def arm_order(process: int, concurrency_index: int) -> list[str]:
    require(1 <= process <= PROCESS_COUNT, "the process identifier is invalid")
    require(
        0 <= concurrency_index < len(campaign.CONCURRENCY_LEVELS),
        "the concurrency index is invalid",
    )
    offset = (process - 1 + concurrency_index) % len(ARMS)
    return list(ARMS[offset:] + ARMS[:offset])


def _identity(measurement: dict) -> dict[int, tuple[int, str]]:
    return {
        report["worker"]: (report["result_bytes"], report["result_sha256"])
        for report in measurement["workers"]
    }


def _cpu_per_operation(measurement: dict) -> float:
    operations = measurement["logical_operations"]
    return measurement["total_client_cpu_ns"] / operations if operations else math.inf


def container_names(postgres: str) -> tuple[str, str, str]:
    marker = "-postgres-"
    require(marker in postgres, "the PostgreSQL container name is invalid")
    prefix, suffix = postgres.split(marker, 1)
    require(bool(prefix) and bool(suffix), "the PostgreSQL container name is invalid")
    return (
        postgres,
        f"{prefix}-postgrest-{suffix}",
        f"{prefix}-supavisor-{suffix}",
    )


def container_resource_snapshot(postgres: str) -> dict:
    names = container_names(postgres)
    completed = campaign.command(
        "docker",
        "stats",
        "--no-stream",
        "--format",
        "{{json .}}",
        *names,
        check=False,
    )
    require(completed.returncode == 0, "the container resource probe failed")
    records = []
    for line in completed.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError("the container resource probe returned invalid JSON") from error
        require(isinstance(value, dict), "the container resource record is invalid")
        record = {
            key: value.get(key)
            for key in ("BlockIO", "CPUPerc", "MemUsage", "Name", "NetIO", "PIDs")
        }
        require(
            all(isinstance(item, str) and item for item in record.values()),
            "the container resource record is incomplete",
        )
        records.append(record)
    require(
        {record["Name"] for record in records} == set(names) and len(records) == len(names),
        "the container resource set changed",
    )
    records.sort(key=lambda item: item["Name"])
    return {"captured_unix_ns": time.time_ns(), "containers": records}


def validate_container_resource_snapshot(value: object) -> None:
    require(isinstance(value, dict), "the container resource snapshot is absent")
    require(
        isinstance(value.get("captured_unix_ns"), int)
        and value["captured_unix_ns"] > 0,
        "the container resource timestamp is invalid",
    )
    records = value.get("containers")
    require(isinstance(records, list) and len(records) == 3, "invalid container resources")
    names = []
    for record in records:
        require(isinstance(record, dict), "the container resource record is invalid")
        require(
            set(record) == {"BlockIO", "CPUPerc", "MemUsage", "Name", "NetIO", "PIDs"},
            "the container resource shape changed",
        )
        require(
            all(isinstance(item, str) and item for item in record.values()),
            "the container resource record is incomplete",
        )
        names.append(record["Name"])
    require(names == sorted(set(names)), "the container resource names changed")


def validate_request_byte_evidence(measurement: dict, arm: str) -> None:
    workers = measurement.get("workers")
    require(isinstance(workers, list) and workers, "the request-byte workers are absent")
    for worker in workers:
        require(
            worker.get("request_bytes_kind") == REQUEST_BYTES_KINDS[arm],
            "the request-byte evidence kind changed",
        )
        value = worker.get("request_application_bytes")
        if arm == "native":
            require(value is None, "the native driver wire size must remain unavailable")
        else:
            require(
                isinstance(value, int) and value > 0,
                "the request-byte evidence is invalid",
            )


def functional_host_preflight() -> dict:
    return {
        "active_build_processes": campaign.active_build_processes(),
        "measurement_mode": "functional-only",
        "minimum_idle_percent": 0.0,
        "observations": [],
        "passed": True,
    }


def compare_measurements(measurements: dict[str, dict], concurrency: int) -> dict:
    require(set(measurements) == set(ARMS), "the comparison arms changed")
    require(
        all(item["concurrency"] == concurrency for item in measurements.values()),
        "the comparison concurrency changed",
    )
    native = measurements["native"]
    ndabi = measurements["ndabi"]
    rpc = measurements["postgrest_rpc"]
    repeated = measurements["postgrest"]
    identities = [_identity(measurements[arm]) for arm in ARMS]
    exact = all(identity == identities[0] for identity in identities[1:])
    exact &= len(identities[0]) == concurrency
    native_throughput = native["logical_operations_per_second"]
    repeated_throughput = repeated["logical_operations_per_second"]
    rpc_throughput = rpc["logical_operations_per_second"]
    ndabi_native_throughput = (
        ndabi["logical_operations_per_second"] / native_throughput
        if native_throughput
        else 0.0
    )
    ndabi_repeated_throughput = (
        ndabi["logical_operations_per_second"] / repeated_throughput
        if repeated_throughput
        else 0.0
    )
    ndabi_rpc_throughput = (
        ndabi["logical_operations_per_second"] / rpc_throughput
        if rpc_throughput
        else 0.0
    )
    ndabi_native_p50 = (
        ndabi["p50_request_ns"] / native["p50_request_ns"]
        if native["p50_request_ns"]
        else math.inf
    )
    ndabi_native_p95 = (
        ndabi["p95_request_ns"] / native["p95_request_ns"]
        if native["p95_request_ns"]
        else math.inf
    )
    native_cpu = _cpu_per_operation(native)
    ndabi_native_cpu = _cpu_per_operation(ndabi) / native_cpu if native_cpu else math.inf
    performance = (
        ndabi_native_throughput >= 0.85
        and ndabi_native_p50 <= 1.20
        and ndabi_native_cpu <= 1.25
        and ndabi_repeated_throughput >= 5.0
        and ndabi["p95_request_ns"] <= 25_000_000
    )
    passed = (
        all(measurement["complete"] for measurement in measurements.values())
        and all(measurement["query_gate_passed"] for measurement in measurements.values())
        and exact
        and (performance or not ENFORCE_PERFORMANCE)
    )
    return {
        "canonical_results_equal": exact,
        "concurrency": concurrency,
        "ndabi_p95_limit_ns": 25_000_000,
        "ndabi_p95_to_native": ndabi_native_p95,
        "ndabi_p50_to_native": ndabi_native_p50,
        "ndabi_p50_to_native_limit": 1.20,
        "ndabi_cpu_to_native": ndabi_native_cpu,
        "ndabi_cpu_to_native_limit": 1.25,
        "ndabi_throughput_over_native": ndabi_native_throughput,
        "ndabi_throughput_over_native_minimum": 0.85,
        "ndabi_throughput_over_postgrest": ndabi_repeated_throughput,
        "ndabi_throughput_over_postgrest_minimum": 5.0,
        "ndabi_throughput_over_postgrest_rpc": ndabi_rpc_throughput,
        "performance_gates_enforced": ENFORCE_PERFORMANCE,
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
    for concurrency_index, concurrency in enumerate(campaign.CONCURRENCY_LEVELS):
        order = arm_order(process, concurrency_index)
        measurements = {}
        for arm in order:
            resources_before = container_resource_snapshot(postgres)
            host_idle = campaign.await_quiet_host()
            campaign.v72.psql(postgres, "SELECT pg_stat_statements_reset()")
            measurement = campaign.run_load_arm(
                arm,
                concurrency,
                pooled_connection,
                endpoint,
                token_path,
                public_key,
                custody,
            )
            resources_after = container_resource_snapshot(postgres)
            observed_queries = campaign.v72.data_queries(postgres)
            expected_queries = campaign.expected_data_queries(arm, concurrency)
            measurement["observed_data_queries"] = observed_queries
            measurement["expected_data_queries"] = expected_queries
            measurement["query_gate_passed"] = observed_queries == expected_queries
            measurement["host_idle_preflight"] = host_idle
            measurement["container_resources_before"] = resources_before
            measurement["container_resources_after"] = resources_after
            try:
                campaign.validate_arm_measurement(measurement, arm, concurrency)
            except ValueError as error:
                worker_errors = json.dumps(
                    measurement.get("errors", []), sort_keys=True, separators=(",", ":")
                )
                raise ValueError(
                    f"{arm} concurrency {concurrency} failed validation: {error}; "
                    f"worker_errors={worker_errors}"
                ) from error
            validate_container_resource_snapshot(resources_before)
            validate_container_resource_snapshot(resources_after)
            validate_request_byte_evidence(measurement, arm)
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
    require(isinstance(process, int) and 1 <= process <= PROCESS_COUNT, "invalid process")
    cases = report.get("cases")
    require(
        isinstance(cases, list) and len(cases) == len(campaign.CONCURRENCY_LEVELS),
        "invalid cases",
    )
    for concurrency_index, concurrency in enumerate(campaign.CONCURRENCY_LEVELS):
        case = next((item for item in cases if item.get("concurrency") == concurrency), None)
        require(isinstance(case, dict), "a concurrency case is absent")
        require(
            case.get("arm_order") == arm_order(process, concurrency_index),
            "the arm order changed",
        )
        measurements = case.get("measurements")
        require(isinstance(measurements, dict), "invalid measurements")
        require(set(measurements) == set(ARMS), "the measurement arms changed")
        for arm in ARMS:
            campaign.validate_arm_measurement(measurements[arm], arm, concurrency)
            validate_container_resource_snapshot(
                measurements[arm].get("container_resources_before")
            )
            validate_container_resource_snapshot(
                measurements[arm].get("container_resources_after")
            )
            validate_request_byte_evidence(measurements[arm], arm)
        expected = compare_measurements(measurements, concurrency)
        comparison = case.get("comparison")
        require(isinstance(comparison, dict), "the comparison is absent")
        for key, value in expected.items():
            if isinstance(value, float):
                require(
                    math.isclose(comparison.get(key, math.inf), value, rel_tol=1e-12),
                    f"the comparison changed: {key}",
                )
            else:
                require(comparison.get(key) == value, f"the comparison changed: {key}")
        require(case.get("passed") is expected["passed"], "the case verdict changed")
    require(report.get("passed") is all(case["passed"] for case in cases), "changed verdict")


def campaign_summary(processes: list[dict]) -> list[dict]:
    summary = []
    for concurrency in campaign.CONCURRENCY_LEVELS:
        cases = [
            next(case for case in process["cases"] if case["concurrency"] == concurrency)
            for process in processes
        ]
        comparisons = [case["comparison"] for case in cases]
        measurements = {
            arm: [case["measurements"][arm] for case in cases] for arm in ARMS
        }
        summary.append(
            {
                "concurrency": concurrency,
                "all_repetitions_passed": all(case["passed"] for case in cases),
                "median_ndabi_cpu_to_native": statistics.median(
                    item["ndabi_cpu_to_native"] for item in comparisons
                ),
                "median_ndabi_p50_to_native": statistics.median(
                    item["ndabi_p50_to_native"] for item in comparisons
                ),
                "median_ndabi_p95_ns": int(
                    statistics.median(item["p95_request_ns"] for item in measurements["ndabi"])
                ),
                "median_native_p95_ns": int(
                    statistics.median(item["p95_request_ns"] for item in measurements["native"])
                ),
                "median_ndabi_p95_to_native": statistics.median(
                    item["ndabi_p95_to_native"] for item in comparisons
                ),
                "median_ndabi_throughput_over_native": statistics.median(
                    item["ndabi_throughput_over_native"] for item in comparisons
                ),
                "median_ndabi_throughput_over_postgrest": statistics.median(
                    item["ndabi_throughput_over_postgrest"] for item in comparisons
                ),
                "median_ndabi_throughput_over_postgrest_rpc": statistics.median(
                    item["ndabi_throughput_over_postgrest_rpc"] for item in comparisons
                ),
            }
        )
    return summary


def repeatability(processes: list[dict]) -> tuple[list[dict], bool]:
    require(len(processes) == PROCESS_COUNT, "the stack repetition count changed")
    evidence = []
    passed = True
    for concurrency in campaign.CONCURRENCY_LEVELS:
        comparisons = [
            next(case for case in process["cases"] if case["concurrency"] == concurrency)[
                "comparison"
            ]
            for process in processes
        ]
        throughput_cv = campaign.coefficient_of_variation(
            [item["ndabi_throughput_over_native"] for item in comparisons]
        )
        p95_cv = campaign.coefficient_of_variation(
            [item["ndabi_p95_to_native"] for item in comparisons]
        )
        median_p95_ratio = statistics.median(
            item["ndabi_p95_to_native"] for item in comparisons
        )
        item_passed = throughput_cv < 0.15 and p95_cv < 0.15 and median_p95_ratio <= 1.15
        evidence.append(
            {
                "concurrency": concurrency,
                "median_ndabi_p95_to_native": median_p95_ratio,
                "median_ndabi_p95_to_native_limit": 1.15,
                "ndabi_native_p95_ratio_cv": p95_cv,
                "ndabi_native_throughput_ratio_cv": throughput_cv,
                "ratio_cv_limit": 0.15,
                "passed": item_passed,
            }
        )
        passed &= item_passed
    return evidence, passed


LEGACY_MODULE_STATE = {
    "ARMS": ARMS,
    "ARM_IDENTIFIERS": ARM_IDENTIFIERS,
    "FUNCTIONAL_SAMPLES_BY_ARM": FUNCTIONAL_SAMPLES_BY_ARM,
    "QUERY_MULTIPLIERS": QUERY_MULTIPLIERS,
    "REQUEST_BYTES_KINDS": REQUEST_BYTES_KINDS,
    "SAMPLES_BY_ARM": SAMPLES_BY_ARM,
    "SOURCE_PATHS": SOURCE_PATHS,
    "WORKER_SCHEMA": WORKER_SCHEMA,
    "campaign_summary": campaign_summary,
    "compare_measurements": compare_measurements,
}


def restore_legacy_campaign() -> None:
    global ENFORCE_PERFORMANCE
    globals().update(LEGACY_MODULE_STATE)
    for name, value in LEGACY_STATE.items():
        setattr(campaign, name, value)
    campaign.ARMS = LEGACY_ARMS
    campaign.ARM_IDENTIFIERS = LEGACY_ARM_IDENTIFIERS
    campaign.QUERY_MULTIPLIERS = LEGACY_QUERY_MULTIPLIERS
    campaign.WORKER_SCHEMA = LEGACY_WORKER_SCHEMA
    campaign.await_quiet_host = QUIET_HOST_PROBE
    campaign.run_process = LEGACY_RUN_PROCESS
    campaign.validate_process_report = LEGACY_VALIDATE_PROCESS_REPORT
    campaign.campaign_summary = LEGACY_CAMPAIGN_SUMMARY
    campaign.repeatability = LEGACY_REPEATABILITY
    campaign.v72.security_checks = LEGACY_SECURITY_CHECKS
    ENFORCE_PERFORMANCE = True


def configure(
    *,
    build_binary: bool = True,
    functional: bool = False,
    result_root: Path | None = None,
) -> None:
    global ENFORCE_PERFORMANCE
    restore_legacy_campaign()
    duration_repair.configure()
    campaign.RESULT_ROOT = result_root or RESULT_ROOT
    campaign.CAMPAIGN_NAME = CAMPAIGN_NAME
    campaign.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    campaign.TENANT_ID = TENANT_ID
    campaign.SESSION_PROOF_LABEL = SESSION_PROOF_LABEL
    campaign.SESSION_PROOF_EXPECTED = SESSION_PROOF_EXPECTED
    campaign.PROCESS_COUNT = PROCESS_COUNT
    campaign.ARMS = ARMS
    campaign.ARM_IDENTIFIERS = ARM_IDENTIFIERS
    campaign.QUERY_MULTIPLIERS = QUERY_MULTIPLIERS
    campaign.WORKER_SCHEMA = WORKER_SCHEMA
    campaign.SAMPLES_BY_ARM = FUNCTIONAL_SAMPLES_BY_ARM if functional else SAMPLES_BY_ARM
    campaign.MINIMUM_ARM_DURATION_NS = 0 if functional else MINIMUM_ARM_DURATION_NS
    campaign.MONITOR_BUILD_PROCESSES_DURING_ARM = not functional
    campaign.BUILD_BINARY = build_binary
    campaign.REQUIRE_QUIET_HOST = not functional
    campaign.await_quiet_host = functional_host_preflight if functional else QUIET_HOST_PROBE
    campaign.MEASUREMENT_MODE = "functional-only" if functional else "performance"
    campaign.PERFORMANCE_GATES_ENFORCED = not functional
    campaign.SMOKE_RESULT_PATH = (
        RESULT_ROOT / "functional-latest.json" if functional else None
    )
    campaign.SOURCE_PATHS = SOURCE_PATHS
    campaign.run_process = run_process
    campaign.validate_process_report = validate_process_report
    campaign.campaign_summary = campaign_summary
    campaign.repeatability = repeatability
    ENFORCE_PERFORMANCE = not functional


def cross_stack_repeatability(stacks: list[list[dict]]) -> tuple[list[dict], bool]:
    require(len(stacks) == QUALIFICATION_STACKS, "the cold-stack count changed")
    require(all(len(processes) == PROCESS_COUNT for processes in stacks), "a stack is incomplete")
    evidence = []
    passed = True
    for concurrency in campaign.CONCURRENCY_LEVELS:
        comparisons_by_stack = [
            [
                next(
                    case for case in process["cases"] if case["concurrency"] == concurrency
                )["comparison"]
                for process in processes
            ]
            for processes in stacks
        ]
        comparisons = [item for stack in comparisons_by_stack for item in stack]
        throughput_values = [
            item["ndabi_throughput_over_native"] for item in comparisons
        ]
        p95_values = [item["ndabi_p95_to_native"] for item in comparisons]
        stack_throughput_medians = [
            statistics.median(
                item["ndabi_throughput_over_native"] for item in stack
            )
            for stack in comparisons_by_stack
        ]
        stack_p95_medians = [
            statistics.median(item["ndabi_p95_to_native"] for item in stack)
            for stack in comparisons_by_stack
        ]
        throughput_cv = campaign.coefficient_of_variation(throughput_values)
        p95_cv = campaign.coefficient_of_variation(p95_values)
        stack_throughput_cv = campaign.coefficient_of_variation(stack_throughput_medians)
        stack_p95_cv = campaign.coefficient_of_variation(stack_p95_medians)
        median_p95 = statistics.median(p95_values)
        item_passed = (
            throughput_cv < 0.15
            and p95_cv < 0.15
            and stack_throughput_cv < 0.10
            and stack_p95_cv < 0.10
            and median_p95 <= 1.15
        )
        evidence.append(
            {
                "concurrency": concurrency,
                "median_ndabi_p95_to_native": median_p95,
                "median_ndabi_p95_to_native_limit": 1.15,
                "ndabi_native_p95_ratio_cv": p95_cv,
                "ndabi_native_throughput_ratio_cv": throughput_cv,
                "ratio_cv_limit": 0.15,
                "stack_median_p95_ratio_cv": stack_p95_cv,
                "stack_median_throughput_ratio_cv": stack_throughput_cv,
                "stack_ratio_cv_limit": 0.10,
                "passed": item_passed,
            }
        )
        passed &= item_passed
    return evidence, passed


def _load_stack_processes(stack_root: Path, aggregate: dict) -> list[dict]:
    evidence = stack_root / aggregate["campaign_id"]
    processes = []
    for process in range(1, PROCESS_COUNT + 1):
        path = evidence / f"process-{process}.json.gz"
        try:
            report = campaign.read_process_evidence(path)
        except (OSError, ValueError) as error:
            raise ValueError("a stack process report cannot be decoded") from error
        validate_process_report(report)
        processes.append(report)
    return processes


def _validate_shard_root(value: str) -> Path:
    root = Path(value).resolve()
    result_root = RESULT_ROOT.resolve()
    try:
        root.relative_to(result_root)
    except ValueError as error:
        raise SystemExit(
            f"the stack-shard root is outside the {CAMPAIGN_VERSION} result root"
        ) from error
    return root


def run_stack_shard(root: Path) -> int:
    configure(build_binary=False, result_root=root)
    sys.argv = [sys.argv[0]]
    try:
        return campaign.main()
    except (RuntimeError, ValueError) as error:
        root.mkdir(parents=True, exist_ok=True)
        campaign.write_json(
            root / "shard-failure.json",
            {
                "error": str(error),
                "error_type": type(error).__name__,
            },
        )
        return 1


def run_formal_campaign(*, acceptance: bool = False) -> int:
    configure()
    stack_target = 1 if acceptance else QUALIFICATION_STACKS
    campaign_mode = "acceptance" if acceptance else "qualification"
    latest = RESULT_ROOT / f"{campaign_mode}-latest.json"
    source_commit = campaign.committed_source()
    initial_source_sha256 = campaign.source_sha256()
    initial_free_disk_bytes = campaign.require_free_disk(RESULT_ROOT)
    campaign.command(
        "cargo",
        "build",
        "--manifest-path",
        str(ROOT / "Cargo.toml"),
        "--release",
        "--locked",
        "--bin",
        "ndabi_v71",
    )
    campaign_id = f"{campaign_mode}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    evidence_root = RESULT_ROOT / campaign_id
    evidence_root.mkdir(parents=True, exist_ok=False)
    stack_records = []
    stack_processes = []
    for stack in range(1, stack_target + 1):
        stack_root = evidence_root / f"stack-{stack}"
        completed = subprocess.run(
            [sys.executable, str(ENTRYPOINT), "--stack-shard", str(stack_root)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        stack_latest = stack_root / "latest.json"
        if not stack_latest.is_file():
            shard_failure = stack_root / "shard-failure.json"
            failure = {
                "exit_code": completed.returncode,
                "stack": stack,
                "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
                "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
                "shard_failure_sha256": (
                    campaign.file_sha256(shard_failure)
                    if shard_failure.is_file()
                    else None
                ),
            }
            stack_root.mkdir(parents=True, exist_ok=True)
            campaign.write_json(stack_root / "orchestrator-failure.json", failure)
            stack_records.append({**failure, "accepted": False})
            break
        try:
            aggregate = json.loads(stack_latest.read_text(encoding="utf-8"))
            processes = _load_stack_processes(stack_root, aggregate)
            evidence_bytes = sum(
                path.stat().st_size
                for path in evidence_root.rglob("*")
                if path.is_file() and not path.is_symlink()
            )
            if evidence_bytes > MAX_QUALIFICATION_EVIDENCE_BYTES:
                raise ValueError("the formal campaign evidence exceeds its size limit")
            manifest_path = evidence_manifest_v80.write_manifest(stack_root)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            failure = {
                "error": str(error),
                "exit_code": completed.returncode,
                "stack": stack,
                "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
                "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
            }
            campaign.write_json(stack_root / "failure.json", failure)
            stack_records.append({**failure, "accepted": False})
            break
        stack_accepted = aggregate.get("accepted") is True and completed.returncode == 0
        stack_records.append(
            {
                "accepted": stack_accepted,
                "aggregate_sha256": campaign.file_sha256(
                    stack_root / aggregate["campaign_id"] / "aggregate.json"
                ),
                "campaign_id": aggregate["campaign_id"],
                "manifest_sha256": campaign.file_sha256(manifest_path),
                "stack": stack,
            }
        )
        stack_processes.append(processes)
        if not stack_accepted:
            break
    if not acceptance and len(stack_processes) == QUALIFICATION_STACKS:
        cross_stack, cross_stack_passed = cross_stack_repeatability(stack_processes)
    else:
        cross_stack, cross_stack_passed = [], False
    combined_summary = (
        campaign_summary(
            [process for processes in stack_processes for process in processes]
        )
        if len(stack_processes) == stack_target
        else []
    )
    final_source_sha256 = campaign.source_sha256()
    source_custody_passed = (
        final_source_sha256 == initial_source_sha256
        and campaign.source_matches_commit(campaign.repository_root(), source_commit)
        and campaign.tracked_worktree_clean(campaign.repository_root())
    )
    accepted = (
        len(stack_records) == stack_target
        and all(record["accepted"] for record in stack_records)
        and (acceptance or cross_stack_passed)
        and source_custody_passed
    )
    aggregate = {
        "accepted": accepted,
        "campaign": f"{FORMAL_CAMPAIGN_NAME} {campaign_mode}",
        "campaign_id": campaign_id,
        "campaign_mode": campaign_mode,
        "cold_stack_count": len(stack_processes),
        "acceptance_repetitions_per_stack": ACCEPTANCE_REPETITIONS,
        "qualification_stack_target": QUALIFICATION_STACKS,
        "requested_stack_count": stack_target,
        "initial_free_disk_bytes": initial_free_disk_bytes,
        "maximum_qualification_evidence_bytes": MAX_QUALIFICATION_EVIDENCE_BYTES,
        "cross_stack_repeatability": cross_stack,
        "cross_stack_repeatability_evaluated": not acceptance,
        "cross_stack_repeatability_passed": cross_stack_passed,
        "process_count_per_stack": PROCESS_COUNT,
        "source_commit": source_commit,
        "source_custody_passed": source_custody_passed,
        "source_sha256": final_source_sha256,
        "stacks": stack_records,
        "summary": combined_summary,
    }
    campaign.write_json(evidence_root / "aggregate.json", aggregate)
    manifest_path = evidence_manifest_v80.write_manifest(evidence_root)
    public_aggregate = {
        **aggregate,
        "evidence_manifest_sha256": campaign.file_sha256(manifest_path),
    }
    campaign.write_json(latest, public_aggregate)
    if not acceptance:
        campaign.write_json(RESULT_ROOT / "latest.json", public_aggregate)
    print(json.dumps(public_aggregate, indent=2))
    return 0 if accepted else 1


def main() -> int:
    arguments = sys.argv[1:]
    if arguments == ["--functional-smoke"]:
        configure(functional=True)
        sys.argv = [sys.argv[0], "--smoke"]
        return campaign.main()
    if arguments == ["--smoke"]:
        configure()
        return campaign.main()
    if arguments == ["--acceptance"]:
        return run_formal_campaign(acceptance=True)
    if len(arguments) == 2 and arguments[0] == "--stack-shard":
        return run_stack_shard(_validate_shard_root(arguments[1]))
    if arguments:
        raise SystemExit(
            "use no argument for qualification, --acceptance, --smoke, or --functional-smoke"
        )
    return run_formal_campaign(acceptance=False)


if __name__ == "__main__":
    raise SystemExit(main())
