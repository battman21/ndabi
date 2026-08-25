#!/usr/bin/env python3
"""Run the equal-security NDABI CPU campaign on direct and Supavisor paths."""

from __future__ import annotations

import math
import json
import statistics
from pathlib import Path

import validation_suite_v80 as production
import validation_suite_v82 as attribution
import validation_suite_v83 as cumulative


ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "results" / "v85"
CAMPAIGN_NAME = "NDABI Supabase equal-security CPU v8.5"
CAMPAIGN_LABEL = "v8.5 equal-security CPU"
FORMAL_CAMPAIGN_NAME = "NDABI Supabase equal-security CPU campaign v8.5"
CAMPAIGN_VERSION = "v8.5"
TENANT_ID = "ndabi-v85"
SESSION_PROOF_LABEL = "ndabi-v85-session-proof"
SESSION_PROOF_EXPECTED = "85"
ARMS = ("native", "governed_native", "ndabi_v85", "postgrest_rpc", "postgrest")
ARM_IDENTIFIERS = {
    "native": "native-indexed-batch-session",
    "governed_native": "governed-native-indexed-batch-session",
    "ndabi_v85": "ndabi-v85-equal-security-session",
    "postgrest_rpc": "postgrest-rpc-user-jwt",
    "postgrest": "postgrest-user-jwt",
}
QUERY_MULTIPLIERS = {
    "native": 1,
    "governed_native": 1,
    "ndabi_v85": 1,
    "postgrest_rpc": 1,
    "postgrest": production.campaign.OPERATIONS,
}
SAMPLES_BY_ARM = {
    "native": 16_383,
    "governed_native": 16_383,
    "ndabi_v85": 16_383,
    "postgrest_rpc": 8_191,
    "postgrest": 1_023,
}
FUNCTIONAL_SAMPLES_BY_ARM = {arm: 3 for arm in ARMS}
REQUEST_BYTES_KINDS = {
    "native": "unavailable-postgresql-driver-wire",
    "governed_native": "typed-in-process-control",
    "ndabi_v85": "exact-ndabi-frame",
    "postgrest_rpc": "exact-json-body",
    "postgrest": "calculated-http-lower-bound",
}
WORKER_SCHEMA = "ndabi-supavisor-load-worker-v8.5"
SECURITY_CHECK_COUNT = 24
SOURCE_PATHS = attribution.SOURCE_PATHS + (
    "validation_suite_v83.py",
    "validation_suite_v85.py",
    "tests/test_validation_v85.py",
    "../../specs/ndabi_supabase_hot_path_campaign_v8_5.md",
)
BASE_CONFIGURE = attribution.configure
BASE_SECURITY_CHECKS = production.LEGACY_SECURITY_CHECKS
BASE_SAMPLES_FOR = production.campaign.samples_for
BASE_CUMULATIVE_WORKER_SCHEMA = cumulative.WORKER_SCHEMA
BOUNDARIES = ("direct", "supavisor")
MINIMUM_ARM_DURATION_NS = 5_000_000_000
COMPONENT_SAMPLES = 255
COMPONENT_KEYS = {
    "request_encoding",
    "request_authentication_and_decoding",
    "replay_admission",
    "registered_plan_dispatch",
    "database_execution",
    "result_encoding",
    "server_result_hashing_and_receipt",
    "client_result_hashing_and_receipt_verification",
    "result_comparison_and_benchmark_bookkeeping",
}
FIXED_COMPONENT_KEYS = {
    "request_encoding",
    "request_authentication_and_decoding",
    "replay_admission",
    "registered_plan_dispatch",
}
FIXED_RESULT_BYTES = (84, 672, 10_758)


def ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else math.inf


def arm_order(process: int, concurrency_index: int, boundary_index: int) -> list[str]:
    production.require(1 <= process <= production.PROCESS_COUNT, "invalid process")
    offset = (process - 1 + concurrency_index + boundary_index) % len(ARMS)
    return list(ARMS[offset:] + ARMS[:offset])


def samples_for(arm: str) -> int:
    production.require(arm in ARMS, "the load arm is invalid")
    value = production.campaign.SAMPLES_BY_ARM[arm]
    production.require(3 <= value <= 100_000, "the v8.5 sample count is invalid")
    return value


def request_bytes(measurement: dict, *, maximum: bool = True) -> int | None:
    values = [worker.get("request_application_bytes") for worker in measurement["workers"]]
    production.require(
        all(value is None for value in values)
        or all(isinstance(value, int) for value in values),
        "the request byte evidence changed",
    )
    if values[0] is None:
        return None
    return max(values) if maximum else min(values)


def validate_request_byte_evidence(measurement: dict, arm: str) -> None:
    workers = measurement.get("workers")
    production.require(isinstance(workers, list) and workers, "request workers are absent")
    for worker in workers:
        production.require(
            worker.get("request_bytes_kind") == REQUEST_BYTES_KINDS[arm],
            "the request byte evidence kind changed",
        )
    value = request_bytes(measurement)
    if arm in {"native", "governed_native"}:
        production.require(value is None, "the control request size must remain unavailable")
    else:
        production.require(value is not None and value > 0, "the request size is invalid")


def cpu_per_operation(measurement: dict, field: str) -> float:
    operations = measurement["logical_operations"]
    return measurement[field] / operations if operations else math.inf


def relevant_container_names(postgres: str, boundary: str, arm: str) -> set[str]:
    postgres_name, postgrest_name, supavisor_name = production.container_names(postgres)
    if arm in {"postgrest", "postgrest_rpc"}:
        return {postgres_name, postgrest_name}
    if boundary == "supavisor":
        return {postgres_name, supavisor_name}
    return {postgres_name}


def add_relevant_stack_cpu(
    measurement: dict, postgres: str, boundary: str, arm: str
) -> None:
    names = relevant_container_names(postgres, boundary, arm)
    records = measurement["container_cpu_delta"]["containers"]
    observed = {record["Name"] for record in records}
    production.require(names <= observed, "a relevant CPU counter is absent")
    relevant_cpu = sum(
        record["UsageNS"] for record in records if record["Name"] in names
    )
    production.require(relevant_cpu > 0, "the relevant container CPU total is empty")
    measurement["relevant_container_names"] = sorted(names)
    measurement["relevant_container_cpu_ns"] = relevant_cpu
    measurement["total_relevant_stack_cpu_ns"] = (
        measurement["total_client_cpu_ns"] + relevant_cpu
    )


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
    governed = measurements["governed_native"]
    ndabi = measurements["ndabi_v85"]
    rpc = measurements["postgrest_rpc"]
    repeated = measurements["postgrest"]
    ndabi_bytes = request_bytes(ndabi)
    rpc_bytes = request_bytes(rpc, maximum=False)
    production.require(ndabi_bytes is not None and rpc_bytes is not None, "bytes are absent")
    request_reduction = 1.0 - ratio(ndabi_bytes, rpc_bytes)
    p95_governed = ratio(ndabi["p95_request_ns"], governed["p95_request_ns"])
    client_cpu_governed = ratio(
        cpu_per_operation(ndabi, "total_client_cpu_ns"),
        cpu_per_operation(governed, "total_client_cpu_ns"),
    )
    stack_cpu_governed = ratio(
        cpu_per_operation(ndabi, "total_relevant_stack_cpu_ns"),
        cpu_per_operation(governed, "total_relevant_stack_cpu_ns"),
    )
    throughput_native = ratio(
        ndabi["logical_operations_per_second"], native["logical_operations_per_second"]
    )
    throughput_postgrest = ratio(
        ndabi["logical_operations_per_second"], repeated["logical_operations_per_second"]
    )
    allocation_delta = ndabi["mean_allocations"] - governed["mean_allocations"]
    performance = (
        p95_governed <= 1.03
        and client_cpu_governed <= 1.05
        and stack_cpu_governed <= 1.05
        and throughput_native >= 0.95
        and throughput_postgrest >= 5.0
        and allocation_delta <= 1.0
        and request_reduction >= 0.80
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
        "ndabi_allocation_delta_to_governed": allocation_delta,
        "ndabi_allocation_delta_to_governed_limit": 1.0,
        "ndabi_client_cpu_to_governed": client_cpu_governed,
        "ndabi_client_cpu_to_governed_limit": 1.05,
        "ndabi_p95_to_governed": p95_governed,
        "ndabi_p95_to_governed_limit": 1.03,
        "ndabi_request_reduction_to_json": request_reduction,
        "ndabi_request_reduction_to_json_minimum": 0.80,
        "ndabi_stack_cpu_to_governed": stack_cpu_governed,
        "ndabi_stack_cpu_to_governed_limit": 1.05,
        "ndabi_throughput_over_native": throughput_native,
        "ndabi_throughput_over_native_minimum": 0.95,
        "ndabi_throughput_over_postgrest": throughput_postgrest,
        "ndabi_throughput_over_postgrest_minimum": 5.0,
        "postgrest_rpc_stack_cpu_per_operation": cpu_per_operation(
            rpc, "total_relevant_stack_cpu_ns"
        ),
        "performance_gates_enforced": production.ENFORCE_PERFORMANCE,
        "performance_gates_passed": performance,
        "passed": passed,
    }


def direct_connection(postgres: str) -> str:
    output = production.campaign.command("docker", "port", postgres, "5432/tcp").stdout
    port = output.strip().rsplit(":", 1)[-1]
    production.require(port.isdigit(), "the direct PostgreSQL port is invalid")
    return (
        f"host=127.0.0.1 port={port} user=authenticator "
        "password=auth-test-only dbname=ndabi"
    )


def governed_probe(
    connection: str, token_path: Path, public_key: Path, start: int
) -> tuple[int, dict]:
    v71 = production.campaign.v72.v71
    completed = production.campaign.command(
        str(production.campaign.BINARY),
        "--governed-native-probe",
        connection,
        str(token_path),
        str(public_key),
        v71.KEY_ID,
        v71.ISSUER,
        v71.AUDIENCE,
        str(start),
        "2",
        check=False,
    )
    try:
        report = json.loads(completed.stdout) if completed.returncode == 0 else {}
    except json.JSONDecodeError:
        report = {}
    return completed.returncode, report


def run_component_probe(
    connection: str, token_path: Path, public_key: Path
) -> dict:
    v71 = production.campaign.v72.v71
    completed = production.campaign.command(
        str(production.campaign.BINARY),
        "--component-probe",
        connection,
        str(token_path),
        str(public_key),
        v71.KEY_ID,
        v71.ISSUER,
        v71.AUDIENCE,
        "1000",
        str(production.campaign.OPERATIONS),
        str(COMPONENT_SAMPLES),
        check=False,
    )
    production.require(completed.returncode == 0, "the component probe failed")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("the component probe returned invalid JSON") from error
    validate_component_report(report)
    return report


def validate_component_report(report: object) -> None:
    production.require(isinstance(report, dict), "the component report is absent")
    production.require(
        report.get("schema") == "ndabi-component-probe-v8.5",
        "the component schema changed",
    )
    production.require(
        report.get("operations") == production.campaign.OPERATIONS
        and report.get("rows")
        == production.campaign.OPERATIONS * production.campaign.ROWS_PER_OPERATION,
        "the component workload changed",
    )
    production.require(
        report.get("samples") == COMPONENT_SAMPLES,
        "the component sample count changed",
    )
    production.require(report.get("passed") is True, "the component probe failed")
    components = report.get("components")
    production.require(
        isinstance(components, dict) and set(components) == COMPONENT_KEYS,
        "the component set changed",
    )
    for value in components.values():
        production.require(
            isinstance(value, dict)
            and set(value) == {"wall_ns", "cpu_ns"}
            and isinstance(value["wall_ns"], int)
            and value["wall_ns"] > 0
            and isinstance(value["cpu_ns"], int)
            and value["cpu_ns"] > 0,
            "a component interval is invalid",
        )
    fixed_profiles = report.get("fixed_profiles")
    production.require(
        isinstance(fixed_profiles, list)
        and [profile.get("result_bytes") for profile in fixed_profiles]
        == list(FIXED_RESULT_BYTES),
        "the fixed component size matrix changed",
    )
    for profile in fixed_profiles:
        production.require(
            profile.get("samples") == COMPONENT_SAMPLES
            and profile.get("passed") is True,
            "a fixed component profile failed",
        )
        fixed_components = profile.get("components")
        production.require(
            isinstance(fixed_components, dict)
            and set(fixed_components) == FIXED_COMPONENT_KEYS,
            "the fixed component set changed",
        )
        for value in fixed_components.values():
            production.require(
                isinstance(value, dict)
                and set(value) == {"wall_ns", "cpu_ns"}
                and isinstance(value["wall_ns"], int)
                and value["wall_ns"] > 0
                and isinstance(value["cpu_ns"], int)
                and value["cpu_ns"] > 0,
                "a fixed component interval is invalid",
            )


def security_checks(
    pooled_connection: str,
    endpoint: str,
    token_paths: dict[str, Path],
    public_key: Path,
    valid_one: str,
) -> dict[str, bool]:
    security = BASE_SECURITY_CHECKS(
        pooled_connection, endpoint, token_paths, public_key, valid_one
    )
    valid_code, report = governed_probe(
        pooled_connection, token_paths["valid"], public_key, 1_000
    )
    cross_code, _ = governed_probe(
        pooled_connection, token_paths["valid"], public_key, 900_000
    )
    second_code, _ = governed_probe(
        pooled_connection, token_paths["user_two"], public_key, 900_000
    )
    security.update(
        {
            "authorised_governed_rows_accepted": valid_code == 0,
            "cross_subject_governed_rows_refused": cross_code != 0,
            "second_subject_governed_rows_accepted": second_code == 0,
            "governed_replay_refused_before_query": report.get(
                "replay_refused_before_query"
            )
            is True,
            "invalid_governed_receipt_refused": report.get(
                "invalid_receipt_refused"
            )
            is True,
            "changed_governed_result_refused": report.get("changed_result_refused")
            is True,
            "changed_governed_operand_receipt_refused": report.get(
                "changed_operand_receipt_refused"
            )
            is True,
        }
    )
    return security


def run_boundary(
    process: int,
    boundary: str,
    postgres: str,
    connection: str,
    endpoint: str,
    token_path: Path,
    public_key: Path,
    custody: Path,
) -> list[dict]:
    cases = []
    boundary_index = BOUNDARIES.index(boundary)
    boundary_custody = custody / boundary
    boundary_custody.mkdir(mode=0o700, exist_ok=True)
    for concurrency_index, concurrency in enumerate(production.campaign.CONCURRENCY_LEVELS):
        order = arm_order(process, concurrency_index, boundary_index)
        measurements = {}
        for arm in order:
            resources_before = production.container_resource_snapshot(postgres)
            host_idle = production.campaign.await_quiet_host()
            production.campaign.v72.psql(postgres, "SELECT pg_stat_statements_reset()")
            measurement = cumulative.run_load_arm_attributed(
                arm,
                concurrency,
                connection,
                endpoint,
                token_path,
                public_key,
                boundary_custody,
                postgres,
            )
            add_relevant_stack_cpu(measurement, postgres, boundary, arm)
            resources_after = production.container_resource_snapshot(postgres)
            observed_queries = production.campaign.v72.data_queries(postgres)
            expected_queries = production.campaign.expected_data_queries(arm, concurrency)
            measurement["observed_data_queries"] = observed_queries
            measurement["expected_data_queries"] = expected_queries
            measurement["query_gate_passed"] = observed_queries == expected_queries
            measurement["host_idle_preflight"] = host_idle
            measurement["container_resources_before"] = resources_before
            measurement["container_resources_after"] = resources_after
            try:
                production.campaign.validate_arm_measurement(measurement, arm, concurrency)
            except ValueError as error:
                worker_errors = json.dumps(
                    measurement.get("errors", []), sort_keys=True, separators=(",", ":")
                )
                raise ValueError(
                    f"{boundary} {arm} concurrency {concurrency} failed: {error}; "
                    f"worker_errors={worker_errors}"
                ) from error
            production.validate_container_resource_snapshot(resources_before)
            production.validate_container_resource_snapshot(resources_after)
            validate_request_byte_evidence(measurement, arm)
            cumulative.validate_container_cpu_snapshot(measurement["container_cpu_before"])
            cumulative.validate_container_cpu_snapshot(measurement["container_cpu_after"])
            production.require(
                measurement["total_relevant_stack_cpu_ns"]
                == measurement["total_client_cpu_ns"]
                + measurement["relevant_container_cpu_ns"],
                "the relevant stack CPU total changed",
            )
            measurements[arm] = measurement
        comparison = compare_measurements(measurements, concurrency)
        cases.append(
            {
                "arm_order": order,
                "boundary": boundary,
                "comparison": comparison,
                "concurrency": concurrency,
                "measurements": measurements,
                "passed": comparison["passed"],
            }
        )
    return cases


def run_process(
    process: int,
    postgres: str,
    pooled_connection: str,
    endpoint: str,
    token_path: Path,
    public_key: Path,
    custody: Path,
) -> dict:
    direct = direct_connection(postgres)
    component_profiles = {
        "direct": run_component_probe(direct, token_path, public_key),
        "supavisor": run_component_probe(pooled_connection, token_path, public_key),
    }
    cases = run_boundary(
        process, "direct", postgres, direct, endpoint, token_path, public_key, custody
    )
    cases.extend(
        run_boundary(
            process,
            "supavisor",
            postgres,
            pooled_connection,
            endpoint,
            token_path,
            public_key,
            custody,
        )
    )
    return {
        "cases": cases,
        "component_profiles": component_profiles,
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
    component_profiles = report.get("component_profiles")
    production.require(
        isinstance(component_profiles, dict)
        and set(component_profiles) == set(BOUNDARIES),
        "the component boundaries changed",
    )
    for component_report in component_profiles.values():
        validate_component_report(component_report)
    expected_count = len(BOUNDARIES) * len(production.campaign.CONCURRENCY_LEVELS)
    production.require(
        isinstance(cases, list) and len(cases) == expected_count,
        "the process cases are invalid",
    )
    for boundary_index, boundary in enumerate(BOUNDARIES):
        for concurrency_index, concurrency in enumerate(production.campaign.CONCURRENCY_LEVELS):
            case = next(
                (
                    item
                    for item in cases
                    if item.get("boundary") == boundary
                    and item.get("concurrency") == concurrency
                ),
                None,
            )
            production.require(isinstance(case, dict), "a boundary case is absent")
            expected_order = arm_order(process, concurrency_index, boundary_index)
            production.require(case.get("arm_order") == expected_order, "arm order changed")
            measurements = case.get("measurements")
            production.require(
                isinstance(measurements, dict) and set(measurements) == set(ARMS),
                "the measurement arms changed",
            )
            for arm in ARMS:
                measurement = measurements[arm]
                production.campaign.validate_arm_measurement(
                    measurement, arm, concurrency
                )
                validate_request_byte_evidence(measurement, arm)
                delta = cumulative.container_cpu_delta(
                    measurement.get("container_cpu_before"),
                    measurement.get("container_cpu_after"),
                )
                production.require(
                    measurement.get("container_cpu_delta") == delta,
                    "the container CPU delta changed",
                )
                names = measurement.get("relevant_container_names")
                production.require(
                    isinstance(names, list) and names == sorted(set(names)) and names,
                    "the relevant container set changed",
                )
                relevant_cpu = sum(
                    record["UsageNS"]
                    for record in delta["containers"]
                    if record["Name"] in names
                )
                production.require(
                    measurement.get("relevant_container_cpu_ns") == relevant_cpu,
                    "the relevant container CPU total changed",
                )
                production.require(
                    measurement.get("total_relevant_stack_cpu_ns")
                    == measurement["total_client_cpu_ns"] + relevant_cpu,
                    "the relevant stack CPU total changed",
                )
            expected = compare_measurements(measurements, concurrency)
            production.require(case.get("comparison") == expected, "comparison changed")
            production.require(case.get("passed") is expected["passed"], "verdict changed")
    production.require(
        report.get("passed") is all(case["passed"] for case in cases),
        "the process verdict changed",
    )


def campaign_summary(processes: list[dict]) -> list[dict]:
    summary = []
    for boundary in BOUNDARIES:
        component_reports = [
            process["component_profiles"][boundary] for process in processes
        ]
        component_cpu_ns_per_sample = {
            key: statistics.median(
                report["components"][key]["cpu_ns"] / report["samples"]
                for report in component_reports
            )
            for key in sorted(COMPONENT_KEYS)
        }
        component_wall_ns_per_sample = {
            key: statistics.median(
                report["components"][key]["wall_ns"] / report["samples"]
                for report in component_reports
            )
            for key in sorted(COMPONENT_KEYS)
        }
        fixed_component_cpu_ns_per_sample = {
            str(result_bytes): {
                key: statistics.median(
                    next(
                        profile
                        for profile in report["fixed_profiles"]
                        if profile["result_bytes"] == result_bytes
                    )["components"][key]["cpu_ns"]
                    / report["samples"]
                    for report in component_reports
                )
                for key in sorted(FIXED_COMPONENT_KEYS)
            }
            for result_bytes in FIXED_RESULT_BYTES
        }
        for concurrency in production.campaign.CONCURRENCY_LEVELS:
            cases = [
                next(
                    case
                    for case in process["cases"]
                    if case["boundary"] == boundary
                    and case["concurrency"] == concurrency
                )
                for process in processes
            ]
            comparisons = [case["comparison"] for case in cases]
            p95_ratios = [item["ndabi_p95_to_governed"] for item in comparisons]
            variation = (
                ratio(max(p95_ratios), min(p95_ratios)) - 1.0 if p95_ratios else math.inf
            )
            summary.append(
                {
                    "all_repetitions_passed": all(case["passed"] for case in cases),
                    "boundary": boundary,
                    "component_cpu_ns_per_sample": component_cpu_ns_per_sample,
                    "component_result_bytes": component_reports[0]["result_bytes"],
                    "component_wall_ns_per_sample": component_wall_ns_per_sample,
                    "concurrency": concurrency,
                    "fixed_component_cpu_ns_per_sample": fixed_component_cpu_ns_per_sample,
                    "median_ndabi_client_cpu_to_governed": statistics.median(
                        item["ndabi_client_cpu_to_governed"] for item in comparisons
                    ),
                    "median_ndabi_p95_to_governed": statistics.median(p95_ratios),
                    "median_ndabi_stack_cpu_to_governed": statistics.median(
                        item["ndabi_stack_cpu_to_governed"] for item in comparisons
                    ),
                    "p95_ratio_variation": variation,
                    "p95_ratio_variation_limit": 0.10,
                    "repeatability_passed": variation <= 0.10,
                }
            )
    return summary


def repeatability(processes: list[dict]) -> tuple[list[dict], bool]:
    production.require(
        len(processes) == production.PROCESS_COUNT,
        "the v8.5 repetition count changed",
    )
    evidence = []
    passed = True
    for boundary in BOUNDARIES:
        for concurrency in production.campaign.CONCURRENCY_LEVELS:
            cases = [
                next(
                    case
                    for case in process["cases"]
                    if case["boundary"] == boundary
                    and case["concurrency"] == concurrency
                )
                for process in processes
            ]
            values = [case["comparison"]["ndabi_p95_to_governed"] for case in cases]
            variation = ratio(max(values), min(values)) - 1.0
            item_passed = all(case["passed"] for case in cases) and variation <= 0.10
            evidence.append(
                {
                    "boundary": boundary,
                    "concurrency": concurrency,
                    "p95_ratio_variation": variation,
                    "p95_ratio_variation_limit": 0.10,
                    "passed": item_passed,
                }
            )
            passed &= item_passed
    return evidence, passed


def configure(
    *,
    build_binary: bool = True,
    functional: bool = False,
    result_root: Path | None = None,
) -> None:
    target_root = result_root or RESULT_ROOT
    BASE_CONFIGURE(
        build_binary=build_binary, functional=functional, result_root=target_root
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
    cumulative.WORKER_SCHEMA = WORKER_SCHEMA

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
    campaign.samples_for = samples_for
    campaign.WORKER_SCHEMA = WORKER_SCHEMA
    campaign.SOURCE_PATHS = SOURCE_PATHS
    campaign.SECURITY_CHECK_COUNT = SECURITY_CHECK_COUNT
    campaign.MINIMUM_ARM_DURATION_NS = 0 if functional else MINIMUM_ARM_DURATION_NS
    campaign.v72.security_checks = security_checks
    campaign.run_process = run_process
    campaign.validate_process_report = validate_process_report
    campaign.campaign_summary = campaign_summary
    campaign.repeatability = repeatability
    campaign.SMOKE_RESULT_PATH = (
        RESULT_ROOT / "functional-latest.json"
        if functional
        else RESULT_ROOT / "performance-smoke-latest.json"
    )


def restore_configuration_mutations() -> None:
    production.campaign.samples_for = BASE_SAMPLES_FOR
    cumulative.WORKER_SCHEMA = BASE_CUMULATIVE_WORKER_SCHEMA


production.RESULT_ROOT = RESULT_ROOT
production.FORMAL_CAMPAIGN_NAME = FORMAL_CAMPAIGN_NAME
production.CAMPAIGN_VERSION = CAMPAIGN_VERSION
production.ENTRYPOINT = Path(__file__).resolve()


if __name__ == "__main__":
    production.configure = configure
    raise SystemExit(production.main())
