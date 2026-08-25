#!/usr/bin/env python3
"""Run the attributed incremental-receipt Supabase campaign."""

from __future__ import annotations

import json
import math
import statistics
from pathlib import Path

import validation_suite_v80 as production
import validation_suite_v81 as duration_repair


ROOT = Path(__file__).resolve().parent
RESULT_ROOT = ROOT / "results" / "v82"
CAMPAIGN_NAME = "NDABI Supabase attributed CPU stack v8.2"
CAMPAIGN_LABEL = "v8.2 stack"
FORMAL_CAMPAIGN_NAME = "NDABI Supabase attributed CPU campaign v8.2"
CAMPAIGN_VERSION = "v8.2"
TENANT_ID = "ndabi-v82"
SESSION_PROOF_LABEL = "ndabi-v82-session-proof"
SESSION_PROOF_EXPECTED = "82"
ARMS = (
    "native",
    "ndabi_incremental",
    "ndabi_incremental_server",
    "ndabi",
    "postgrest_rpc",
    "postgrest",
)
ARM_IDENTIFIERS = {
    "native": "native-indexed-batch-session",
    "ndabi_incremental": "ndabi-incremental-receipt-session",
    "ndabi_incremental_server": "ndabi-incremental-server-session",
    "ndabi": "ndabi-indexed-batch-session",
    "postgrest_rpc": "postgrest-rpc-user-jwt",
    "postgrest": "postgrest-user-jwt",
}
QUERY_MULTIPLIERS = {
    "native": 1,
    "ndabi_incremental": 1,
    "ndabi_incremental_server": 1,
    "ndabi": 1,
    "postgrest_rpc": 1,
    "postgrest": production.campaign.OPERATIONS,
}
SAMPLES_BY_ARM = {
    "native": 8_191,
    "ndabi_incremental": 8_191,
    "ndabi_incremental_server": 8_191,
    "ndabi": 8_191,
    "postgrest_rpc": 2_047,
    "postgrest": 255,
}
FUNCTIONAL_SAMPLES_BY_ARM = {arm: 3 for arm in ARMS}
REQUEST_BYTES_KINDS = {
    "native": "unavailable-postgresql-driver-wire",
    "ndabi_incremental": "exact-ndabi-frame",
    "ndabi_incremental_server": "exact-ndabi-frame",
    "ndabi": "exact-ndabi-frame",
    "postgrest_rpc": "exact-json-body",
    "postgrest": "calculated-http-lower-bound",
}
WORKER_SCHEMA = "ndabi-supavisor-load-worker-v8.2"
SECURITY_CHECK_COUNT = 23
SOURCE_PATHS = duration_repair.SOURCE_PATHS + (
    "validation_suite_v82.py",
    "requirements-v82.txt",
    "tests/test_validation_v82.py",
    "../../specs/ndabi_incremental_receipt_profile_v0_1.md",
    "../../specs/ndabi_supabase_cpu_attribution_campaign_v8_2.md",
)
BASE_CONFIGURE = duration_repair.configure
BASE_SECURITY_CHECKS = production.LEGACY_SECURITY_CHECKS


def ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else math.inf


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
    incremental = measurements["ndabi_incremental"]
    server = measurements["ndabi_incremental_server"]
    legacy = measurements["ndabi"]
    rpc = measurements["postgrest_rpc"]
    repeated = measurements["postgrest"]
    native_cpu = production._cpu_per_operation(native)
    incremental_cpu = production._cpu_per_operation(incremental)
    server_cpu = production._cpu_per_operation(server)
    legacy_cpu = production._cpu_per_operation(legacy)

    throughput_native = ratio(
        incremental["logical_operations_per_second"],
        native["logical_operations_per_second"],
    )
    throughput_repeated = ratio(
        incremental["logical_operations_per_second"],
        repeated["logical_operations_per_second"],
    )
    throughput_rpc = ratio(
        incremental["logical_operations_per_second"],
        rpc["logical_operations_per_second"],
    )
    p50_native = ratio(incremental["p50_request_ns"], native["p50_request_ns"])
    p95_native = ratio(incremental["p95_request_ns"], native["p95_request_ns"])
    cpu_native = ratio(incremental_cpu, native_cpu)
    server_cpu_native = ratio(server_cpu, native_cpu)
    cpu_legacy = ratio(incremental_cpu, legacy_cpu)
    performance = (
        throughput_native >= 0.85
        and p50_native <= 1.20
        and cpu_native <= 1.25
        and server_cpu_native <= 1.10
        and cpu_legacy <= 0.95
        and throughput_repeated >= 5.0
        and incremental["p95_request_ns"] <= 25_000_000
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
        "estimated_client_receipt_cpu_ns_per_operation": incremental_cpu - server_cpu,
        "incremental_cpu_to_legacy": cpu_legacy,
        "incremental_cpu_to_legacy_limit": 0.95,
        "ndabi_cpu_to_native": cpu_native,
        "ndabi_cpu_to_native_limit": 1.25,
        "ndabi_incremental_server_cpu_to_native": server_cpu_native,
        "ndabi_incremental_server_cpu_to_native_limit": 1.10,
        "ndabi_p50_to_native": p50_native,
        "ndabi_p50_to_native_limit": 1.20,
        "ndabi_p95_limit_ns": 25_000_000,
        "ndabi_p95_to_native": p95_native,
        "ndabi_throughput_over_native": throughput_native,
        "ndabi_throughput_over_native_minimum": 0.85,
        "ndabi_throughput_over_postgrest": throughput_repeated,
        "ndabi_throughput_over_postgrest_minimum": 5.0,
        "ndabi_throughput_over_postgrest_rpc": throughput_rpc,
        "performance_gates_enforced": production.ENFORCE_PERFORMANCE,
        "performance_gates_passed": performance,
        "passed": passed,
    }


def campaign_summary(processes: list[dict]) -> list[dict]:
    summary = []
    for concurrency in production.campaign.CONCURRENCY_LEVELS:
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
                "all_repetitions_passed": all(case["passed"] for case in cases),
                "concurrency": concurrency,
                "median_estimated_client_receipt_cpu_ns_per_operation": statistics.median(
                    item["estimated_client_receipt_cpu_ns_per_operation"]
                    for item in comparisons
                ),
                "median_incremental_cpu_to_legacy": statistics.median(
                    item["incremental_cpu_to_legacy"] for item in comparisons
                ),
                "median_ndabi_cpu_to_native": statistics.median(
                    item["ndabi_cpu_to_native"] for item in comparisons
                ),
                "median_ndabi_incremental_server_cpu_to_native": statistics.median(
                    item["ndabi_incremental_server_cpu_to_native"]
                    for item in comparisons
                ),
                "median_ndabi_p50_to_native": statistics.median(
                    item["ndabi_p50_to_native"] for item in comparisons
                ),
                "median_ndabi_p95_ns": int(
                    statistics.median(
                        item["p95_request_ns"]
                        for item in measurements["ndabi_incremental"]
                    )
                ),
                "median_native_p95_ns": int(
                    statistics.median(
                        item["p95_request_ns"] for item in measurements["native"]
                    )
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
    completed = production.campaign.command(
        str(production.campaign.BINARY),
        "--ndabi-incremental-probe",
        pooled_connection,
        str(token_paths["valid"]),
        str(public_key),
        production.campaign.v72.v71.KEY_ID,
        production.campaign.v72.v71.ISSUER,
        production.campaign.v72.v71.AUDIENCE,
        "1000",
        "2",
        check=False,
    )
    try:
        report = json.loads(completed.stdout) if completed.returncode == 0 else {}
    except json.JSONDecodeError:
        report = {}
    security.update(
        {
            "incremental_authorised_rows_accepted": completed.returncode == 0,
            "incremental_changed_frame_refused": report.get("changed_frame_refused") is True,
            "incremental_changed_result_refused": report.get("changed_result_refused") is True,
            "incremental_invalid_receipt_refused": report.get("invalid_receipt_refused") is True,
            "incremental_replay_refused_before_query": report.get("replay_refused_before_query")
            is True,
            "incremental_valid_result_accepted": report.get("valid_result_accepted") is True,
        }
    )
    return security


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

    production.campaign.RESULT_ROOT = target_root
    production.campaign.CAMPAIGN_NAME = CAMPAIGN_NAME
    production.campaign.CAMPAIGN_LABEL = CAMPAIGN_LABEL
    production.campaign.TENANT_ID = TENANT_ID
    production.campaign.SESSION_PROOF_LABEL = SESSION_PROOF_LABEL
    production.campaign.SESSION_PROOF_EXPECTED = SESSION_PROOF_EXPECTED
    production.campaign.ARMS = ARMS
    production.campaign.ARM_IDENTIFIERS = ARM_IDENTIFIERS
    production.campaign.QUERY_MULTIPLIERS = QUERY_MULTIPLIERS
    production.campaign.SAMPLES_BY_ARM = (
        FUNCTIONAL_SAMPLES_BY_ARM if functional else SAMPLES_BY_ARM
    )
    production.campaign.WORKER_SCHEMA = WORKER_SCHEMA
    production.campaign.SOURCE_PATHS = SOURCE_PATHS
    production.campaign.SECURITY_CHECK_COUNT = SECURITY_CHECK_COUNT
    production.campaign.v72.security_checks = security_checks
    production.campaign.campaign_summary = campaign_summary
    production.campaign.SMOKE_RESULT_PATH = (
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
