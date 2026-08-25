#!/usr/bin/env python3
"""Run the frozen PostgreSQL batch methodology repair v6.3 once."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from pathlib import Path

import validation_suite_v44 as shared
import validation_suite_v61 as base
import validation_suite_v62 as repair


ROOT = Path(__file__).resolve().parent
BUILD_TARGET = ROOT / "target" / "ndabi-v63"
BINARY = BUILD_TARGET / "release" / "ndabi_v61"
POSTGRES_IMAGE = base.POSTGRES_IMAGE
RESULT_ROOT = ROOT / "results" / "v63"
PROCESS_COUNT = base.PROCESS_COUNT
SOURCE_PATHS = repair.SOURCE_PATHS + (
    "validation_suite_v63.py",
    "../../specs/ndabi_canonical_postgresql_batch_campaign_v6_3.md",
)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = (ROOT / relative).resolve()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def validate_report(report: dict) -> None:
    if report.get("campaign") != "NDABI canonical PostgreSQL batch v6.3":
        raise ValueError("the campaign identity changed")
    if report.get("samples") != base.SAMPLES or report.get("warmups") != base.WARMUPS:
        raise ValueError("the sample plan changed")
    cases = report.get("cases")
    if not isinstance(cases, list) or {item.get("operation_count") for item in cases} != set(base.CASES):
        raise ValueError("the case matrix changed")
    for case in cases:
        count = case["operation_count"]
        expected = base.CASES[count]
        arms = {item.get("arm") for item in case.get("measurements", [])}
        if arms != {"sequential-canonical", "batch-canonical", "native-fused"}:
            raise ValueError("the measurement arms changed")
        for item in case["measurements"]:
            raw_wall = item.get("raw_ns")
            raw_cpu = item.get("raw_cpu_ns")
            if not isinstance(raw_wall, list) or len(raw_wall) != base.SAMPLES:
                raise ValueError("the wall samples are incomplete")
            if not isinstance(raw_cpu, list) or len(raw_cpu) != base.SAMPLES:
                raise ValueError("the CPU samples are incomplete")
            if any(not isinstance(value, int) or value <= 0 for value in raw_wall + raw_cpu):
                raise ValueError("a timing sample is invalid")
            if item["p50_ns"] != base.percentile(raw_wall, 0.50):
                raise ValueError("the wall median changed")
            if item["p95_ns"] != base.percentile(raw_wall, 0.95):
                raise ValueError("the wall p95 changed")
            if item["p99_ns"] != base.percentile(raw_wall, 0.99):
                raise ValueError("the wall p99 changed")
            if item["p50_cpu_ns"] != base.percentile(raw_cpu, 0.50):
                raise ValueError("the CPU median changed")
        sequential = base.measurement(case, "sequential-canonical")
        batch = base.measurement(case, "batch-canonical")
        native = base.measurement(case, "native-fused")
        expected_bytes = base.expected_result(count)
        checks = [
            case["sequential_frame_bytes"] == 160 * count,
            case["batch_frame_bytes"] == 160 + 20 * count,
            math.isclose(
                case["request_compression"],
                1.0 - case["batch_frame_bytes"] / case["sequential_frame_bytes"],
                rel_tol=1e-12,
            ),
            case["sequential_data_queries"] == (base.SAMPLES + base.WARMUPS) * count,
            case["batch_data_queries"] == base.SAMPLES + base.WARMUPS,
            case["response_bytes"] == len(expected_bytes),
            case["result_sha256"] == hashlib.sha256(expected_bytes).hexdigest(),
            case.get("receipts_valid") is True,
            math.isclose(case["p95_speedup"], sequential["p95_ns"] / batch["p95_ns"], rel_tol=1e-12),
            math.isclose(
                case["cpu_p50_speedup"],
                sequential["p50_cpu_ns"] / batch["p50_cpu_ns"],
                rel_tol=1e-12,
            ),
            math.isclose(
                case["batch_native_p95_distance"],
                batch["p95_ns"] / native["p95_ns"],
                rel_tol=1e-12,
            ),
            math.isclose(
                case["batch_native_p50_distance"],
                batch["p50_ns"] / native["p50_ns"],
                rel_tol=1e-12,
            ),
            math.isclose(
                case["batch_native_cpu_distance"],
                batch["p50_cpu_ns"] / native["p50_cpu_ns"],
                rel_tol=1e-12,
            ),
            case["request_compression"] >= 0.80,
            case["p95_speedup"] >= expected["speed"],
            case["cpu_p50_speedup"] >= expected["cpu"],
            case["batch_native_p50_distance"] <= 1.25,
            case["batch_native_cpu_distance"] <= 1.35,
            math.isclose(
                case["allocation_reduction"],
                1.0 - batch["mean_allocations"] / sequential["mean_allocations"],
                rel_tol=1e-12,
            ),
            math.isclose(
                case["allocated_bytes_reduction"],
                1.0 - batch["mean_allocated_bytes"] / sequential["mean_allocated_bytes"],
                rel_tol=1e-12,
            ),
            case["allocation_reduction"] >= 0.75,
            case["allocated_bytes_reduction"] >= 0.40,
            case.get("passed") is True,
        ]
        if not all(checks):
            raise ValueError(f"the {count}-operand hard gate failed")
    security = report.get("security", {})
    security_checks = [
        security.get("replay_refused"),
        security.get("mutation_refused"),
        security.get("inadequate_budget_refused_before_query"),
        security.get("noncanonical_order_refused_before_query"),
        security.get("successful_data_queries") == 1,
        security.get("passed"),
        report.get("passed"),
    ]
    if not all(security_checks):
        raise ValueError("the security gate failed")


def capture_process(
    process: int,
    connection: str,
    campaign: Path,
    custody: dict,
    reader_role_read_only: bool,
    reader_write_refused: bool,
) -> dict:
    child = base.command(str(BINARY), connection, check=False)
    try:
        report = json.loads(child.stdout)
    except json.JSONDecodeError as error:
        report = {
            "campaign": "NDABI canonical PostgreSQL batch v6.3",
            "process": process,
            "binary_exit_code": child.returncode,
            "json_parsed": False,
            "validation_passed": False,
            "validation_error": str(error),
            "stdout_sha256": repair.digest_text(child.stdout),
            "stderr_sha256": repair.digest_text(child.stderr),
            "passed": False,
        }
    else:
        validation_error = None
        try:
            validate_report(report)
        except (KeyError, TypeError, ValueError) as error:
            validation_error = str(error)
        report.update(
            process=process,
            binary_exit_code=child.returncode,
            json_parsed=True,
            validation_passed=validation_error is None,
            validation_error=validation_error,
            stderr_sha256=repair.digest_text(child.stderr),
        )
        report["passed"] = (
            report.get("passed") is True
            and child.returncode == 0
            and validation_error is None
            and reader_role_read_only
            and reader_write_refused
        )
    report.update(
        reader_role_read_only=reader_role_read_only,
        reader_write_refused=reader_write_refused,
        **custody,
    )
    (campaign / f"process-{process}.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def summarise(reports: list[dict]) -> tuple[list[dict], bool]:
    if len(reports) != PROCESS_COUNT or not all(report.get("passed") for report in reports):
        return [], False
    summaries = []
    repeatability_passed = True
    for count in base.CASES:
        cases = [
            next(item for item in report["cases"] if item["operation_count"] == count)
            for report in reports
        ]
        median_distances = [item["batch_native_p50_distance"] for item in cases]
        variation = base.coefficient_of_variation(median_distances)
        repeatability_passed &= variation < 0.10
        summaries.append(
            {
                "operation_count": count,
                "p95_speedup": {
                    "minimum": min(item["p95_speedup"] for item in cases),
                    "median": statistics.median(item["p95_speedup"] for item in cases),
                    "maximum": max(item["p95_speedup"] for item in cases),
                },
                "cpu_p50_speedup": {
                    "minimum": min(item["cpu_p50_speedup"] for item in cases),
                    "median": statistics.median(item["cpu_p50_speedup"] for item in cases),
                    "maximum": max(item["cpu_p50_speedup"] for item in cases),
                },
                "batch_native_p50_distance": {
                    "minimum": min(median_distances),
                    "median": statistics.median(median_distances),
                    "maximum": max(median_distances),
                    "coefficient_of_variation": variation,
                },
                "batch_native_p95_distance_diagnostic": {
                    "minimum": min(item["batch_native_p95_distance"] for item in cases),
                    "median": statistics.median(item["batch_native_p95_distance"] for item in cases),
                    "maximum": max(item["batch_native_p95_distance"] for item in cases),
                },
                "request_compression": cases[0]["request_compression"],
                "allocation_reduction": {
                    "minimum": min(item["allocation_reduction"] for item in cases),
                    "median": statistics.median(item["allocation_reduction"] for item in cases),
                },
                "allocated_bytes_reduction": {
                    "minimum": min(item["allocated_bytes_reduction"] for item in cases),
                    "median": statistics.median(item["allocated_bytes_reduction"] for item in cases),
                },
            }
        )
    return summaries, repeatability_passed


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v6.3 formal campaign already exists")
    base.command(
        "cargo", "build", "--release", "--bin", "ndabi_v61", "--locked",
        "--target-dir", str(BUILD_TARGET),
    )
    if not BINARY.is_file():
        raise SystemExit("the dedicated v6.3 release binary is missing")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    container = f"ndabi-v63-postgres-{time.time_ns()}"
    reports = []
    try:
        base.command(
            "docker", "run", "--detach", "--name", container,
            "--publish", "127.0.0.1::5432",
            "--env", "POSTGRES_PASSWORD=ndabi-test-only",
            "--env", "POSTGRES_DB=ndabi",
            POSTGRES_IMAGE,
        )
        for _ in range(60):
            ready = base.command(
                "docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "ndabi",
                check=False,
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgreSQL did not become ready")
        connection, reader_role_read_only, reader_write_refused = repair.setup_engine(container)
        custody = {
            "binary_sha256": shared.sha256(BINARY),
            "source_sha256": source_sha256(),
            "postgres_image_id": base.command(
                "docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE
            ).stdout.strip(),
        }
        for process in range(1, PROCESS_COUNT + 1):
            reports.append(
                capture_process(
                    process,
                    connection,
                    campaign,
                    custody,
                    reader_role_read_only,
                    reader_write_refused,
                )
            )
        summaries, repeatability_passed = summarise(reports)
        accepted = all(report.get("passed") for report in reports) and repeatability_passed
        aggregate = {
            "campaign": "NDABI canonical PostgreSQL batch methodology repair v6.3",
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            **custody,
            "cases": summaries,
            "repeatability_passed": repeatability_passed,
            "accepted": accepted,
            "process_results": [
                str(path.relative_to(ROOT)) for path in sorted(campaign.glob("process-*.json"))
            ],
        }
        encoded = json.dumps(aggregate, indent=2) + "\n"
        (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
        latest.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if accepted else 1
    finally:
        base.command("docker", "rm", "--force", container, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
