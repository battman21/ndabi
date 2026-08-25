#!/usr/bin/env python3
"""Run the frozen canonical PostgreSQL batch v6.1 campaign once."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import struct
import subprocess
import time
from pathlib import Path

import validation_suite_v44 as shared


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v61"
POSTGRES_IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
RESULT_ROOT = ROOT / "results" / "v61"
PROCESS_COUNT = 5
SAMPLES = 31
WARMUPS = 5
CASES = {32: {"speed": 10.0, "cpu": 8.0}, 128: {"speed": 25.0, "cpu": 20.0}}
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-protocol/Cargo.toml",
    "crates/ndabi-protocol/src/lib.rs",
    "crates/ndabi-protocol/src/batch.rs",
    "crates/ndabi-protocol/src/replay.rs",
    "crates/ndabi-postgres-v1/Cargo.toml",
    "crates/ndabi-postgres-v1/src/lib.rs",
    "src/bin/ndabi_v61.rs",
    "validation_suite_v61.py",
    "../../specs/ndabi_canonical_postgresql_batch_campaign_v6_1.md",
)


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = (ROOT / relative).resolve()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil((len(ordered) - 1) * quantile)]


def measurement(case: dict, arm: str) -> dict:
    return next(item for item in case["measurements"] if item["arm"] == arm)


def expected_result(count: int) -> bytes:
    start = 1_000 if count == 32 else 5_000
    output = bytearray(struct.pack("<HI", 1, count))
    for identifier in range(start, start + count):
        output.extend(
            struct.pack(
                "<qiii64s",
                identifier,
                identifier % 1_000,
                identifier % 100,
                identifier % 10_000,
                bytes([identifier % 256]) * 64,
            )
        )
    return bytes(output)


def validate_report(report: dict) -> None:
    if report.get("campaign") != "NDABI canonical PostgreSQL batch v6.1":
        raise ValueError("the campaign identity changed")
    if report.get("samples") != SAMPLES or report.get("warmups") != WARMUPS:
        raise ValueError("the sample plan changed")
    cases = report.get("cases")
    if not isinstance(cases, list) or {item.get("operation_count") for item in cases} != set(CASES):
        raise ValueError("the case matrix changed")
    for case in cases:
        count = case["operation_count"]
        expected = CASES[count]
        arms = {item.get("arm") for item in case.get("measurements", [])}
        if arms != {"sequential-canonical", "batch-canonical", "native-fused"}:
            raise ValueError("the measurement arms changed")
        for item in case["measurements"]:
            raw_wall = item.get("raw_ns")
            raw_cpu = item.get("raw_cpu_ns")
            if not isinstance(raw_wall, list) or len(raw_wall) != SAMPLES:
                raise ValueError("the wall samples are incomplete")
            if not isinstance(raw_cpu, list) or len(raw_cpu) != SAMPLES:
                raise ValueError("the CPU samples are incomplete")
            if any(not isinstance(value, int) or value <= 0 for value in raw_wall + raw_cpu):
                raise ValueError("a timing sample is invalid")
            if item["p50_ns"] != percentile(raw_wall, 0.50):
                raise ValueError("the wall median changed")
            if item["p95_ns"] != percentile(raw_wall, 0.95):
                raise ValueError("the wall p95 changed")
            if item["p99_ns"] != percentile(raw_wall, 0.99):
                raise ValueError("the wall p99 changed")
            if item["p50_cpu_ns"] != percentile(raw_cpu, 0.50):
                raise ValueError("the CPU median changed")
        sequential = measurement(case, "sequential-canonical")
        batch = measurement(case, "batch-canonical")
        native = measurement(case, "native-fused")
        expected_bytes = expected_result(count)
        checks = [
            case["sequential_frame_bytes"] == 160 * count,
            case["batch_frame_bytes"] == 160 + 20 * count,
            math.isclose(
                case["request_compression"],
                1.0 - case["batch_frame_bytes"] / case["sequential_frame_bytes"],
                rel_tol=1e-12,
            ),
            case["sequential_data_queries"] == (SAMPLES + WARMUPS) * count,
            case["batch_data_queries"] == SAMPLES + WARMUPS,
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
                case["batch_native_cpu_distance"],
                batch["p50_cpu_ns"] / native["p50_cpu_ns"],
                rel_tol=1e-12,
            ),
            case["request_compression"] >= 0.80,
            case["p95_speedup"] >= expected["speed"],
            case["cpu_p50_speedup"] >= expected["cpu"],
            case["batch_native_p95_distance"] <= 1.25,
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


def coefficient_of_variation(values: list[float]) -> float:
    mean = statistics.mean(values)
    return statistics.pstdev(values) / mean


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v6.1 formal campaign already exists")
    if not BINARY.is_file():
        raise SystemExit("build the ndabi_v61 release binary before the campaign")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    container = f"ndabi-v61-postgres-{suffix}"
    reports = []
    encoded = None
    accepted = False
    try:
        command(
            "docker",
            "run",
            "--detach",
            "--name",
            container,
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_PASSWORD=ndabi-test-only",
            "--env",
            "POSTGRES_DB=ndabi",
            POSTGRES_IMAGE,
        )
        for _ in range(60):
            ready = command(
                "docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "ndabi", check=False
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgreSQL did not become ready")
        setup = (
            "CREATE ROLE ndabi_reader NOINHERIT LOGIN PASSWORD 'reader-test-only';"
            "ALTER ROLE ndabi_reader SET default_transaction_read_only=on;"
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
            "CREATE TABLE ndabi_v61_items(id bigint PRIMARY KEY,bucket integer NOT NULL,"
            "owner integer NOT NULL,score integer NOT NULL,payload bytea NOT NULL);"
            "INSERT INTO ndabi_v61_items SELECT id,(id%1000)::integer,(id%100)::integer,"
            "(id%10000)::integer,decode(repeat(lpad(to_hex((id%256)::integer),2,'0'),64),'hex') "
            "FROM generate_series(1,10000) AS id;"
            "GRANT USAGE ON SCHEMA public TO ndabi_reader;"
            "GRANT SELECT ON ndabi_v61_items TO ndabi_reader;"
        )
        command(
            "docker", "exec", container, "psql", "-U", "postgres", "-d", "ndabi",
            "-v", "ON_ERROR_STOP=1", "-c", setup,
        )
        port = command("docker", "port", container, "5432/tcp").stdout.strip().rsplit(":", 1)[1]
        connection = (
            f"host=127.0.0.1 port={port} user=ndabi_reader "
            "password=reader-test-only dbname=ndabi"
        )
        role_state = command(
            "docker", "exec", "--env", "PGPASSWORD=reader-test-only", container,
            "psql", "-h", "127.0.0.1", "-U", "ndabi_reader", "-d", "ndabi", "-At",
            "-c", "SHOW default_transaction_read_only",
        ).stdout.strip()
        write = command(
            "docker", "exec", "--env", "PGPASSWORD=reader-test-only", container,
            "psql", "-h", "127.0.0.1", "-U", "ndabi_reader", "-d", "ndabi",
            "-v", "ON_ERROR_STOP=1", "-c", "INSERT INTO ndabi_v61_items VALUES (10001,1,1,1,'\\x00')",
            check=False,
        )
        binary_digest = shared.sha256(BINARY)
        source_digest = source_sha256()
        image_id = command(
            "docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE
        ).stdout.strip()
        for process in range(1, PROCESS_COUNT + 1):
            completed = command(str(BINARY), connection, check=False)
            if completed.returncode != 0:
                raise RuntimeError("the canonical PostgreSQL batch process failed")
            report = json.loads(completed.stdout)
            validate_report(report)
            report.update(
                process=process,
                reader_role_read_only=role_state == "on",
                reader_write_refused=write.returncode != 0,
                binary_sha256=binary_digest,
                source_sha256=source_digest,
                postgres_image_id=image_id,
            )
            report["passed"] = (
                report["passed"]
                and report["reader_role_read_only"]
                and report["reader_write_refused"]
            )
            (campaign / f"process-{process}.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            reports.append(report)
        summaries = []
        repeatability_passed = True
        for count in CASES:
            case_reports = [
                next(item for item in report["cases"] if item["operation_count"] == count)
                for report in reports
            ]
            distances = [item["batch_native_p95_distance"] for item in case_reports]
            variation = coefficient_of_variation(distances)
            repeatability_passed &= variation < 0.20
            summaries.append(
                {
                    "operation_count": count,
                    "p95_speedup": {
                        "minimum": min(item["p95_speedup"] for item in case_reports),
                        "median": statistics.median(item["p95_speedup"] for item in case_reports),
                        "maximum": max(item["p95_speedup"] for item in case_reports),
                    },
                    "cpu_p50_speedup": {
                        "minimum": min(item["cpu_p50_speedup"] for item in case_reports),
                        "median": statistics.median(item["cpu_p50_speedup"] for item in case_reports),
                        "maximum": max(item["cpu_p50_speedup"] for item in case_reports),
                    },
                    "batch_native_p95_distance": {
                        "minimum": min(distances),
                        "median": statistics.median(distances),
                        "maximum": max(distances),
                        "coefficient_of_variation": variation,
                    },
                    "request_compression": case_reports[0]["request_compression"],
                    "allocation_reduction": {
                        "minimum": min(item["allocation_reduction"] for item in case_reports),
                        "median": statistics.median(item["allocation_reduction"] for item in case_reports),
                    },
                    "allocated_bytes_reduction": {
                        "minimum": min(item["allocated_bytes_reduction"] for item in case_reports),
                        "median": statistics.median(item["allocated_bytes_reduction"] for item in case_reports),
                    },
                }
            )
        accepted = all(report["passed"] for report in reports) and repeatability_passed
        aggregate = {
            "campaign": "NDABI canonical PostgreSQL batch v6.1",
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            "binary_sha256": binary_digest,
            "source_sha256": source_digest,
            "postgres_image_id": image_id,
            "cases": summaries,
            "repeatability_passed": repeatability_passed,
            "accepted": accepted,
            "process_results": [
                str(path.relative_to(ROOT)) for path in sorted(campaign.glob("process-*.json"))
            ],
        }
        encoded = json.dumps(aggregate, indent=2) + "\n"
        (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
    finally:
        for _ in range(3):
            command("docker", "rm", "--force", container, check=False)
            absent = command("docker", "inspect", container, check=False)
            if absent.returncode != 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("the temporary PostgreSQL container remains")
    if encoded is None:
        raise RuntimeError("the canonical PostgreSQL batch aggregate is absent")
    latest.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
