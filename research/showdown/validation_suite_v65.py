#!/usr/bin/env python3
"""Run the frozen PostgreSQL transport performance campaign v6.5 once."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import struct
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v65"
POSTGRES_IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
RESULT_ROOT = ROOT / "results" / "v65"
PROCESS_COUNT = 5
ROWS = (1, 32, 128, 1_024)
STARTS = {1: 1_000, 32: 10_000, 128: 100_000, 1_024: 500_000}
ARMS = {"native-prepared", "canonical-v1", "canonical-v2-transport"}
SAMPLES = 63
WARMUPS = 7
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "src/alloc.rs",
    "src/bin/ndabi_v65.rs",
    "validation_suite_v65.py",
    "crates/ndabi-protocol/Cargo.toml",
    "crates/ndabi-protocol/src/lib.rs",
    "crates/ndabi-protocol/src/connection.rs",
    "crates/ndabi-protocol/src/replay.rs",
    "crates/ndabi-protocol/src/transport.rs",
    "crates/ndabi-postgres-v1/Cargo.toml",
    "crates/ndabi-postgres-v1/src/lib.rs",
    "../../specs/ndabi_postgresql_transport_performance_campaign_v6_5.md",
    "../../specs/ndabi_transport_candidate_v0_2.md",
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


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil((len(ordered) - 1) * quantile)]


def coefficient_of_variation(values: list[float]) -> float:
    mean = statistics.mean(values)
    return statistics.pstdev(values) / mean if mean else math.inf


def expected_result(rows: int) -> bytes:
    output = bytearray(struct.pack("<HI", 1, rows))
    start = STARTS[rows]
    for identifier in range(start, start + rows):
        output.extend(
            struct.pack(
                "<qiii",
                identifier,
                identifier % 1_000,
                identifier % 100,
                identifier % 10_000,
            )
        )
        output.extend(bytes([identifier % 256]) * 64)
    return bytes(output)


def measurement(case: dict, arm: str) -> dict:
    return next(item for item in case["measurements"] if item["arm"] == arm)


def validate_report(report: dict) -> None:
    if report.get("campaign") != "NDABI PostgreSQL transport performance v6.5":
        raise ValueError("the campaign identity changed")
    if report.get("samples") != SAMPLES or report.get("warmups") != WARMUPS:
        raise ValueError("the sample plan changed")
    cases = report.get("cases")
    if not isinstance(cases, list) or {item.get("rows") for item in cases} != set(ROWS):
        raise ValueError("the case matrix changed")
    for case in cases:
        rows = case["rows"]
        expected = expected_result(rows)
        if case.get("request_bytes") != 160:
            raise ValueError("the request size changed")
        if case.get("result_bytes") != len(expected):
            raise ValueError("the result size changed")
        if case.get("transport_result_frame_bytes") != len(expected) + 160:
            raise ValueError("the transport frame size changed")
        if case.get("result_sha256") != hashlib.sha256(expected).hexdigest():
            raise ValueError("the exact result changed")
        if case.get("data_queries") != [WARMUPS + SAMPLES] * 3:
            raise ValueError("a database query count changed")
        if case.get("expected_data_queries") != WARMUPS + SAMPLES:
            raise ValueError("the expected database query count changed")
        measurements = case.get("measurements")
        if not isinstance(measurements, list) or {item.get("arm") for item in measurements} != ARMS:
            raise ValueError("the measurement arms changed")
        for item in measurements:
            raw_wall = item.get("raw_ns")
            raw_cpu = item.get("raw_cpu_ns")
            if not isinstance(raw_wall, list) or len(raw_wall) != SAMPLES:
                raise ValueError("the wall samples are incomplete")
            if not isinstance(raw_cpu, list) or len(raw_cpu) != SAMPLES:
                raise ValueError("the CPU samples are incomplete")
            if any(not isinstance(value, int) or value <= 0 for value in raw_wall + raw_cpu):
                raise ValueError("a timing sample is invalid")
            if item.get("p50_ns") != percentile(raw_wall, 0.50):
                raise ValueError("the wall median changed")
            if item.get("p95_ns") != percentile(raw_wall, 0.95):
                raise ValueError("the wall p95 changed")
            if item.get("p99_ns") != percentile(raw_wall, 0.99):
                raise ValueError("the wall p99 changed")
            if item.get("p50_cpu_ns") != percentile(raw_cpu, 0.50):
                raise ValueError("the CPU median changed")
        native = measurement(case, "native-prepared")
        v1 = measurement(case, "canonical-v1")
        v2 = measurement(case, "canonical-v2-transport")
        ratios = {
            "v1_native_p50_distance": v1["p50_ns"] / native["p50_ns"],
            "v2_native_p50_distance": v2["p50_ns"] / native["p50_ns"],
            "v2_v1_p50_distance": v2["p50_ns"] / v1["p50_ns"],
            "v2_v1_p95_distance": v2["p95_ns"] / v1["p95_ns"],
            "v2_v1_cpu_distance": v2["p50_cpu_ns"] / v1["p50_cpu_ns"],
        }
        for name, expected_ratio in ratios.items():
            if not math.isclose(case.get(name), expected_ratio, rel_tol=1e-12):
                raise ValueError(f"the {name} ratio changed")
        gates = (
            ratios["v1_native_p50_distance"] <= 1.25,
            ratios["v2_native_p50_distance"] <= 1.35,
            ratios["v2_v1_p50_distance"] <= 1.25,
            ratios["v2_v1_cpu_distance"] <= 1.50,
        )
        if case.get("passed") is not all(gates):
            raise ValueError("the case verdict changed")
    security = report.get("security")
    if not isinstance(security, dict):
        raise ValueError("the security report is absent")
    security_names = (
        "request_mutation_refused",
        "replay_refused_before_query",
        "invalid_receipt_refused",
        "invalid_receipt_preserved_pending_request",
        "reflected_result_refused",
        "valid_result_accepted_after_refusals",
    )
    security_passed = all(security.get(name) is True for name in security_names)
    security_passed &= security.get("successful_data_queries") == 1
    if security.get("passed") is not security_passed:
        raise ValueError("the security verdict changed")
    expected_passed = all(case["passed"] for case in cases) and security_passed
    if report.get("passed") is not expected_passed:
        raise ValueError("the process verdict changed")


def psql(container: str, statement: str, user: str = "postgres", password: str | None = None) -> subprocess.CompletedProcess:
    arguments = ["docker", "exec"]
    if password is not None:
        arguments.extend(["--env", f"PGPASSWORD={password}"])
    arguments.extend(
        [container, "psql", "-h", "127.0.0.1", "-U", user, "-d", "ndabi", "-At", "-v", "ON_ERROR_STOP=1", "-c", statement]
    )
    return command(*arguments)


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v6.5 formal campaign already exists")
    if not BINARY.exists():
        raise SystemExit("build the ndabi_v65 release binary before the campaign")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    postgres = f"ndabi-v65-postgres-{time.time_ns()}"
    reports: list[dict] = []
    try:
        command(
            "docker",
            "run",
            "--detach",
            "--name",
            postgres,
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
                "docker", "exec", postgres, "pg_isready", "-U", "postgres", "-d", "ndabi", check=False
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgreSQL did not become ready")
        statements = (
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
            "CREATE ROLE ndabi_service NOINHERIT LOGIN PASSWORD 'service-test-only'",
            "ALTER ROLE ndabi_service SET default_transaction_read_only=on",
            "CREATE TABLE ndabi_v65_items(id bigint PRIMARY KEY,bucket integer NOT NULL,owner integer NOT NULL,score integer NOT NULL,payload bytea NOT NULL)",
            "INSERT INTO ndabi_v65_items SELECT value,(value%1000)::integer,(value%100)::integer,(value%10000)::integer,decode(repeat(lpad(to_hex(value%256),2,'0'),64),'hex') FROM generate_series(1,1000000) AS value",
            "ANALYZE ndabi_v65_items",
            "GRANT USAGE ON SCHEMA public TO ndabi_service",
            "GRANT SELECT ON ndabi_v65_items TO ndabi_service",
        )
        for statement in statements:
            psql(postgres, statement)
        role_state = psql(
            postgres,
            "SELECT rolsuper,rolcreaterole,rolcreatedb,rolcanlogin FROM pg_roles WHERE rolname='ndabi_service'",
        ).stdout.strip()
        read_only_state = psql(
            postgres,
            "SHOW default_transaction_read_only",
            user="ndabi_service",
            password="service-test-only",
        ).stdout.strip()
        write_attempt = command(
            "docker",
            "exec",
            "--env",
            "PGPASSWORD=service-test-only",
            postgres,
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            "ndabi_service",
            "-d",
            "ndabi",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "INSERT INTO ndabi_v65_items VALUES (1000001,1,1,1,decode(repeat('aa',64),'hex'))",
            check=False,
        )
        port = command("docker", "port", postgres, "5432/tcp").stdout.strip().rsplit(":", 1)[1]
        connection = (
            f"host=127.0.0.1 port={port} user=ndabi_service "
            "password=service-test-only dbname=ndabi"
        )
        for process in range(1, PROCESS_COUNT + 1):
            completed = command(str(BINARY), connection, check=False)
            try:
                report = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                report = {
                    "process": process,
                    "binary_exit_code": completed.returncode,
                    "parsed": False,
                    "validation_error": str(error),
                    "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
                    "passed": False,
                }
            else:
                report["process"] = process
                report["binary_exit_code"] = completed.returncode
                report["parsed"] = True
                report["stderr_sha256"] = hashlib.sha256(completed.stderr.encode()).hexdigest()
                validation_error = None
                try:
                    validate_report(report)
                except (KeyError, TypeError, ValueError) as error:
                    validation_error = str(error)
                report["validation_error"] = validation_error
                report["validated"] = validation_error is None
            (campaign / f"process-{process}.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            reports.append(report)

        repeatability = []
        repeatability_passed = len(reports) == PROCESS_COUNT and all(
            report.get("validated") for report in reports
        )
        if repeatability_passed:
            for rows in ROWS:
                cases = [next(case for case in report["cases"] if case["rows"] == rows) for report in reports]
                for name in (
                    "v1_native_p50_distance",
                    "v2_native_p50_distance",
                    "v2_v1_p50_distance",
                    "v2_v1_cpu_distance",
                ):
                    values = [case[name] for case in cases]
                    variation = coefficient_of_variation(values)
                    repeatability.append({"rows": rows, "ratio": name, "coefficient_of_variation": variation})
                    repeatability_passed &= variation < 0.10
        accepted = (
            repeatability_passed
            and all(report.get("passed") is True for report in reports)
            and all(report.get("binary_exit_code") == 0 for report in reports)
            and role_state == "f|f|f|t"
            and read_only_state == "on"
            and write_attempt.returncode != 0
        )
        aggregate = {
            "campaign": "NDABI PostgreSQL transport performance v6.5",
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            "source_sha256": source_sha256(),
            "binary_sha256": file_sha256(BINARY),
            "postgres_image_id": command(
                "docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE
            ).stdout.strip(),
            "service_role_least_privilege": role_state == "f|f|f|t",
            "service_role_read_only": read_only_state == "on",
            "service_write_refused": write_attempt.returncode != 0,
            "repeatability": repeatability,
            "repeatability_passed": repeatability_passed,
            "accepted": accepted,
        }
        encoded = json.dumps(aggregate, indent=2) + "\n"
        (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
        latest.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if accepted else 1
    finally:
        command("docker", "rm", "--force", postgres, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
