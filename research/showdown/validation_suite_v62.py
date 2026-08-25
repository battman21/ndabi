#!/usr/bin/env python3
"""Run the frozen PostgreSQL batch evidence-closure repair v6.2 once."""

from __future__ import annotations

import hashlib
import json
import statistics
import time
from pathlib import Path

import validation_suite_v44 as shared
import validation_suite_v61 as base


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v61"
POSTGRES_IMAGE = base.POSTGRES_IMAGE
RESULT_ROOT = ROOT / "results" / "v62"
PROCESS_COUNT = base.PROCESS_COUNT
SOURCE_PATHS = base.SOURCE_PATHS + (
    "validation_suite_v62.py",
    "../../specs/ndabi_canonical_postgresql_batch_campaign_v6_2.md",
)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = (ROOT / relative).resolve()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def remove_container(container: str) -> None:
    for _ in range(3):
        base.command("docker", "rm", "--force", container, check=False)
        absent = base.command("docker", "inspect", container, check=False)
        if absent.returncode != 0:
            return
        time.sleep(1)
    raise RuntimeError("the temporary PostgreSQL container remains")


def setup_engine(container: str) -> tuple[str, bool, bool]:
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
    base.command(
        "docker", "exec", container, "psql", "-U", "postgres", "-d", "ndabi",
        "-v", "ON_ERROR_STOP=1", "-c", setup,
    )
    port = base.command("docker", "port", container, "5432/tcp").stdout.strip().rsplit(":", 1)[1]
    connection = (
        f"host=127.0.0.1 port={port} user=ndabi_reader "
        "password=reader-test-only dbname=ndabi"
    )
    role_state = base.command(
        "docker", "exec", "--env", "PGPASSWORD=reader-test-only", container,
        "psql", "-h", "127.0.0.1", "-U", "ndabi_reader", "-d", "ndabi", "-At",
        "-c", "SHOW default_transaction_read_only",
    ).stdout.strip()
    write = base.command(
        "docker", "exec", "--env", "PGPASSWORD=reader-test-only", container,
        "psql", "-h", "127.0.0.1", "-U", "ndabi_reader", "-d", "ndabi",
        "-v", "ON_ERROR_STOP=1", "-c", "INSERT INTO ndabi_v61_items VALUES (10001,1,1,1,'\\x00')",
        check=False,
    )
    return connection, role_state == "on", write.returncode != 0


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
            "campaign": "NDABI canonical PostgreSQL batch v6.1",
            "process": process,
            "binary_exit_code": child.returncode,
            "json_parsed": False,
            "validation_passed": False,
            "validation_error": str(error),
            "stdout_sha256": digest_text(child.stdout),
            "stderr_sha256": digest_text(child.stderr),
            "passed": False,
        }
    else:
        validation_error = None
        try:
            base.validate_report(report)
        except (KeyError, TypeError, ValueError) as error:
            validation_error = str(error)
        report.update(
            process=process,
            binary_exit_code=child.returncode,
            json_parsed=True,
            validation_passed=validation_error is None,
            validation_error=validation_error,
            stderr_sha256=digest_text(child.stderr),
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
        distances = [item["batch_native_p95_distance"] for item in cases]
        variation = base.coefficient_of_variation(distances)
        repeatability_passed &= variation < 0.20
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
                "batch_native_p95_distance": {
                    "minimum": min(distances),
                    "median": statistics.median(distances),
                    "maximum": max(distances),
                    "coefficient_of_variation": variation,
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
        raise SystemExit("the first v6.2 formal campaign already exists")
    if not BINARY.is_file():
        raise SystemExit("build the ndabi_v61 release binary before the repair campaign")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    container = f"ndabi-v62-postgres-{time.time_ns()}"
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
        connection, reader_role_read_only, reader_write_refused = setup_engine(container)
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
            "campaign": "NDABI canonical PostgreSQL batch repair v6.2",
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
        remove_container(container)


if __name__ == "__main__":
    raise SystemExit(main())
