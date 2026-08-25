#!/usr/bin/env python3
"""Run the frozen PostgreSQL write-admission v5.1 campaign once."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

import validation_suite_v44 as shared


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v51"
POSTGRES_IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
RESULT_ROOT = ROOT / "results" / "v51"
PROCESS_COUNT = 5
CAMPAIGN_NAME = "NDABI PostgreSQL write admission v5.1"
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-session/src/lib.rs",
    "crates/ndabi-write/Cargo.toml",
    "crates/ndabi-write/src/lib.rs",
    "src/bin/ndabi_v51.rs",
)


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update((ROOT / relative).read_bytes() + b"\0")
    return digest.hexdigest()


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v5.1 formal campaign already exists")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    container = f"ndabi-v51-postgres-{time.time_ns()}"
    reports = []
    try:
        command(
            "docker", "run", "--detach", "--name", container,
            "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=ndabi-test-only",
            "--env", "POSTGRES_DB=ndabi", POSTGRES_IMAGE,
        )
        for _ in range(60):
            ready = command("docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "ndabi", check=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgreSQL did not become ready")
        command(
            "docker", "exec", container, "psql", "-U", "postgres", "-d", "ndabi",
            "-v", "ON_ERROR_STOP=1", "-c",
            "CREATE TABLE ndabi_write_records(id bigint PRIMARY KEY,version bigint NOT NULL,value bigint NOT NULL); INSERT INTO ndabi_write_records VALUES (1,0,0)",
        )
        port = command("docker", "port", container, "5432/tcp").stdout.strip().rsplit(":", 1)[1]
        connection = f"host=127.0.0.1 port={port} user=postgres password=ndabi-test-only dbname=ndabi"
        for process in range(1, PROCESS_COUNT + 1):
            command(
                "docker", "exec", container, "psql", "-U", "postgres", "-d", "ndabi",
                "-v", "ON_ERROR_STOP=1", "-c", "UPDATE ndabi_write_records SET version=0,value=0 WHERE id=1",
            )
            report = json.loads(command(str(BINARY), connection).stdout)
            report["process"] = process
            (campaign / f"process-{process}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            reports.append(report)
        aggregate = {
            "campaign": CAMPAIGN_NAME,
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            "binary_sha256": shared.sha256(BINARY),
            "source_sha256": source_sha256(),
            "postgres_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE).stdout.strip(),
            "accepted": all(report["passed"] for report in reports),
            "process_results": [str(path.relative_to(ROOT)) for path in sorted(campaign.glob("process-*.json"))],
        }
        encoded = json.dumps(aggregate, indent=2) + "\n"
        (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
        latest.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if aggregate["accepted"] else 1
    finally:
        command("docker", "rm", "--force", container, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
