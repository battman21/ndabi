#!/usr/bin/env python3
"""Run the frozen canonical MongoDB binding v6.0 campaign once."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

import validation_suite_v44 as shared


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v60"
MONGODB_IMAGE = "mongo@sha256:0a83b2f824b29c94c5284a49b018db2e3166d9879d1edda5cce545d899ef2bbb"
RESULT_ROOT = ROOT / "results" / "v60"
PROCESS_COUNT = 5
PREPARE_SENTINEL = "I_UNDERSTAND_THIS_DROPS_THE_EPHEMERAL_DATABASE"
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-protocol/Cargo.toml",
    "crates/ndabi-protocol/src/lib.rs",
    "crates/ndabi-protocol/src/replay.rs",
    "crates/ndabi-mongodb-v1/Cargo.toml",
    "crates/ndabi-mongodb-v1/src/lib.rs",
    "src/bin/ndabi_v60.rs",
    "validation_suite_v60.py",
    "../../specs/ndabi_canonical_mongodb_campaign_v6_0.md",
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


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v6.0 formal campaign already exists")
    if not BINARY.is_file():
        raise SystemExit("build the ndabi_v60 release binary before the campaign")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    container = f"ndabi-v60-mongodb-{suffix}"
    database = f"ndabi_v60_{suffix}"
    reports = []
    try:
        command(
            "docker",
            "run",
            "--detach",
            "--name",
            container,
            "--publish",
            "127.0.0.1::27017",
            "--env",
            "MONGO_INITDB_ROOT_USERNAME=root",
            "--env",
            "MONGO_INITDB_ROOT_PASSWORD=root-test-only",
            MONGODB_IMAGE,
        )
        for _ in range(90):
            ready = command(
                "docker",
                "exec",
                container,
                "mongosh",
                "--quiet",
                "mongodb://root:root-test-only@127.0.0.1:27017/admin?directConnection=true",
                "--eval",
                "db.adminCommand({ping:1}).ok",
                check=False,
            )
            if ready.returncode == 0 and ready.stdout.strip() == "1":
                break
            time.sleep(1)
        else:
            raise RuntimeError("the MongoDB container did not become ready")
        mapping = command("docker", "port", container, "27017/tcp").stdout.strip()
        port = mapping.rsplit(":", 1)[1]
        root_uri = (
            f"mongodb://root:root-test-only@127.0.0.1:{port}/"
            "?authSource=admin&directConnection=true"
        )
        command(str(BINARY), "prepare-ephemeral", root_uri, database, PREPARE_SENTINEL)
        create_user = (
            f'db.getSiblingDB("{database}").createUser('
            f'{{user:"ndabi_reader",pwd:"reader-test-only",roles:[{{role:"read",db:"{database}"}}]}})'
        )
        command(
            "docker",
            "exec",
            container,
            "mongosh",
            "--quiet",
            "mongodb://root:root-test-only@127.0.0.1:27017/admin?directConnection=true",
            "--eval",
            create_user,
        )
        reader_uri = (
            f"mongodb://ndabi_reader:reader-test-only@127.0.0.1:{port}/"
            f"?authSource={database}&directConnection=true"
        )
        container_reader_uri = (
            "mongodb://ndabi_reader:reader-test-only@127.0.0.1:27017/"
            f"?authSource={database}&directConnection=true"
        )
        reader_count = command(
            "docker",
            "exec",
            container,
            "mongosh",
            "--quiet",
            container_reader_uri,
            "--eval",
            f'db.getSiblingDB("{database}").items.countDocuments({{}})',
        ).stdout.strip()
        reader_write = command(
            "docker",
            "exec",
            container,
            "mongosh",
            "--quiet",
            container_reader_uri,
            "--eval",
            f'db.getSiblingDB("{database}").items.insertOne({{_id:999}})',
            check=False,
        )
        binary_digest = shared.sha256(BINARY)
        source_digest = source_sha256()
        image_id = command(
            "docker", "image", "inspect", "--format", "{{.Id}}", MONGODB_IMAGE
        ).stdout.strip()
        for process in range(1, PROCESS_COUNT + 1):
            report = json.loads(command(str(BINARY), "run", reader_uri, database).stdout)
            report.update(
                process=process,
                reader_count_passed=reader_count == "256",
                reader_write_refused=reader_write.returncode != 0,
                binary_sha256=binary_digest,
                source_sha256=source_digest,
                mongodb_image_id=image_id,
            )
            report["passed"] = (
                report["passed"]
                and report["reader_count_passed"]
                and report["reader_write_refused"]
            )
            (campaign / f"process-{process}.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            reports.append(report)
        aggregate = {
            "campaign": "NDABI canonical MongoDB binding v6.0",
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            "binary_sha256": binary_digest,
            "source_sha256": source_digest,
            "mongodb_image_id": image_id,
            "accepted": all(report["passed"] for report in reports),
            "process_results": [
                str(path.relative_to(ROOT)) for path in sorted(campaign.glob("process-*.json"))
            ],
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
