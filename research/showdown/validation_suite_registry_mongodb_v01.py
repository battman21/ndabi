#!/usr/bin/env python3
"""Run the frozen registered MongoDB campaign v0.1."""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_registry_mongodb_v01"
MONGODB_IMAGE = (
    "mongo@sha256:0a83b2f824b29c94c5284a49b018db2e3166d9879d1edda5cce545d899ef2bbb"
)
RESULT_ROOT = ROOT / "results" / "registry-mongodb-v01"
PROCESS_COUNT = 5
PREPARE_SENTINEL = "I_UNDERSTAND_THIS_DROPS_THE_EPHEMERAL_DATABASE"
CAMPAIGN = "NDABI registered MongoDB profile v0.1"
REGISTERED_PROFILE = "0x4d471002"
TRUE_FIELDS = (
    "complete_result_match",
    "changed_registry_refused",
    "legacy_identity_refused",
    "unknown_handle_refused",
    "changed_shape_refused",
    "excessive_limits_refused",
    "changed_frame_refused",
    "replay_refused",
    "receipt_verified",
    "passed",
)
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-protocol/Cargo.toml",
    "crates/ndabi-protocol/src/lib.rs",
    "crates/ndabi-protocol/src/registry.rs",
    "crates/ndabi-mongodb-v1/Cargo.toml",
    "crates/ndabi-mongodb-v1/src/lib.rs",
    "src/bin/ndabi_registry_mongodb_v01.rs",
    "validation_suite_registry_mongodb_v01.py",
    "../../specs/ndabi_registered_mongodb_campaign_v0_1.md",
)


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = (ROOT / relative).resolve()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def expected_result() -> bytes:
    output = bytearray()
    for identifier in range(10, 10 + 128):
        output.extend(
            struct.pack(
                "<qiii",
                identifier,
                identifier % 1_024,
                identifier % 4_096,
                identifier % 10_000,
            )
        )
        output.extend(bytes([identifier % 251]) * 64)
    return bytes(output)


def validate_report(report: dict) -> None:
    if report.get("campaign") != CAMPAIGN:
        raise ValueError("the campaign identity changed")
    if report.get("registered_profile") != REGISTERED_PROFILE:
        raise ValueError("the registered profile changed")
    registry_digest = report.get("registry_digest")
    if not isinstance(registry_digest, str) or len(registry_digest) != 64:
        raise ValueError("the registry digest is invalid")
    expected = expected_result()
    if report.get("request_bytes") != 160:
        raise ValueError("the request size changed")
    if report.get("response_rows") != 128:
        raise ValueError("the response row count changed")
    if report.get("response_bytes") != len(expected):
        raise ValueError("the response byte count changed")
    if report.get("result_sha256") != hashlib.sha256(expected).hexdigest():
        raise ValueError("the complete result changed")
    if report.get("find_commands") != 1 or report.get("get_more_commands") != 0:
        raise ValueError("the MongoDB command count changed")
    for field in TRUE_FIELDS:
        if report.get(field) is not True:
            raise ValueError(f"the {field} gate failed")


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first registered MongoDB campaign already exists")
    if not BINARY.is_file():
        raise SystemExit("build the registered MongoDB release binary first")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    container = f"ndabi-registry-mongodb-{suffix}"
    database = f"ndabi_registry_mongo_{suffix}"
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

        port = command("docker", "port", container, "27017/tcp").stdout.strip().rsplit(":", 1)[1]
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
        binary_digest = file_sha256(BINARY)
        source_digest = source_sha256()
        image_id = command(
            "docker", "image", "inspect", "--format", "{{.Id}}", MONGODB_IMAGE
        ).stdout.strip()

        for process in range(1, PROCESS_COUNT + 1):
            completed = command(str(BINARY), "run", reader_uri, database, check=False)
            if completed.returncode != 0:
                raise ValueError("the registered MongoDB process refused")
            report = json.loads(completed.stdout)
            validate_report(report)
            report.update(
                process=process,
                reader_count_passed=reader_count == "256",
                reader_write_refused=reader_write.returncode != 0,
            )
            report["passed"] = (
                report["passed"]
                and report["reader_count_passed"]
                and report["reader_write_refused"]
            )
            (campaign / f"process-{process}.json").write_text(
                json.dumps(report, indent=2) + "\n",
                encoding="utf-8",
            )
            reports.append(report)

        registry_digests = {report["registry_digest"] for report in reports}
        accepted = (
            len(reports) == PROCESS_COUNT
            and all(report["passed"] for report in reports)
            and len(registry_digests) == 1
        )
        aggregate = {
            "campaign": CAMPAIGN,
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            "source_sha256": source_digest,
            "binary_sha256": binary_digest,
            "mongodb_image_id": image_id,
            "registered_profile": REGISTERED_PROFILE,
            "registry_digest": next(iter(registry_digests), None),
            "registry_digest_consistent": len(registry_digests) == 1,
            "reader_count_passed": reader_count == "256",
            "reader_write_refused": reader_write.returncode != 0,
            "accepted": accepted,
        }
        encoded = json.dumps(aggregate, indent=2) + "\n"
        (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
        latest.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if accepted else 1
    finally:
        command("docker", "rm", "--force", container, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
