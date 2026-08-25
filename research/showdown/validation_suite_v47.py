#!/usr/bin/env python3
"""Run the frozen local MongoDB point-profile v4.7 campaign once."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

import validation_suite_v44 as shared


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v47"
MONGODB_IMAGE = "mongo@sha256:02a0cc7939f5ed38f30f9bc714ef5f682d49baf9350c54acf302ce833087fe8a"
RESULT_ROOT = ROOT / "results" / "v47"
PROCESS_COUNT = 5
CAMPAIGN_NAME = "NDABI MongoDB point profile v4.7"
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-session/Cargo.toml",
    "crates/ndabi-session/src/lib.rs",
    "crates/ndabi-mongodb/Cargo.toml",
    "crates/ndabi-mongodb/src/lib.rs",
    "src/bin/ndabi_v47.rs",
)


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update((ROOT / relative).read_bytes() + b"\0")
    return digest.hexdigest()


def arm(report: dict, identifier: str) -> dict:
    return next(value for value in report["arms"] if value["id"] == identifier)


def main(
    *,
    campaign_name: str = CAMPAIGN_NAME,
    mongodb_image: str = MONGODB_IMAGE,
    result_root: Path = RESULT_ROOT,
) -> int:
    latest = result_root / "latest.json"
    if latest.exists():
        raise SystemExit("the first v4.7 formal campaign already exists")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = result_root / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    container = f"ndabi-v47-mongodb-{time.time_ns()}"
    binary_digest = shared.sha256(BINARY)
    source_digest = source_sha256()
    image_id = command("docker", "image", "inspect", "--format", "{{.Id}}", mongodb_image).stdout.strip()
    reports = []
    try:
        command(
            "docker", "run", "--detach", "--name", container,
            "--publish", "127.0.0.1::27017", mongodb_image,
        )
        for _ in range(60):
            ready = command(
                "docker", "exec", container, "mongosh", "--quiet",
                "--eval", "db.adminCommand({ping:1}).ok", check=False,
            )
            if ready.returncode == 0 and ready.stdout.strip() == "1":
                break
            time.sleep(1)
        else:
            raise RuntimeError("the MongoDB container did not become ready")
        mapping = command("docker", "port", container, "27017/tcp").stdout.strip()
        port = mapping.rsplit(":", 1)[1]
        uri = f"mongodb://127.0.0.1:{port}/?directConnection=true"
        command(str(BINARY), "prepare", uri)
        for process in range(1, PROCESS_COUNT + 1):
            completed = command(str(BINARY), "run", uri)
            report = json.loads(completed.stdout)
            report.update(
                process=process,
                binary_sha256=binary_digest,
                source_sha256=source_digest,
                mongodb_image_id=image_id,
            )
            (campaign / f"process-{process}.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            reports.append(report)
        aggregate = {
            "campaign": campaign_name,
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            "binary_sha256": binary_digest,
            "source_sha256": source_digest,
            "mongodb_image": mongodb_image,
            "mongodb_image_id": image_id,
            "native_p95_ns": [arm(report, "native")["p95_ns"] for report in reports],
            "json_p95_ns": [arm(report, "json")["p95_ns"] for report in reports],
            "ndabi_p95_ns": [arm(report, "ndabi")["p95_ns"] for report in reports],
            "request_compression": [report["request_compression"] for report in reports],
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
