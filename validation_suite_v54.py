#!/usr/bin/env python3
"""Run the frozen MongoDB single-batch v5.4 campaign once."""

from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v54"
MONGODB_IMAGE = "mongo@sha256:0a83b2f824b29c94c5284a49b018db2e3166d9879d1edda5cce545d899ef2bbb"
RESULT_ROOT = ROOT / "results" / "v54"
PROCESS_COUNT = 5
BATCH_SIZES = (1, 8, 32, 128)
CAMPAIGN_LABEL = "NDABI MongoDB single batch v5.4"
RUN_COMMAND = "run-v54"
VERSION = "v5.4"
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-session/Cargo.toml",
    "crates/ndabi-session/src/lib.rs",
    "crates/ndabi-mongodb/Cargo.toml",
    "crates/ndabi-mongodb/src/lib.rs",
    "src/bin/ndabi_v53.rs",
    "src/bin/ndabi_v54.rs",
    "../../specs/ndabi_mongodb_single_batch_campaign_v5_4.md",
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


def find_case(report: dict, batch_size: int) -> dict:
    return next(case for case in report["cases"] if case["batch_size"] == batch_size)


def find_arm(case: dict, identifier: str) -> dict:
    return next(arm for arm in case["arms"] if arm["id"] == identifier)


def median(values: list[float | int]) -> float:
    return float(statistics.median(values))


def process_integrity(report: dict) -> bool:
    audit = report.get("single_batch_audit")
    audit_passed = audit is None or (
        audit["passed"]
        and audit["find_commands"] == 1
        and audit["get_more_commands"] == 0
    )
    return report["refusals"] == "8/8" and audit_passed and all(
        case["exact_results"]
        and all(arm["deterministic_encoding"] for arm in case["arms"])
        for case in report["cases"]
    )


def aggregate_case(reports: list[dict], batch_size: int) -> dict:
    cases = [find_case(report, batch_size) for report in reports]
    arm_ids = (
        "native-sequential",
        "json-sequential",
        "json-set",
        "native-set",
        "ndabi-typed",
        "ndabi-raw",
    )
    median_p95_ns = {
        identifier: median([find_arm(case, identifier)["p95_ns"] for case in cases])
        for identifier in arm_ids
    }
    median_allocated_bytes = {
        identifier: median(
            [
                find_arm(case, identifier)["allocated_bytes_per_operation"]
                for case in cases
            ]
        )
        for identifier in ("native-set", "ndabi-typed", "ndabi-raw")
    }
    typed_native_ratio = median_p95_ns["ndabi-typed"] / median_p95_ns["native-set"]
    typed_sequential_speedup = (
        median_p95_ns["json-sequential"] / median_p95_ns["ndabi-typed"]
    )
    typed_native_allocated_ratio = (
        median_allocated_bytes["ndabi-typed"]
        / max(median_allocated_bytes["native-set"], 1.0)
    )
    request_compression = median([case["request_compression"] for case in cases])
    exact_results = all(case["exact_results"] for case in cases)
    passed = exact_results and request_compression >= 0.60
    if batch_size == 32:
        passed = passed and typed_native_ratio <= 1.15 and typed_sequential_speedup >= 5.0
    if batch_size == 128:
        passed = (
            passed
            and typed_native_ratio <= 1.15
            and typed_sequential_speedup >= 20.0
            and typed_native_allocated_ratio <= 1.05
        )
    return {
        "batch_size": batch_size,
        "median_p95_ns": median_p95_ns,
        "median_allocated_bytes_per_operation": median_allocated_bytes,
        "ndabi_typed_native_ratio": typed_native_ratio,
        "ndabi_typed_sequential_json_speedup": typed_sequential_speedup,
        "ndabi_typed_native_allocated_byte_ratio": typed_native_allocated_ratio,
        "request_compression": request_compression,
        "exact_results": exact_results,
        "passed": passed,
    }


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit(f"the first {VERSION} formal campaign already exists")
    if not BINARY.is_file():
        raise SystemExit(f"the {VERSION} release binary is absent")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    container = f"ndabi-v54-mongodb-{time.time_ns()}"
    binary_digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    source_digest = source_sha256()
    image_id = command(
        "docker", "image", "inspect", "--format", "{{.Id}}", MONGODB_IMAGE
    ).stdout.strip()
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
            MONGODB_IMAGE,
        )
        for _ in range(90):
            ready = command(
                "docker",
                "exec",
                container,
                "mongosh",
                "--quiet",
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
        uri = f"mongodb://127.0.0.1:{port}/?directConnection=true"
        command(str(BINARY), "prepare", uri)
        for process in range(1, PROCESS_COUNT + 1):
            completed = command(str(BINARY), RUN_COMMAND, uri)
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
        aggregate_cases = [aggregate_case(reports, size) for size in BATCH_SIZES]
        integrity = [process_integrity(report) for report in reports]
        aggregate = {
            "campaign": CAMPAIGN_LABEL,
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            "binary_sha256": binary_digest,
            "source_sha256": source_digest,
            "mongodb_image": MONGODB_IMAGE,
            "mongodb_image_id": image_id,
            "cases": aggregate_cases,
            "process_integrity": integrity,
            "accepted": all(integrity) and all(case["passed"] for case in aggregate_cases),
            "process_results": [
                str(path.relative_to(ROOT))
                for path in sorted(campaign.glob("process-*.json"))
            ],
        }
        encoded = json.dumps(aggregate, indent=2) + "\n"
        (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
        latest.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if aggregate["accepted"] else 1
    finally:
        for _ in range(3):
            command("docker", "rm", "--force", container, check=False)
            absent = command("docker", "inspect", container, check=False)
            if absent.returncode != 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("the temporary MongoDB container remains")


if __name__ == "__main__":
    raise SystemExit(main())
