#!/usr/bin/env python3
"""Run the frozen v2.6 PostgreSQL process campaign."""

from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "evidence" / "v25-failed" / "ndabi_v25"
EXPECTED_BINARY_SHA256 = "0fb95571ab8f26dbf76fe6b2eaaec1850304ca5518a527ee5e2fe0cf7804b962"
IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
RESULT_ROOT = ROOT / "results" / "v26"
PROCESS_COUNT = 5


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def measurement(result: dict, arm: str) -> dict:
    return next(item for item in result["measurements"] if item["id"] == arm)


def coefficient(values: list[float]) -> float:
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else float("inf")


def correctness_passed(result: dict) -> bool:
    checks = {item["id"]: item["passed"] for item in result["hard_gate"]["checks"]}
    return checks.get("literal-result-and-receipt-equality") is True and checks.get("frame-refusals") is True


def aggregate(results: list[dict], exit_codes: list[int], campaign_id: str, image_id: str) -> dict:
    arms = ["simple-sql", "native-prepared", "full-ndabi", "session-ndabi", "direct-repeat"]
    p95 = {arm: [measurement(result, arm)["p95_ns"] for result in results] for arm in arms}
    median_p95 = {arm: statistics.median(values) for arm, values in p95.items()}
    ratios = {
        "simple_over_session": median_p95["simple-sql"] / median_p95["session-ndabi"],
        "full_over_session": median_p95["full-ndabi"] / median_p95["session-ndabi"],
        "session_over_native": median_p95["session-ndabi"] / median_p95["native-prepared"],
        "native_over_direct_repeat": median_p95["native-prepared"] / median_p95["direct-repeat"],
    }
    process_session_native = [
        measurement(result, "session-ndabi")["p95_ns"]
        / measurement(result, "native-prepared")["p95_ns"]
        for result in results
    ]
    payloads = {
        (result["canonical_response_sha256"], result["receipt_core_sha256"])
        for result in results
    }
    checks = [
        {
            "id": "five-complete-processes",
            "passed": len(results) == PROCESS_COUNT and all(code in (0, 1) for code in exit_codes),
            "observed": {"results": len(results), "exit_codes": exit_codes},
            "target": "five complete results and exit status zero or local-performance one",
        },
        {
            "id": "all-correctness-gates",
            "passed": all(correctness_passed(result) for result in results),
            "observed": sum(correctness_passed(result) for result in results),
            "target": "5/5",
        },
        {
            "id": "one-result-identity",
            "passed": len(payloads) == 1,
            "observed": sorted(payloads),
            "target": "one canonical payload and receipt digest",
        },
        {
            "id": "simple-stack-removal",
            "passed": ratios["simple_over_session"] >= 1.10,
            "observed": ratios["simple_over_session"],
            "target": "at least 1.10x",
        },
        {
            "id": "session-native-distance",
            "passed": ratios["session_over_native"] <= 1.10,
            "observed": ratios["session_over_native"],
            "target": "no more than 1.10x",
        },
        {
            "id": "full-session-distance",
            "passed": ratios["full_over_session"] <= 1.50,
            "observed": ratios["full_over_session"],
            "target": "no more than 1.50x",
        },
        {
            "id": "direct-repeat-distance",
            "passed": 0.90 <= ratios["native_over_direct_repeat"] <= 1.10,
            "observed": ratios["native_over_direct_repeat"],
            "target": "between 0.90x and 1.10x",
        },
        {
            "id": "session-native-repeatability",
            "passed": coefficient(process_session_native) < 0.20,
            "observed": {
                "ratios": process_session_native,
                "coefficient_of_variation": coefficient(process_session_native),
            },
            "target": "coefficient below 0.20",
        },
    ]
    return {
        "schema": "ndabi-postgresql-process-campaign-v2.6",
        "campaign_id": campaign_id,
        "status": "accepted" if all(item["passed"] for item in checks) else "failed",
        "binary": {"path": str(BINARY.relative_to(ROOT)), "sha256": sha256(BINARY)},
        "image": {"reference": IMAGE, "id": image_id},
        "processes": PROCESS_COUNT,
        "median_process_p95_ns": median_p95,
        "ratios": ratios,
        "process_session_native_ratios": process_session_native,
        "hard_gate": {"passed": all(item["passed"] for item in checks), "checks": checks},
    }


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, capture_output=True, text=True, check=check)


def main() -> int:
    if sha256(BINARY) != EXPECTED_BINARY_SHA256:
        raise SystemExit("the frozen v2.5 binary digest changed")
    campaign_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{time.time_ns()}"
    directory = RESULT_ROOT / campaign_id
    directory.mkdir(parents=True, exist_ok=False)
    container = f"ndabi-v26-{time.time_ns()}"
    results = []
    exit_codes = []
    try:
        command(
            "docker", "run", "--detach", "--rm", "--name", container,
            "--env", "POSTGRES_PASSWORD=ndabi-test-only", "--publish", "127.0.0.1::5432", IMAGE,
        )
        for _ in range(30):
            ready = command("docker", "exec", container, "pg_isready", "-U", "postgres", check=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise SystemExit("the PostgreSQL container did not become ready")
        port_line = command("docker", "port", container, "5432/tcp").stdout.strip()
        port = port_line.rsplit(":", 1)[1]
        image_id = command("docker", "inspect", "--format", "{{.Image}}", container).stdout.strip()
        connection = f"host=127.0.0.1 port={port} user=postgres password=ndabi-test-only dbname=postgres"
        for index in range(PROCESS_COUNT):
            completed = command(str(BINARY), connection, check=False)
            exit_codes.append(completed.returncode)
            if completed.stderr:
                (directory / f"process-{index:02d}.stderr").write_text(completed.stderr)
            try:
                result = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                raise SystemExit(f"process {index} did not return complete JSON: {error}") from error
            (directory / f"process-{index:02d}.json").write_text(json.dumps(result, indent=2) + "\n")
            results.append(result)
        summary = aggregate(results, exit_codes, campaign_id, image_id)
        (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        (RESULT_ROOT / "latest.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
        return 0 if summary["hard_gate"]["passed"] else 1
    finally:
        command("docker", "stop", container, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
