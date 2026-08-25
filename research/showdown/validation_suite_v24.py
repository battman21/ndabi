#!/usr/bin/env python3
"""Run the frozen v2.4 White Tree process campaign."""

from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "evidence" / "v23-failed" / "ndabi_v23"
EXPECTED_BINARY_SHA256 = "954e828ed9e20f03f04fe52e714ccdbeddd76f6a17ea35a03e38022dd15aae36"
RESULT_ROOT = ROOT / "results" / "v24"
PROCESS_COUNT = 5


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def measurement(result: dict, arm: str) -> dict:
    return next(item for item in result["measurements"] if item["id"] == arm)


def coefficient(values: list[float]) -> float:
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else float("inf")


def correctness_passed(result: dict) -> bool:
    checks = {item["id"]: item["passed"] for item in result["hard_gate"]["checks"]}
    return checks.get("literal-semantic-equality") is True and checks.get("frame-refusals") is True


def aggregate(results: list[dict], exit_codes: list[int], campaign_id: str) -> dict:
    arms = ["governed-sql", "full-ndabi", "session-ndabi", "native-typed", "direct-repeat"]
    p95 = {
        arm: [measurement(result, arm)["p95_ns"] for result in results]
        for arm in arms
    }
    median_p95 = {arm: statistics.median(values) for arm, values in p95.items()}
    ratios = {
        "sql_over_session": median_p95["governed-sql"] / median_p95["session-ndabi"],
        "full_over_session": median_p95["full-ndabi"] / median_p95["session-ndabi"],
        "session_over_native": median_p95["session-ndabi"] / median_p95["native-typed"],
        "native_over_direct_repeat": median_p95["native-typed"] / median_p95["direct-repeat"],
    }
    process_session_native = [
        measurement(result, "session-ndabi")["p95_ns"]
        / measurement(result, "native-typed")["p95_ns"]
        for result in results
    ]
    roots = {result["database_data_root_sha256"] for result in results}
    payloads = {
        (result["canonical_response_sha256"], result["canonical_response_bytes"])
        for result in results
    }
    fingerprints = {result["source_fingerprint_sha256"] for result in results}
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
            "id": "one-evidence-identity",
            "passed": len(roots) == len(payloads) == len(fingerprints) == 1,
            "observed": {
                "database_roots": sorted(roots),
                "canonical_payloads": sorted(payloads),
                "source_fingerprints": sorted(fingerprints),
            },
            "target": "one database root, payload identity, and source fingerprint",
        },
        {
            "id": "sql-stack-removal",
            "passed": ratios["sql_over_session"] >= 2.5,
            "observed": ratios["sql_over_session"],
            "target": "at least 2.5x",
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
        "schema": "ndabi-white-tree-process-campaign-v2.4",
        "campaign_id": campaign_id,
        "status": "accepted" if all(item["passed"] for item in checks) else "failed",
        "binary": {"path": str(BINARY.relative_to(ROOT)), "sha256": sha256(BINARY)},
        "processes": PROCESS_COUNT,
        "median_process_p95_ns": median_p95,
        "ratios": ratios,
        "process_session_native_ratios": process_session_native,
        "hard_gate": {"passed": all(item["passed"] for item in checks), "checks": checks},
    }


def main() -> int:
    if sha256(BINARY) != EXPECTED_BINARY_SHA256:
        raise SystemExit("the frozen v2.3 binary digest changed")
    campaign_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{time.time_ns()}"
    directory = RESULT_ROOT / campaign_id
    directory.mkdir(parents=True, exist_ok=False)
    results = []
    exit_codes = []
    for index in range(PROCESS_COUNT):
        completed = subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)
        exit_codes.append(completed.returncode)
        if completed.stderr:
            (directory / f"process-{index:02d}.stderr").write_text(completed.stderr)
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise SystemExit(f"process {index} did not return complete JSON: {error}") from error
        raw = directory / f"process-{index:02d}.json"
        raw.write_text(json.dumps(result, indent=2) + "\n")
        results.append(result)
    summary = aggregate(results, exit_codes, campaign_id)
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    (RESULT_ROOT / "latest.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if summary["hard_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
