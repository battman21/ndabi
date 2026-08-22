#!/usr/bin/env python3
"""Run the frozen NDABI v1.2 corrected measurement campaign."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent.parent
BINARY = ROOT / "target" / "release" / "ndabi_v11"
RESULTS = ROOT / "results"
LATEST = RESULTS / "v12-measurement-campaign.json"
PREREGISTRATION = REPOSITORY / "specs" / "ndabi_poc_measurement_campaign_v1_2.md"

CASES = [
    ("point-512", "point", 512, 64, 2_000),
    ("point-10k", "point", 10_000, 64, 2_000),
    ("point-100k", "point", 100_000, 64, 2_000),
    ("point-1m", "point", 1_000_000, 64, 2_000),
    ("temporal-1m", "temporal", 1_000_000, 64, 2_000),
    ("filter-512-64b", "filter", 512, 64, 400),
    ("filter-10k-4k", "filter", 10_000, 4_096, 20),
    ("filter-100k-64k", "filter", 100_000, 65_536, 2),
    ("filter-1m-1m", "filter", 1_000_000, 1_048_576, 1),
    ("aggregate-10k", "aggregate", 10_000, 64, 20),
    ("aggregate-100k", "aggregate", 100_000, 64, 2),
    ("aggregate-1m", "aggregate", 1_000_000, 64, 1),
]


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def arm(result: dict[str, object], identifier: str) -> dict[str, object]:
    return next(item for item in result["arms"] if item["id"] == identifier)


def ratio(left: dict[str, object], right: dict[str, object]) -> float:
    return float(left["median_ns_per_operation"]) / max(
        float(right["median_ns_per_operation"]), 0.000_001
    )


def run_case(case: tuple[str, str, int, int, int]) -> tuple[dict[str, object], bytes]:
    identifier, workload, records, result_bytes, operations = case
    completed = subprocess.run(
        [
            str(BINARY),
            "--records",
            str(records),
            "--workload",
            workload,
            "--result-bytes",
            str(result_bytes),
            "--batches",
            "24",
            "--operations-per-batch",
            str(operations),
            "--warmup-batches",
            "2",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        timeout=300,
    )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"{identifier}: {detail or 'the case returned invalid JSON'}"
        ) from error
    if result.get("schema") != "ndabi-poc-result-v1.1":
        raise RuntimeError(f"{identifier}: the result schema does not match")
    return result, completed.stdout


def store_exclusive(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as destination:
        destination.write(value)


def store_latest(value: bytes) -> None:
    RESULTS.mkdir(exist_ok=True)
    temporary = LATEST.with_name(f".{LATEST.name}.tmp")
    temporary.write_bytes(value)
    temporary.replace(LATEST)


def main() -> None:
    if not BINARY.is_file():
        raise RuntimeError("The NDABI v1.1 release binary is absent.")
    if not PREREGISTRATION.is_file():
        raise RuntimeError("The NDABI v1.2 measurement preregistration is absent.")
    binary_sha256 = sha256_file(BINARY)
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns()}"
    campaign_root = RESULTS / "v12" / campaign_id
    results = []
    evidence = []
    for index, case in enumerate(CASES, start=1):
        result, raw = run_case(case)
        path = campaign_root / "cases" / f"case-{index:02}-{case[0]}.json"
        store_exclusive(path, raw)
        results.append(result)
        evidence.append(
            {
                "id": case[0],
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256_bytes(raw),
            }
        )
    if sha256_file(BINARY) != binary_sha256:
        raise RuntimeError("The release binary changed during the scale campaign.")
    fingerprints = {
        result["environment"]["source_fingerprint_blake3"] for result in results
    }
    if len(fingerprints) != 1:
        raise RuntimeError("The source fingerprint changed during the scale campaign.")
    cases = []
    for case, result in zip(CASES, results, strict=True):
        stateless = arm(result, "stateless-json")
        prepared = arm(result, "prepared-json")
        cbor = arm(result, "canonical-cbor")
        protected_cbor = arm(result, "protected-cbor")
        ndabi = arm(result, "ndabi")
        direct = arm(result, "direct")
        cases.append(
            {
                "id": case[0],
                "config": result["config"],
                "hard_gate_passed": result["hard_gate"]["passed"],
                "timer_control_ratio": result["calibration"]["timer_control_ratio"],
                "ratios": {
                    "state_reuse_stateless_vs_prepared_json": ratio(stateless, prepared),
                    "generic_binary_prepared_json_vs_cbor": ratio(prepared, cbor),
                    "integrity_cbor_vs_protected_cbor": ratio(cbor, protected_cbor),
                    "specialised_encoding_protected_cbor_vs_ndabi": ratio(
                        protected_cbor, ndabi
                    ),
                    "ndabi_wire_over_direct": ratio(ndabi, direct),
                },
                "bytes": {
                    item["id"]: {
                        "request": item["request_bytes"],
                        "response": item["response_bytes"],
                    }
                    for item in result["arms"]
                },
            }
        )
    all_cases_passed = all(result["hard_gate"]["passed"] for result in results)
    report = {
        "schema": "ndabi-v12-measurement-campaign-v0.1",
        "status": "corrected-integrity-equalised-local-campaign",
        "campaign_id": campaign_id,
        "configuration": {
            "cases": len(CASES),
            "batches_per_arm": 24,
            "warmup_batches_per_arm": 2,
            "speed_gate_registered": False,
        },
        "source_fingerprint_blake3": fingerprints.pop(),
        "release_binary_sha256": binary_sha256,
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "preregistration_sha256": sha256_file(PREREGISTRATION),
        "campaign_gate": {
            "passed": all_cases_passed and len(results) == len(CASES),
            "all_cases_passed": all_cases_passed,
            "cases_passed": sum(result["hard_gate"]["passed"] for result in results),
            "cases_total": len(CASES),
        },
        "cases": cases,
        "raw_evidence": evidence,
        "limitations": [
            "This campaign uses a fixture query engine.",
            "The campaign has no registered speed acceptance target.",
            "macOS results do not establish publishable absolute latency.",
            "The campaign does not prove database, remote, durable, or model behaviour.",
        ],
    }
    summary = (json.dumps(report, indent=2) + "\n").encode()
    store_exclusive(campaign_root / "summary.json", summary)
    store_latest(summary)
    print(summary.decode(), end="")


if __name__ == "__main__":
    main()
