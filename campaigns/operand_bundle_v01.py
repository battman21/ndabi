#!/usr/bin/env python3
"""Run the frozen NDABI operand bundle campaign v0.1."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from semantic_batch_v02 import DockerFixture, await_quiet_host, clean_checkout


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = ROOT / "campaigns" / "results" / "operand-bundle-v01"
EXAMPLE = "review_operand_bundle_showdown"
RELEASE_EXAMPLE = ROOT / "target" / "release" / "examples" / EXAMPLE
ARMS = ("fused_native", "ndabi_graph", "ndabi_bundle")
FORMAL_CELLS = tuple(
    (item_count, concurrency)
    for item_count in (8, 128, 1024)
    for concurrency in (1, 8, 32)
)


class CampaignError(RuntimeError):
    """Reject incomplete or failed evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignError(message)


def command(arguments: list[str], *, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise CampaignError(f"command failed: {arguments[0]}: {detail}")
    return completed


def build_binary(destination: Path) -> dict[str, str]:
    command(
        [
            "cargo",
            "build",
            "--release",
            "-p",
            "ndabi-postgres-v1",
            "--example",
            EXAMPLE,
            "--features",
            "allocation-counting",
            "--locked",
        ],
        timeout=900,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(RELEASE_EXAMPLE, destination)
    return {
        "path": str(destination),
        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
    }


def run_worker(
    binary: Path,
    connection: str,
    arm: str,
    item_count: int,
    iterations: int,
    warmup: int,
) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["NDABI_TEST_READER_CONNECTION"] = connection
    completed = subprocess.run(
        [
            str(binary),
            "environment",
            arm,
            str(item_count),
            str(iterations),
            str(warmup),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=900,
        check=False,
        env=environment,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise CampaignError(f"the {arm} worker failed: {detail}")
    report = json.loads(completed.stdout)
    require(report["arm"] == arm, "the worker reported the wrong arm")
    require(report["exact_results"], "the worker did not prove exact results")
    require(report["receipt_verified"], "the worker did not verify receipts")
    return report


def run_arm(
    binary: Path,
    connection: str,
    arm: str,
    item_count: int,
    concurrency: int,
    iterations: int,
    warmup: int,
) -> list[dict[str, Any]]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(
                run_worker,
                binary,
                connection,
                arm,
                item_count,
                iterations,
                warmup,
            )
            for _ in range(concurrency)
        ]
        return [future.result() for future in futures]


def aggregate_arm(reports: list[dict[str, Any]]) -> dict[str, Any]:
    require(bool(reports), "the arm has no worker reports")
    request_reduction = {report["request_reduction_percent"] for report in reports}
    bundle_decodes = [report["bundle_decodes"] for report in reports]
    return {
        "workers": len(reports),
        "wall_mean_ns": statistics.median(report["wall"]["mean_ns"] for report in reports),
        "wall_p95_ns": statistics.median(report["wall"]["p95_ns"] for report in reports),
        "cpu_mean_ns": statistics.median(
            report["client_thread_cpu"]["mean_ns"] for report in reports
        ),
        "allocated_bytes": statistics.median(
            report["allocation"]["allocated_bytes"] for report in reports
        ),
        "request_reduction_percent": next(iter(request_reduction)),
        "bundle_decodes": bundle_decodes,
    }


def evaluate_cell(arms: dict[str, dict[str, Any]], item_count: int) -> dict[str, Any]:
    fused = arms["fused_native"]
    graph = arms["ndabi_graph"]
    bundle = arms["ndabi_bundle"]
    gates = {
        "request_reduction": item_count < 1024
        or bundle["request_reduction_percent"] >= 70.0,
        "one_static_decode": all(value == 1 for value in bundle["bundle_decodes"]),
        "p95_floor": bundle["wall_p95_ns"] <= fused["wall_p95_ns"] * 1.05,
        "mean_floor": bundle["wall_mean_ns"] <= fused["wall_mean_ns"] * 1.03,
        "cpu_reduction": bundle["cpu_mean_ns"] <= graph["cpu_mean_ns"] * 0.75,
        "allocation_reduction": bundle["allocated_bytes"]
        <= graph["allocated_bytes"] * 0.50,
    }
    return {"gates": gates, "accepted": all(gates.values())}


def run_campaign(smoke: bool) -> dict[str, Any]:
    if not smoke:
        require(clean_checkout(), "the formal campaign requires a clean checkout")
        quiet = await_quiet_host()
    else:
        quiet = {"qualified": False, "reason": "smoke mode"}
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns()}"
    result_root = RESULT_ROOT / campaign_id
    binary = ROOT / "target" / "campaign-binaries" / campaign_id / EXAMPLE
    fixture = DockerFixture(suffix=f"bundle-{os.getpid()}-{time.time_ns()}")
    reports: list[dict[str, Any]] = []
    try:
        build = build_binary(binary)
        fixture.start()
        repetitions = 1 if smoke else 5
        cells = ((1024, 1),) if smoke else FORMAL_CELLS
        iterations = 100 if smoke else 4096
        warmup = 10 if smoke else 64
        for repetition in range(repetitions):
            for cell_index, (item_count, concurrency) in enumerate(cells):
                offset = (repetition + cell_index) % len(ARMS)
                order = ARMS[offset:] + ARMS[:offset]
                arm_reports = {
                    arm: run_arm(
                        binary,
                        fixture.reader_connection(),
                        arm,
                        item_count,
                        concurrency,
                        iterations,
                        warmup,
                    )
                    for arm in order
                }
                arms = {arm: aggregate_arm(arm_reports[arm]) for arm in ARMS}
                reports.append(
                    {
                        "repetition": repetition + 1,
                        "item_count": item_count,
                        "concurrency": concurrency,
                        "arm_order": order,
                        "arms": arms,
                        **evaluate_cell(arms, item_count),
                    }
                )
        result = {
            "schema": "ndabi-operand-bundle-campaign-v0.1",
            "mode": "smoke" if smoke else "formal",
            "campaign_id": campaign_id,
            "build": build,
            "quiet_host": quiet,
            "reports": reports,
            "accepted": not smoke and all(report["accepted"] for report in reports),
        }
        result_root.mkdir(parents=True, exist_ok=False)
        (result_root / "aggregate.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )
        return result
    finally:
        fixture.cleanup()
        if binary.parent.exists():
            shutil.rmtree(binary.parent)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        print(json.dumps(run_campaign(parse_arguments().smoke), sort_keys=True))
    except (CampaignError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
