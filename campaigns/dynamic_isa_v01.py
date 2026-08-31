#!/usr/bin/env python3
"""Run the frozen NDABI dynamic PostgreSQL campaign v0.1."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from semantic_batch_v02 import (
    CampaignError as FixtureCampaignError,
    DockerFixture,
    PINNED_POSTGRES,
    PINNED_TOXIPROXY,
    await_quiet_host,
    clean_checkout,
    host_snapshot,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = ROOT / "campaigns" / "results" / "dynamic-isa-v01"
SPECIFICATION = ROOT / "specs" / "ndabi_dynamic_postgres_campaign_v0_1.md"
EXAMPLE = "dynamic_isa_showdown"
RELEASE_EXAMPLE = ROOT / "target" / "release" / "examples" / EXAMPLE
ARMS = ("governed_native", "dynamic_full", "dynamic_cached")
FORMAL_CELLS = ((1, 1), (32, 1), (256, 1), (32, 8), (32, 32))
FORMAL_OPERATIONS = 4_096
SOURCE_CLOSURE = (
    ROOT / "Cargo.toml",
    ROOT / "Cargo.lock",
    ROOT / "rust-toolchain.toml",
    ROOT / "crates" / "ndabi-isa" / "Cargo.toml",
    ROOT / "crates" / "ndabi-isa" / "src" / "lib.rs",
    ROOT / "crates" / "ndabi-protocol" / "Cargo.toml",
    ROOT / "crates" / "ndabi-protocol" / "src" / "lib.rs",
    ROOT / "crates" / "ndabi-protocol" / "src" / "dynamic.rs",
    ROOT / "crates" / "ndabi-protocol" / "src" / "dynamic_cache.rs",
    ROOT / "crates" / "ndabi-postgres" / "src" / "isa.rs",
    ROOT / "crates" / "ndabi-postgres" / "Cargo.toml",
    ROOT / "crates" / "ndabi-postgres" / "examples" / f"{EXAMPLE}.rs",
    ROOT / "campaigns" / "semantic_batch_v02.py",
    Path(__file__).resolve(),
    ROOT / "specs" / "ndabi_dynamic_isa_candidate_v0_1.md",
    SPECIFICATION,
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
            "ndabi-postgres",
            "--example",
            EXAMPLE,
            "--features",
            "allocation-counting,benchmark-governed-native",
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
    result_rows: int,
    iterations: int,
    warmup: int,
    barrier: Path,
    worker: int,
) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["NDABI_TEST_READER_CONNECTION"] = connection
    environment["NDABI_CAMPAIGN_BARRIER"] = str(barrier)
    environment["NDABI_CAMPAIGN_WORKER"] = str(worker)
    completed = subprocess.run(
        [
            str(binary),
            "environment",
            arm,
            str(result_rows),
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
    require(report["allocation"] is not None, "the worker did not measure allocations")
    require(report["barrier_synchronised"], "the worker bypassed the campaign barrier")
    return report


def run_arm(
    binary: Path,
    connection: str,
    arm: str,
    result_rows: int,
    concurrency: int,
    total_operations: int,
    warmup: int,
) -> list[dict[str, Any]]:
    iterations = max(100, math.ceil(total_operations / concurrency))
    barrier_root = ROOT / "target" / "campaign-barriers"
    barrier_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{arm}-", dir=barrier_root) as temporary:
        barrier = Path(temporary)
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [
                executor.submit(
                    run_worker,
                    binary,
                    connection,
                    arm,
                    result_rows,
                    iterations,
                    warmup,
                    barrier,
                    worker,
                )
                for worker in range(concurrency)
            ]
            release_barrier_phase(barrier, futures, concurrency, "latency")
            release_barrier_phase(barrier, futures, concurrency, "throughput")
            return [future.result() for future in futures]


def release_barrier_phase(
    barrier: Path,
    futures: list[concurrent.futures.Future[dict[str, Any]]],
    concurrency: int,
    phase: str,
) -> None:
    deadline = time.monotonic() + 120
    release = barrier / f"release-{phase}"
    while len(list(barrier.glob(f"ready-{phase}-*"))) != concurrency:
        failed = next((future for future in futures if future.done()), None)
        if failed is not None:
            release_all_barrier_phases(barrier, "release after failure\n")
            failed.result()
        if time.monotonic() >= deadline:
            release_all_barrier_phases(barrier, "release after timeout\n")
            raise CampaignError(f"the workers did not reach the {phase} barrier")
        time.sleep(0.001)
    release.write_text("release\n")


def release_all_barrier_phases(barrier: Path, reason: str) -> None:
    for phase in ("latency", "throughput"):
        (barrier / f"release-{phase}").write_text(reason)


def aggregate_arm(reports: list[dict[str, Any]]) -> dict[str, Any]:
    require(bool(reports), "the arm has no worker reports")
    fingerprints = {report["result_fingerprint"] for report in reports}
    full_sizes = {report["full_request_bytes"] for report in reports}
    cached_sizes = {report["cached_request_bytes"] for report in reports}
    reductions = {report["request_reduction_percent"] for report in reports}
    require(len(fingerprints) == 1, "the arm result fingerprints differ")
    require(len(full_sizes) == 1, "the full request sizes differ")
    require(len(cached_sizes) == 1, "the cached request sizes differ")
    require(len(reductions) == 1, "the request reductions differ")
    require(
        all(report["barrier_synchronised"] for report in reports),
        "the arm contains an unsynchronised worker",
    )
    total_operations = sum(report["iterations"] for report in reports)
    started_ns = min(
        report["measurement_started_monotonic_ns"] for report in reports
    )
    ended_ns = max(report["measurement_ended_monotonic_ns"] for report in reports)
    elapsed_ns = ended_ns - started_ns
    require(elapsed_ns > 0, "the concurrent measurement interval is not positive")
    return {
        "workers": len(reports),
        "wall_mean_ns": statistics.median(report["wall"]["mean_ns"] for report in reports),
        "wall_p95_ns": statistics.median(report["wall"]["p95_ns"] for report in reports),
        "wall_p99_ns": statistics.median(report["wall"]["p99_ns"] for report in reports),
        "cpu_mean_ns": statistics.median(
            report["client_thread_cpu"]["mean_ns"] for report in reports
        ),
        "allocations": statistics.median(
            report["allocation"]["allocations"] for report in reports
        ),
        "allocated_bytes": statistics.median(
            report["allocation"]["allocated_bytes"] for report in reports
        ),
        "throughput_ops_s": total_operations * 1_000_000_000.0 / elapsed_ns,
        "measurement_elapsed_ns": elapsed_ns,
        "measurement_started_monotonic_ns": started_ns,
        "measurement_ended_monotonic_ns": ended_ns,
        "barrier_synchronised": True,
        "full_request_bytes": next(iter(full_sizes)),
        "cached_request_bytes": next(iter(cached_sizes)),
        "request_reduction_percent": next(iter(reductions)),
        "result_fingerprint": next(iter(fingerprints)),
    }


def evaluate_cell(arms: dict[str, dict[str, Any]]) -> dict[str, Any]:
    native = arms["governed_native"]
    full = arms["dynamic_full"]
    cached = arms["dynamic_cached"]
    fingerprints = {value["result_fingerprint"] for value in arms.values()}
    gates = {
        "exact_cross_arm_results": len(fingerprints) == 1,
        "request_reduction": cached["request_reduction_percent"] >= 70.0,
        "p95_floor": cached["wall_p95_ns"] <= native["wall_p95_ns"] * 1.05,
        "mean_floor": cached["wall_mean_ns"] <= native["wall_mean_ns"] * 1.03,
        "client_cpu_floor": cached["cpu_mean_ns"] <= native["cpu_mean_ns"] * 1.15,
        "allocation_non_regression": cached["allocated_bytes"] <= full["allocated_bytes"],
        "throughput_floor": cached["throughput_ops_s"] >= native["throughput_ops_s"] * 0.95,
    }
    return {"gates": gates, "accepted": all(gates.values())}


def coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2 or statistics.mean(values) == 0.0:
        return float("inf")
    return statistics.pstdev(values) / statistics.mean(values)


def evaluate_repeatability(reports: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for report in reports:
        grouped[(report["result_rows"], report["concurrency"])].append(report)
    cells: dict[str, Any] = {}
    accepted = True
    for result_rows, concurrency in FORMAL_CELLS:
        samples = grouped.get((result_rows, concurrency), [])
        metrics: dict[str, float] = {}
        cell_accepted = len(samples) == 5
        for arm in ARMS:
            for metric in ("wall_mean_ns", "wall_p95_ns"):
                values = [float(sample["arms"][arm][metric]) for sample in samples]
                variation = coefficient_of_variation(values)
                metrics[f"{arm}_{metric}_cv"] = variation
                cell_accepted = cell_accepted and variation < 0.10
        key = f"rows-{result_rows}-concurrency-{concurrency}"
        cells[key] = {
            "accepted": cell_accepted,
            "metrics": metrics,
            "repetitions": len(samples),
        }
        accepted = accepted and cell_accepted
    return {"accepted": accepted, "cells": cells}


def source_manifest() -> dict[str, Any]:
    files = {
        str(path.relative_to(ROOT)): sha256_file(path)
        for path in SOURCE_CLOSURE
        if path.is_file()
    }
    if len(files) != len(SOURCE_CLOSURE):
        raise CampaignError("the dynamic ISA source closure is incomplete")
    digest = hashlib.sha256()
    for name, file_digest in sorted(files.items()):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(file_digest.encode())
        digest.update(b"\n")
    return {"sha256": digest.hexdigest(), "files": files}


def run_campaign(smoke: bool) -> dict[str, Any]:
    if not smoke:
        require(clean_checkout(), "the formal campaign requires a clean checkout")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns()}"
    result_root = RESULT_ROOT / campaign_id
    binary = ROOT / "target" / "campaign-binaries" / campaign_id / EXAMPLE
    fixture = DockerFixture(suffix=f"dynamic-v01-{os.getpid()}-{time.time_ns()}")
    reports: list[dict[str, Any]] = []
    cleanup: dict[str, Any] = {"completed": False}
    try:
        build = build_binary(binary)
        qualification = (
            {"qualified": False, "reason": "smoke mode"}
            if smoke
            else await_quiet_host()
        )
        pre_host = host_snapshot()
        fixture.start()
        image_ids = fixture.identities()
        repetitions = 1 if smoke else 5
        cells = ((32, 1),) if smoke else FORMAL_CELLS
        total_operations = 100 if smoke else FORMAL_OPERATIONS
        for repetition in range(repetitions):
            for cell_index, (result_rows, concurrency) in enumerate(cells):
                offset = (repetition + cell_index) % len(ARMS)
                order = ARMS[offset:] + ARMS[:offset]
                warmup = 10 if smoke else max(10, math.ceil(64 / concurrency))
                arm_reports = {
                    arm: run_arm(
                        binary,
                        fixture.reader_connection(),
                        arm,
                        result_rows,
                        concurrency,
                        total_operations,
                        warmup,
                    )
                    for arm in order
                }
                arms = {arm: aggregate_arm(arm_reports[arm]) for arm in ARMS}
                reports.append(
                    {
                        "repetition": repetition + 1,
                        "result_rows": result_rows,
                        "concurrency": concurrency,
                        "arm_order": order,
                        "arms": arms,
                        "worker_reports": arm_reports,
                        **evaluate_cell(arms),
                    }
                )
        repeatability = evaluate_repeatability(reports) if not smoke else None
        accepted = (
            not smoke
            and all(report["accepted"] for report in reports)
            and repeatability is not None
            and repeatability["accepted"]
        )
        result = {
            "schema": "ndabi-dynamic-isa-campaign-v0.1",
            "mode": "smoke" if smoke else "formal",
            "campaign_id": campaign_id,
            "source": source_manifest(),
            "build": build,
            "images": {
                "references": {
                    "postgres": PINNED_POSTGRES,
                    "toxiproxy": PINNED_TOXIPROXY,
                },
                "ids": image_ids,
            },
            "qualification": qualification,
            "pre_host": pre_host,
            "post_host": host_snapshot(),
            "reports": reports,
            "repeatability": repeatability,
            "accepted": accepted,
        }
        result_root.mkdir(parents=True, exist_ok=False)
        (result_root / "aggregate.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )
        return result
    finally:
        cleanup = fixture.cleanup()
        if binary.parent.exists():
            shutil.rmtree(binary.parent)
        if result_root.exists():
            (result_root / "cleanup.json").write_text(
                json.dumps(cleanup, indent=2, sort_keys=True) + "\n"
            )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        print(json.dumps(run_campaign(parse_arguments().smoke), sort_keys=True))
    except (
        CampaignError,
        FixtureCampaignError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
