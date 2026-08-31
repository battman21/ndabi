#!/usr/bin/env python3
"""Run the floor-adjusted NDABI operand bundle campaign v0.2."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import operand_bundle_v01 as base
from semantic_batch_v02 import (
    PINNED_POSTGRES,
    PINNED_TOXIPROXY,
    await_quiet_host,
    clean_checkout,
    host_snapshot,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = ROOT / "campaigns" / "results" / "operand-bundle-v02"
SPECIFICATION = ROOT / "specs" / "ndabi_operand_bundle_campaign_v0_2.md"
FORMAL_CELLS = ((8, 1), (128, 1), (1_024, 1), (1_024, 8), (1_024, 32))
SOURCE_CLOSURE = (
    ROOT / "Cargo.toml",
    ROOT / "Cargo.lock",
    ROOT / "rust-toolchain.toml",
    ROOT / "crates" / "ndabi-protocol" / "src" / "operand_bundle.rs",
    ROOT / "crates" / "ndabi-postgres-v1" / "src" / "lib.rs",
    ROOT / "crates" / "ndabi-postgres-v1" / "src" / "operand_bundle.rs",
    ROOT
    / "crates"
    / "ndabi-postgres-v1"
    / "examples"
    / "review_operand_bundle_showdown.rs",
    ROOT / "campaigns" / "operand_bundle_v01.py",
    ROOT / "campaigns" / "semantic_batch_v02.py",
    Path(__file__).resolve(),
    SPECIFICATION,
)


def protocol_excess(measured: float, fused_floor: float) -> float:
    """Return measurable client cost above the equivalent native database floor."""
    return max(measured - fused_floor, 0.0)


def reduction_gate(candidate: float, control: float, minimum_reduction: float) -> bool:
    """Accept zero excess, or require the candidate to reduce positive control excess."""
    if control == 0.0:
        return candidate == 0.0
    return candidate <= control * (1.0 - minimum_reduction)


def evaluate_cell(arms: dict[str, dict[str, Any]], item_count: int) -> dict[str, Any]:
    fused = arms["fused_native"]
    graph = arms["ndabi_graph"]
    bundle = arms["ndabi_bundle"]
    graph_cpu_excess = protocol_excess(graph["cpu_mean_ns"], fused["cpu_mean_ns"])
    bundle_cpu_excess = protocol_excess(bundle["cpu_mean_ns"], fused["cpu_mean_ns"])
    graph_allocation_excess = protocol_excess(
        graph["allocated_bytes"], fused["allocated_bytes"]
    )
    bundle_allocation_excess = protocol_excess(
        bundle["allocated_bytes"], fused["allocated_bytes"]
    )
    gates = {
        "request_reduction": item_count < 1_024
        or bundle["request_reduction_percent"] >= 70.0,
        "one_static_decode": all(value == 1 for value in bundle["bundle_decodes"]),
        "p95_floor": bundle["wall_p95_ns"] <= fused["wall_p95_ns"] * 1.05,
        "mean_floor": bundle["wall_mean_ns"] <= fused["wall_mean_ns"] * 1.03,
        "complete_cpu_floor": bundle["cpu_mean_ns"] <= fused["cpu_mean_ns"] * 1.25,
        "protocol_cpu_reduction": reduction_gate(
            bundle_cpu_excess, graph_cpu_excess, 0.25
        ),
        "allocation_non_regression": bundle["allocated_bytes"]
        <= graph["allocated_bytes"],
        "protocol_allocation_reduction": reduction_gate(
            bundle_allocation_excess, graph_allocation_excess, 0.50
        ),
    }
    return {
        "gates": gates,
        "accepted": all(gates.values()),
        "floor_adjusted": {
            "graph_cpu_excess_ns": graph_cpu_excess,
            "bundle_cpu_excess_ns": bundle_cpu_excess,
            "graph_allocation_excess_bytes": graph_allocation_excess,
            "bundle_allocation_excess_bytes": bundle_allocation_excess,
        },
    }


def coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2 or statistics.mean(values) == 0.0:
        return float("inf")
    return statistics.pstdev(values) / statistics.mean(values)


def evaluate_repeatability(reports: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for report in reports:
        grouped[(report["item_count"], report["concurrency"])].append(report)
    cells: dict[str, Any] = {}
    accepted = True
    for item_count, concurrency in FORMAL_CELLS:
        key = (item_count, concurrency)
        samples = grouped.get(key, [])
        cell_metrics: dict[str, float] = {}
        cell_accepted = len(samples) == 5
        for arm in base.ARMS:
            for metric in ("wall_mean_ns", "wall_p95_ns"):
                values = [float(sample["arms"][arm][metric]) for sample in samples]
                variation = coefficient_of_variation(values)
                cell_metrics[f"{arm}_{metric}_cv"] = variation
                cell_accepted = cell_accepted and variation < 0.10
        cells[f"items-{item_count}-concurrency-{concurrency}"] = {
            "accepted": cell_accepted,
            "metrics": cell_metrics,
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
        raise base.CampaignError("the v0.2 source closure is incomplete")
    digest = hashlib.sha256()
    for name, file_digest in sorted(files.items()):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(file_digest.encode())
        digest.update(b"\n")
    return {"sha256": digest.hexdigest(), "files": files}


def run_campaign(smoke: bool) -> dict[str, Any]:
    if not smoke:
        base.require(clean_checkout(), "the formal campaign requires a clean checkout")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns()}"
    result_root = RESULT_ROOT / campaign_id
    binary = ROOT / "target" / "campaign-binaries" / campaign_id / base.EXAMPLE
    fixture = base.DockerFixture(suffix=f"bundle-v02-{os.getpid()}-{time.time_ns()}")
    reports: list[dict[str, Any]] = []
    cleanup: dict[str, Any] = {"completed": False}
    try:
        build = base.build_binary(binary)
        qualification = (
            {"qualified": False, "reason": "smoke mode"}
            if smoke
            else await_quiet_host()
        )
        pre_host = host_snapshot()
        fixture.start()
        image_ids = fixture.identities()
        repetitions = 1 if smoke else 5
        cells = ((1_024, 1),) if smoke else FORMAL_CELLS
        iterations = 100 if smoke else 4_096
        warmup = 10 if smoke else 64
        for repetition in range(repetitions):
            for cell_index, (item_count, concurrency) in enumerate(cells):
                offset = (repetition + cell_index) % len(base.ARMS)
                order = base.ARMS[offset:] + base.ARMS[:offset]
                arm_reports = {
                    arm: base.run_arm(
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
                arms = {arm: base.aggregate_arm(arm_reports[arm]) for arm in base.ARMS}
                reports.append(
                    {
                        "repetition": repetition + 1,
                        "item_count": item_count,
                        "concurrency": concurrency,
                        "arm_order": order,
                        "arms": arms,
                        "worker_reports": arm_reports,
                        **evaluate_cell(arms, item_count),
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
            "schema": "ndabi-operand-bundle-campaign-v0.2",
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
    except (base.CampaignError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=os.sys.stderr)
        raise SystemExit(1) from error
