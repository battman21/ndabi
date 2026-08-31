#!/usr/bin/env python3
"""Prove the NDABI Supabase bundle against the complete local stack."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKDIR = Path(__file__).resolve().parent
CLI = ["npx", "--yes", "supabase@2.116.0"]
NETWORK = "ndabi-supabase-local"
DATABASE_URL = (
    "host=127.0.0.1 port=55322 user=postgres password=postgres dbname=postgres"
)


class ProofError(RuntimeError):
    """Reject an incomplete local-stack proof."""


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
        raise ProofError(f"command failed: {arguments[0]}: {detail}")
    return completed


def stack_status() -> dict:
    completed = subprocess.run(
        CLI + ["status", "--workdir", str(WORKDIR), "--output", "json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        return {}
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {}


def api_health() -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:55321/auth/v1/health", timeout=5
            ) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise ProofError("the Supabase Auth health endpoint did not become ready")


def run() -> dict:
    existing = stack_status()
    started = not bool(existing)
    network_created = False
    try:
        if started:
            inspect = subprocess.run(
                ["docker", "network", "inspect", NETWORK],
                cwd=ROOT,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if inspect.returncode != 0:
                command(
                    [
                        "docker",
                        "network",
                        "create",
                        "-o",
                        "com.docker.network.bridge.host_binding_ipv4=127.0.0.1",
                        NETWORK,
                    ],
                    timeout=30,
                )
                network_created = True
            command(
                CLI
                + [
                    "start",
                    "--workdir",
                    str(WORKDIR),
                    "--network-id",
                    NETWORK,
                ],
                timeout=1_800,
            )
        api_health()
        status = stack_status()
        if not status:
            raise ProofError("the Supabase CLI did not report a running stack")
        environment = os.environ.copy()
        environment["NDABI_SUPABASE_GRAPH_TEST_URL"] = DATABASE_URL
        completed = subprocess.run(
            [
                "cargo",
                "test",
                "-p",
                "ndabi-supabase-v1",
                "--test",
                "review_batch_graph",
                "--locked",
                "--",
                "--ignored",
                "--exact",
                "one_registered_graph_preserves_supabase_rls_and_exact_receipts",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=600,
            check=False,
            env=environment,
        )
        if completed.returncode != 0:
            detail = "\n".join(
                part
                for part in (completed.stdout.strip(), completed.stderr.strip())
                if part
            )
            raise ProofError(f"the NDABI Supabase integration failed: {detail}")
        return {
            "schema": "ndabi-supabase-full-stack-proof-v0.1",
            "cli_version": command(CLI + ["--version"], timeout=60).stdout.strip(),
            "stack_reported": True,
            "auth_health": True,
            "forced_rls": True,
            "operand_bundle": True,
            "exact_results": True,
            "receipt_verified": True,
        }
    finally:
        if started:
            subprocess.run(
                CLI + ["stop", "--workdir", str(WORKDIR), "--no-backup"],
                cwd=ROOT,
                capture_output=True,
                timeout=300,
                check=False,
            )
        if network_created:
            subprocess.run(
                ["docker", "network", "rm", NETWORK],
                cwd=ROOT,
                capture_output=True,
                timeout=30,
                check=False,
            )


if __name__ == "__main__":
    try:
        print(json.dumps(run(), sort_keys=True))
    except (OSError, ProofError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
