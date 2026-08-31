#!/usr/bin/env python3
"""Run the NDABI dynamic Supabase-compatible RLS campaign v0.1."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from semantic_batch_v02 import (
    CampaignError as FixtureCampaignError,
    DockerFixture,
    PINNED_POSTGRES,
    PINNED_TOXIPROXY,
    command as fixture_command,
    clean_checkout,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = ROOT / "campaigns" / "results" / "dynamic-supabase-rls-v01"
SPECIFICATION = ROOT / "specs" / "ndabi_dynamic_supabase_rls_campaign_v0_1.md"
EXAMPLE = "dynamic_rls_probe"
RELEASE_EXAMPLE = ROOT / "target" / "release" / "examples" / EXAMPLE
AUTHENTICATOR_ROLE = "ndabi_supabase_authenticator"
AUTHENTICATOR_PASSWORD = "ndabi-supabase-test-only"
SUBJECTS = ("user-a", "user-b")
STATIC_SOURCE_CLOSURE = (
    ROOT / "Cargo.toml",
    ROOT / "Cargo.lock",
    ROOT / "rust-toolchain.toml",
    ROOT / ".cargo" / "config.toml",
    ROOT / "crates" / "ndabi-supabase-v1" / "examples" / f"{EXAMPLE}.rs",
    ROOT / "campaigns" / "semantic_batch_v02.py",
    Path(__file__).resolve(),
    ROOT / "specs" / "ndabi_dynamic_isa_candidate_v0_1.md",
    SPECIFICATION,
)
LOCAL_CRATES = (
    "ndabi-isa",
    "ndabi-session",
    "ndabi-protocol",
    "ndabi-postgres",
    "ndabi-postgres-v1",
    "ndabi-supabase-v1",
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


class SupabaseRlsFixture(DockerFixture):
    def start(self) -> None:
        super().start()
        for _ in range(40):
            ready = fixture_command(
                [
                    "docker",
                    "exec",
                    self.postgres,
                    "pg_isready",
                    "-h",
                    self.toxiproxy,
                    "-p",
                    "8666",
                    "-U",
                    AUTHENTICATOR_ROLE,
                    "-d",
                    "postgres",
                ],
                check=False,
            )
            if ready.returncode == 0:
                return
            time.sleep(0.25)
        raise CampaignError("the Supabase proxy path did not become ready")

    def _seed_postgres(self) -> None:
        sql = f"""
        CREATE ROLE authenticated NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        CREATE ROLE {AUTHENTICATOR_ROLE} LOGIN PASSWORD '{AUTHENTICATOR_PASSWORD}'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        GRANT authenticated TO {AUTHENTICATOR_ROLE};
        ALTER ROLE {AUTHENTICATOR_ROLE} SET default_transaction_read_only=on;
        CREATE TABLE public.supabase_items(
            id bigint PRIMARY KEY,
            score bigint NOT NULL,
            owner_sub text NOT NULL
        );
        INSERT INTO public.supabase_items
        SELECT id,id % 10000,CASE WHEN id % 2=0 THEN 'user-a' ELSE 'user-b' END
        FROM generate_series(1,10000) AS id;
        ALTER TABLE public.supabase_items ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.supabase_items FORCE ROW LEVEL SECURITY;
        CREATE POLICY owner_reads ON public.supabase_items FOR SELECT TO authenticated
            USING (owner_sub=current_setting('request.jwt.claims',true)::jsonb->>'sub');
        GRANT CONNECT ON DATABASE postgres TO {AUTHENTICATOR_ROLE};
        GRANT USAGE ON SCHEMA public TO authenticated;
        GRANT SELECT ON public.supabase_items TO authenticated;
        ANALYZE public.supabase_items;
        """
        seed_arguments = [
            "docker",
            "exec",
            self.postgres,
            "psql",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ]
        for _ in range(30):
            seeded = fixture_command(seed_arguments, timeout=180, check=False)
            if seeded.returncode == 0:
                break
            detail = seeded.stderr.strip() or seeded.stdout.strip()
            if not transient_seed_failure(detail):
                raise CampaignError(f"Supabase RLS seeding failed: {detail}")
            time.sleep(1)
        else:
            raise CampaignError("PostgreSQL did not remain ready for Supabase RLS seeding")
        refused = fixture_command(
            [
                "docker",
                "exec",
                "--env",
                f"PGPASSWORD={AUTHENTICATOR_PASSWORD}",
                self.postgres,
                "psql",
                "-U",
                AUTHENTICATOR_ROLE,
                "-d",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "SET ROLE authenticated; UPDATE public.supabase_items SET score=0 WHERE id=1",
            ],
            check=False,
        )
        require(refused.returncode != 0, "the Supabase authenticator accepted a write")

    def reader_connection(self) -> str:
        return (
            f"host=127.0.0.1 port={self.proxy_port} user={AUTHENTICATOR_ROLE} "
            f"password={AUTHENTICATOR_PASSWORD} dbname=postgres"
        )


def transient_seed_failure(detail: str) -> bool:
    return any(
        message in detail
        for message in (
            "No such file or directory",
            "the database system is starting up",
            "the database system is shutting down",
        )
    )


def build_binary(destination: Path) -> dict[str, str]:
    command(
        [
            "cargo",
            "build",
            "--release",
            "-p",
            "ndabi-supabase-v1",
            "--example",
            EXAMPLE,
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


def run_probe(binary: Path, connection: str, subject: str) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["NDABI_SUPABASE_TEST_CONNECTION"] = connection
    completed = subprocess.run(
        [str(binary), subject],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
        env=environment,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise CampaignError(f"the {subject} probe failed: {detail}")
    report = json.loads(completed.stdout)
    require(report["subject"] == subject, "the probe reported the wrong subject")
    for gate in (
        "exact_results",
        "receipt_verified",
        "rls_isolated",
        "replay_refused",
        "mutation_refused",
        "principal_refused",
        "jwt_refusals",
    ):
        require(report[gate] is True, f"the {subject} probe failed {gate}")
    require(report["prepared_programs"] == 1, "the dynamic program was not prepared once")
    require(
        report["request_reduction_percent"] >= 70.0,
        "the cached request reduction fell below 70 percent",
    )
    return report


def evaluate_pair(reports: list[dict[str, Any]]) -> dict[str, Any]:
    require(len(reports) == 2, "the RLS pair is incomplete")
    by_subject = {report["subject"]: report for report in reports}
    require(set(by_subject) == set(SUBJECTS), "the RLS subjects changed")
    expected = {
        "user-a": [[2, "user-a"], [4, "user-a"], [6, "user-a"], [8, "user-a"]],
        "user-b": [[1, "user-b"], [3, "user-b"], [5, "user-b"], [7, "user-b"]],
    }
    gates = {
        "exact_user_a": by_subject["user-a"]["rows"] == expected["user-a"],
        "exact_user_b": by_subject["user-b"]["rows"] == expected["user-b"],
        "separate_results": by_subject["user-a"]["result_digest"]
        != by_subject["user-b"]["result_digest"],
        "complete_refusals": all(
            all(
                report[gate]
                for gate in (
                    "receipt_verified",
                    "replay_refused",
                    "mutation_refused",
                    "principal_refused",
                    "jwt_refusals",
                )
            )
            for report in reports
        ),
    }
    return {"accepted": all(gates.values()), "gates": gates}


def source_closure() -> tuple[Path, ...]:
    paths = set(STATIC_SOURCE_CLOSURE)
    for crate in LOCAL_CRATES:
        crate_root = ROOT / "crates" / crate
        paths.add(crate_root / "Cargo.toml")
        paths.update((crate_root / "src").rglob("*.rs"))
        build_script = crate_root / "build.rs"
        if build_script.is_file():
            paths.add(build_script)
    return tuple(sorted(paths))


def source_manifest() -> dict[str, Any]:
    closure = source_closure()
    files = {
        str(path.relative_to(ROOT)): sha256_file(path)
        for path in closure
        if path.is_file()
    }
    require(len(files) == len(closure), "the Supabase source closure is incomplete")
    digest = hashlib.sha256()
    for name, file_digest in sorted(files.items()):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(file_digest.encode())
        digest.update(b"\n")
    return {"sha256": digest.hexdigest(), "files": files}


def fixture_suffix(process_id: int, captured_unix_ns: int) -> str:
    suffix = f"ds01-{process_id}-{captured_unix_ns}"
    require(
        len(f"ndabi-semantic-toxiproxy-{suffix}") <= 63,
        "the campaign container name exceeds one DNS label",
    )
    return suffix


def cleanup_complete(cleanup: dict[str, Any]) -> bool:
    return all(
        cleanup.get(gate) is True
        for gate in (
            "containers_removed",
            "network_removed",
            "runner_pulled_proxy_image_removed",
            "temporary_binaries_removed",
        )
    ) and not cleanup.get("cleanup_errors")


def cleanup_campaign(
    fixture: SupabaseRlsFixture,
    binary_root: Path,
    result_root: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        cleanup = fixture.cleanup()
    except Exception as error:
        cleanup = {
            "containers_removed": False,
            "network_removed": False,
            "runner_pulled_proxy_image_removed": False,
        }
        errors.append(f"fixture cleanup failed: {type(error).__name__}: {error}")
    try:
        if binary_root.exists():
            shutil.rmtree(binary_root)
    except Exception as error:
        errors.append(f"temporary binary cleanup failed: {type(error).__name__}: {error}")
    cleanup["temporary_binaries_removed"] = not binary_root.exists()
    if errors:
        cleanup["cleanup_errors"] = errors
    cleanup["completed"] = cleanup_complete(cleanup)
    (result_root / "cleanup.json").write_text(
        json.dumps(cleanup, indent=2, sort_keys=True) + "\n"
    )
    return cleanup


def write_failure(
    result_root: Path,
    error: Exception,
    cleanup: dict[str, Any],
) -> None:
    (result_root / "failure.json").write_text(
        json.dumps(
            {
                "error_type": type(error).__name__,
                "message": str(error),
                "cleanup_completed": cleanup_complete(cleanup),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def run_campaign(smoke: bool) -> dict[str, Any]:
    if not smoke:
        require(clean_checkout(), "the formal campaign requires a clean checkout")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{time.time_ns()}"
    result_root = RESULT_ROOT / campaign_id
    binary = ROOT / "target" / "campaign-binaries" / campaign_id / EXAMPLE
    fixture = SupabaseRlsFixture(suffix=fixture_suffix(os.getpid(), time.time_ns()))
    result: dict[str, Any] | None = None
    failure: Exception | None = None
    result_root.mkdir(parents=True, exist_ok=False)
    try:
        source = source_manifest()
        build = build_binary(binary)
        fixture.start()
        repetitions = 1 if smoke else 5
        reports = []
        for repetition in range(1, repetitions + 1):
            probes = [
                run_probe(binary, fixture.reader_connection(), subject)
                for subject in SUBJECTS
            ]
            reports.append(
                {
                    "repetition": repetition,
                    "probes": probes,
                    **evaluate_pair(probes),
                }
            )
        require(
            source_manifest()["sha256"] == source["sha256"],
            "the source closure changed during the campaign",
        )
        result = {
            "schema": "ndabi-dynamic-supabase-rls-campaign-v0.1",
            "mode": "smoke" if smoke else "formal",
            "campaign_id": campaign_id,
            "source": source,
            "build": build,
            "images": {
                "references": {
                    "postgres": PINNED_POSTGRES,
                    "toxiproxy": PINNED_TOXIPROXY,
                },
                "ids": fixture.identities(),
            },
            "reports": reports,
        }
    except Exception as error:
        failure = error
    finally:
        cleanup = cleanup_campaign(fixture, binary.parent, result_root)
    if failure is not None:
        write_failure(result_root, failure, cleanup)
        raise failure
    require(result is not None, "the Supabase campaign result is absent")
    result["cleanup"] = cleanup
    result["accepted"] = (
        not smoke
        and all(report["accepted"] for report in result["reports"])
        and cleanup_complete(cleanup)
    )
    (result_root / "aggregate.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    if not cleanup_complete(cleanup):
        cleanup_failure = CampaignError("the Supabase campaign cleanup was incomplete")
        write_failure(result_root, cleanup_failure, cleanup)
        raise cleanup_failure
    return result


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
