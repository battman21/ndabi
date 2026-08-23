#!/usr/bin/env python3
"""Run the frozen local Supavisor session campaign v7.2."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import cryptography

import validation_suite_v71 as v71


ROOT = Path(__file__).resolve().parent
BINARY = v71.BINARY
POSTGRES_IMAGE = v71.POSTGRES_IMAGE
POSTGREST_IMAGE = v71.POSTGREST_IMAGE
SUPAVISOR_IMAGE = "supabase/supavisor@sha256:31c2f05b13b11069660fdfae2f6cfd37b509748d2710aca121cfee8b16cb8b07"
POOLER_CONFIG = ROOT / "support" / "v72" / "pooler.exs"
RESULT_ROOT = ROOT / "results" / "v72"
PROCESS_COUNT = 5
TENANT_ID = "ndabi-v72"
EXPECTED_QUERIES_PER_ARM = v71.EXPECTED_QUERIES
SOURCE_PATHS = v71.SOURCE_PATHS + (
    "validation_suite_v72.py",
    "requirements-v72.txt",
    "support/v72/pooler.exs",
    "../../specs/ndabi_supavisor_session_campaign_v7_2.md",
)


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def repository_root() -> Path:
    return Path(
        command("git", "-C", str(ROOT), "rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = (ROOT / relative).resolve()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def source_matches_commit(repository: Path, commit: str) -> bool:
    for relative in SOURCE_PATHS:
        source = (ROOT / relative).resolve()
        try:
            repository_path = source.relative_to(repository).as_posix()
        except ValueError:
            return False
        candidate = subprocess.run(
            ["git", "show", f"{commit}:{repository_path}"],
            cwd=repository,
            check=False,
            capture_output=True,
        )
        if candidate.returncode != 0 or candidate.stdout != source.read_bytes():
            return False
    return True


def committed_source() -> str:
    repository = repository_root()
    commit = command("git", "-C", str(repository), "rev-parse", "HEAD").stdout.strip()
    if not commit or not source_matches_commit(repository, commit):
        raise SystemExit("commit every registered source file before the campaign")
    return commit


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def psql(
    container: str,
    statement: str,
    user: str = "postgres",
    password: str | None = None,
) -> subprocess.CompletedProcess:
    arguments = ["docker", "exec"]
    if password is not None:
        arguments.extend(["--env", f"PGPASSWORD={password}"])
    arguments.extend(
        [
            container,
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            user,
            "-d",
            "ndabi",
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            statement,
        ]
    )
    return command(*arguments)


def setup_database(postgres: str) -> tuple[str, str]:
    statements = (
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
        "CREATE EXTENSION pg_stat_statements",
        "CREATE ROLE anon NOLOGIN",
        "CREATE ROLE authenticated NOLOGIN",
        "CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'auth-test-only'",
        "GRANT authenticated TO authenticator",
        "CREATE ROLE pgbouncer LOGIN PASSWORD 'ndabi-test-only'",
        "CREATE SCHEMA pgbouncer AUTHORIZATION pgbouncer",
        "CREATE FUNCTION pgbouncer.get_auth(p_usename text) RETURNS TABLE(username text,password text) LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$BEGIN RETURN QUERY SELECT rolname::text,CASE WHEN rolvaliduntil < now() THEN NULL ELSE rolpassword::text END FROM pg_authid WHERE rolname=p_usename AND rolcanlogin; END$$",
        "REVOKE ALL ON FUNCTION pgbouncer.get_auth(text) FROM PUBLIC",
        "GRANT EXECUTE ON FUNCTION pgbouncer.get_auth(text) TO pgbouncer",
        "CREATE TABLE supabase_items(id bigint PRIMARY KEY,bucket integer NOT NULL,owner integer NOT NULL,score integer NOT NULL,payload bytea NOT NULL,owner_sub text NOT NULL)",
        "INSERT INTO supabase_items SELECT value,(value%1000)::integer,(value%100)::integer,(value%10000)::integer,decode(repeat(lpad(to_hex(value%256),2,'0'),64),'hex'),CASE WHEN value<=200000 THEN 'user-1' ELSE 'user-2' END FROM generate_series(1,1000000) AS value",
        "ANALYZE supabase_items",
        "GRANT USAGE ON SCHEMA public TO authenticated",
        "GRANT SELECT ON supabase_items TO authenticated",
        "ALTER TABLE supabase_items ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE supabase_items FORCE ROW LEVEL SECURITY",
        "CREATE POLICY user_rows ON supabase_items FOR SELECT TO authenticated USING (owner_sub = (current_setting('request.jwt.claims',true)::json ->> 'sub'))",
        f"CREATE FUNCTION check_token() RETURNS void LANGUAGE plpgsql AS $$DECLARE claims json:=current_setting('request.jwt.claims',true)::json; BEGIN IF claims->>'iss'<>'{v71.ISSUER}' OR claims->>'aud'<>'{v71.AUDIENCE}' OR claims->>'role'<>'authenticated' OR coalesce(claims->>'sub','')='' THEN RAISE insufficient_privilege; END IF; END$$",
        "REVOKE ALL ON FUNCTION check_token() FROM PUBLIC",
        "GRANT EXECUTE ON FUNCTION check_token() TO authenticated",
    )
    for statement in statements:
        psql(postgres, statement)
    role_state = psql(
        postgres,
        "SELECT rolsuper,rolcreaterole,rolcreatedb,rolcanlogin FROM pg_roles WHERE rolname='authenticator'",
    ).stdout.strip()
    rls_state = psql(
        postgres,
        "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname='supabase_items'",
    ).stdout.strip()
    return role_state, rls_state


def start_postgrest(
    name: str,
    network: str,
    postgres: str,
    jwks: str,
) -> str:
    command(
        "docker",
        "run",
        "--detach",
        "--name",
        name,
        "--network",
        network,
        "--publish",
        "127.0.0.1::3000",
        "--env",
        f"PGRST_DB_URI=postgresql://authenticator:auth-test-only@{postgres}:5432/ndabi",
        "--env",
        "PGRST_DB_SCHEMAS=public",
        "--env",
        "PGRST_DB_ANON_ROLE=anon",
        "--env",
        f"PGRST_JWT_SECRET={jwks}",
        "--env",
        f"PGRST_JWT_AUD={v71.AUDIENCE}",
        "--env",
        "PGRST_DB_PRE_REQUEST=public.check_token",
        "--env",
        "PGRST_LOG_LEVEL=warn",
        POSTGREST_IMAGE,
    )
    for _ in range(60):
        logs = command("docker", "logs", name, check=False)
        if "API server listening" in logs.stdout + logs.stderr:
            port = command("docker", "port", name, "3000/tcp").stdout.strip()
            return port.rsplit(":", 1)[1]
        time.sleep(1)
    raise RuntimeError("PostgREST did not become ready")


def start_supavisor(name: str, network: str, postgres: str) -> str:
    command(
        "docker",
        "run",
        "--detach",
        "--name",
        name,
        "--network",
        network,
        "--publish",
        "127.0.0.1::5432",
        "--mount",
        f"type=bind,source={POOLER_CONFIG},target=/etc/pooler/pooler.exs,readonly",
        "--env",
        "PORT=4000",
        "--env",
        "PROXY_PORT_SESSION=5432",
        "--env",
        "PROXY_PORT_TRANSACTION=6543",
        "--env",
        f"POSTGRES_HOST={postgres}",
        "--env",
        "POSTGRES_PORT=5432",
        "--env",
        "POSTGRES_DB=ndabi",
        "--env",
        "POSTGRES_PASSWORD=ndabi-test-only",
        "--env",
        f"DATABASE_URL=ecto://postgres:ndabi-test-only@{postgres}:5432/ndabi",
        "--env",
        "CLUSTER_POSTGRES=true",
        "--env",
        "SECRET_KEY_BASE=ndabi-v72-test-only-secret-key-base-0123456789-abcdefghijklmnopqrstuvwxyz",
        "--env",
        "VAULT_ENC_KEY=12345678901234567890123456789012",
        "--env",
        "API_JWT_SECRET=ndabi-v72-test-only-api-jwt-secret",
        "--env",
        "METRICS_JWT_SECRET=ndabi-v72-test-only-metrics-secret",
        "--env",
        "REGION=local",
        "--env",
        "ERL_AFLAGS=-proto_dist inet_tcp",
        "--env",
        f"POOLER_TENANT_ID={TENANT_ID}",
        "--env",
        "POOLER_DEFAULT_POOL_SIZE=20",
        "--env",
        "POOLER_MAX_CLIENT_CONN=100",
        "--env",
        "POOLER_POOL_MODE=session",
        "--env",
        "DB_POOL_SIZE=5",
        SUPAVISOR_IMAGE,
        "/bin/sh",
        "-c",
        '/app/bin/migrate && /app/bin/supavisor eval "$(cat /etc/pooler/pooler.exs)" && /app/bin/server',
    )
    for _ in range(90):
        probe = command(
            "docker",
            "exec",
            "--env",
            "PGPASSWORD=auth-test-only",
            postgres,
            "psql",
            "-h",
            name,
            "-p",
            "5432",
            "-U",
            f"authenticator.{TENANT_ID}",
            "-d",
            "ndabi",
            "-At",
            "-c",
            "SELECT 1",
            check=False,
        )
        if probe.returncode == 0 and probe.stdout.strip() == "1":
            port = command("docker", "port", name, "5432/tcp").stdout.strip()
            return port.rsplit(":", 1)[1]
        time.sleep(1)
    logs = command("docker", "logs", name, check=False)
    raise RuntimeError(f"Supavisor did not become ready: {logs.stderr[-2000:]}")


def session_proof(postgres: str, supavisor: str) -> bool:
    completed = command(
        "docker",
        "exec",
        "--env",
        "PGPASSWORD=auth-test-only",
        postgres,
        "psql",
        "-h",
        supavisor,
        "-p",
        "5432",
        "-U",
        f"authenticator.{TENANT_ID}",
        "-d",
        "ndabi",
        "-At",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        "SET application_name='ndabi-v72-session-proof'",
        "-c",
        "PREPARE ndabi_session_proof(integer) AS SELECT $1::integer",
        "-c",
        "EXECUTE ndabi_session_proof(72)",
        "-c",
        "SELECT current_setting('application_name')",
        check=False,
    )
    lines = {line.strip() for line in completed.stdout.splitlines() if line.strip()}
    return completed.returncode == 0 and {"72", "ndabi-v72-session-proof"}.issubset(lines)


def security_checks(
    pooled_connection: str,
    endpoint: str,
    token_paths: dict[str, Path],
    public_key: Path,
    valid_one: str,
) -> dict[str, bool]:
    admissions = v71.admission_probe(token_paths, public_key)
    security = {
        "valid_token_accepted": admissions["valid"],
        "changed_signature_refused": not admissions["changed_signature"],
        "unknown_key_refused": not admissions["unknown_key"],
        "wrong_issuer_refused": not admissions["wrong_issuer"],
        "wrong_audience_refused": not admissions["wrong_audience"],
        "expired_token_refused": not admissions["expired"],
        "unsigned_subject_refused": not admissions["unsigned_subject"],
        "elevated_role_refused": not admissions["elevated_role"],
    }
    authorised = command(
        str(BINARY), "--ndabi-probe", pooled_connection, str(token_paths["valid"]),
        str(public_key), v71.KEY_ID, v71.ISSUER, v71.AUDIENCE, "1000", "2", check=False,
    )
    cross_subject = command(
        str(BINARY), "--ndabi-probe", pooled_connection, str(token_paths["valid"]),
        str(public_key), v71.KEY_ID, v71.ISSUER, v71.AUDIENCE, "900000", "2", check=False,
    )
    second_subject = command(
        str(BINARY), "--ndabi-probe", pooled_connection, str(token_paths["user_two"]),
        str(public_key), v71.KEY_ID, v71.ISSUER, v71.AUDIENCE, "900000", "2", check=False,
    )
    try:
        report = json.loads(authorised.stdout) if authorised.returncode == 0 else {}
    except json.JSONDecodeError:
        report = {}
    security.update(
        {
            "authorised_ndabi_rows_accepted": authorised.returncode == 0,
            "cross_subject_ndabi_rows_refused": cross_subject.returncode != 0,
            "second_subject_ndabi_rows_accepted": second_subject.returncode == 0,
            "changed_ndabi_frame_refused": report.get("changed_frame_refused") is True,
            "ndabi_replay_refused_before_query": report.get("replay_refused_before_query") is True,
            "invalid_ndabi_receipt_refused": report.get("invalid_receipt_refused") is True,
            "valid_ndabi_result_accepted": report.get("valid_result_accepted") is True,
        }
    )
    status, body = v71.shared.request(
        f"{endpoint}?select=id&id=gte.900000&id=lt.900002", bearer=valid_one
    )
    try:
        hidden_rows = json.loads(body)
    except json.JSONDecodeError:
        hidden_rows = None
    security["cross_subject_postgrest_rows_hidden"] = status == 200 and hidden_rows == []
    write_status, _ = v71.shared.request(
        endpoint,
        method="POST",
        bearer=valid_one,
        body=b'{"id":1000001,"bucket":1,"owner":1,"score":1,"payload":"\\x00","owner_sub":"user-1"}',
    )
    security["user_write_refused"] = write_status >= 400
    return security


def measurement(report: dict, operations: int, arm: str) -> dict:
    case = next(item for item in report["cases"] if item["operations"] == operations)
    return next(item for item in case["measurements"] if item["arm"] == arm)


def compare_pair(direct: dict, pooled: dict) -> dict:
    try:
        v71.validate_report(direct)
        v71.validate_report(pooled)
    except (KeyError, TypeError, ValueError) as error:
        return {"cases": [], "validation_error": str(error), "passed": False}
    cases = []
    for operations in v71.BATCH_SIZES:
        direct_case = next(item for item in direct["cases"] if item["operations"] == operations)
        pooled_case = next(item for item in pooled["cases"] if item["operations"] == operations)
        direct_ndabi = measurement(direct, operations, "ndabi-indexed-batch-session")
        pooled_ndabi = measurement(pooled, operations, "ndabi-indexed-batch-session")
        pooled_rest = measurement(pooled, operations, "postgrest-user-jwt")
        pooled_to_direct = pooled_ndabi["p50_ns"] / direct_ndabi["p50_ns"]
        pooled_to_postgrest = pooled_ndabi["p50_ns"] / pooled_rest["p50_ns"]
        exact = (
            pooled_case["result_sha256"] == direct_case["result_sha256"]
            and pooled_case["result_bytes"] == direct_case["result_bytes"]
            and pooled_case["ndabi_request_bytes"] == direct_case["ndabi_request_bytes"]
        )
        performance = operations == 2 or (
            pooled_to_direct <= 1.50 and pooled_to_postgrest <= 0.20
        )
        cases.append(
            {
                "operations": operations,
                "pooled_to_direct_p50_ratio": pooled_to_direct,
                "pooled_to_postgrest_p50_ratio": pooled_to_postgrest,
                "canonical_result_equal": exact,
                "passed": exact and performance and direct_case["passed"] and pooled_case["passed"],
            }
        )
    return {
        "cases": cases,
        "validation_error": None,
        "passed": all(case["passed"] for case in cases),
    }


def data_queries(postgres: str) -> int:
    return int(
        psql(
            postgres,
            "SELECT coalesce(sum(calls),0)::bigint FROM pg_stat_statements WHERE query LIKE '%supabase_items%' AND query NOT LIKE '%pg_stat_statements%'",
        ).stdout.strip()
    )


def run_arm(
    connection: str,
    endpoint: str,
    token_path: Path,
    public_key: Path,
) -> tuple[subprocess.CompletedProcess, dict]:
    completed = command(
        str(BINARY), connection, endpoint, str(token_path), str(public_key),
        v71.KEY_ID, v71.ISSUER, v71.AUDIENCE, check=False,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        report = {
            "parsed": False,
            "validated": False,
            "validation_error": str(error),
            "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
            "passed": False,
        }
        return completed, report
    validation_error = None
    try:
        v71.validate_report(report)
    except (KeyError, TypeError, ValueError) as error:
        validation_error = str(error)
    report["parsed"] = True
    report["validated"] = validation_error is None
    report["validation_error"] = validation_error
    return completed, report


def campaign_summary(direct_reports: list[dict], pooled_reports: list[dict]) -> list[dict]:
    summary = []
    for operations in v71.BATCH_SIZES:
        direct_ndabi = [
            measurement(report, operations, "ndabi-indexed-batch-session")
            for report in direct_reports
        ]
        pooled_ndabi = [
            measurement(report, operations, "ndabi-indexed-batch-session")
            for report in pooled_reports
        ]
        direct_rest = [
            measurement(report, operations, "postgrest-user-jwt")
            for report in direct_reports
        ]
        pooled_rest = [
            measurement(report, operations, "postgrest-user-jwt")
            for report in pooled_reports
        ]
        pooled_cases = [
            next(case for case in report["cases"] if case["operations"] == operations)
            for report in pooled_reports
        ]
        summary.append(
            {
                "operations": operations,
                "direct_ndabi_median_p50_ns": int(
                    statistics.median(item["p50_ns"] for item in direct_ndabi)
                ),
                "pooled_ndabi_median_p50_ns": int(
                    statistics.median(item["p50_ns"] for item in pooled_ndabi)
                ),
                "direct_postgrest_median_p50_ns": int(
                    statistics.median(item["p50_ns"] for item in direct_rest)
                ),
                "pooled_postgrest_median_p50_ns": int(
                    statistics.median(item["p50_ns"] for item in pooled_rest)
                ),
                "pooled_to_direct_median_p50_ratio": statistics.median(
                    pooled["p50_ns"] / direct["p50_ns"]
                    for direct, pooled in zip(direct_ndabi, pooled_ndabi, strict=True)
                ),
                "pooled_speedup_over_postgrest": statistics.median(
                    rest["p50_ns"] / pooled["p50_ns"]
                    for pooled, rest in zip(pooled_ndabi, pooled_rest, strict=True)
                ),
                "direct_speedup_over_postgrest": statistics.median(
                    rest["p50_ns"] / direct["p50_ns"]
                    for direct, rest in zip(direct_ndabi, direct_rest, strict=True)
                ),
                "minimum_request_reduction": statistics.median(
                    case["minimum_request_reduction"] for case in pooled_cases
                ),
                "database_query_reduction": statistics.median(
                    case["database_query_reduction"] for case in pooled_cases
                ),
                "pooled_median_mean_allocations": statistics.median(
                    item["mean_allocations"] for item in pooled_ndabi
                ),
                "pooled_median_mean_allocated_bytes": statistics.median(
                    item["mean_allocated_bytes"] for item in pooled_ndabi
                ),
            }
        )
    return summary


def repeatability(pairs: list[dict]) -> tuple[list[dict], bool]:
    evidence = []
    if len(pairs) != PROCESS_COUNT or any(
        len(pair.get("cases", [])) != len(v71.BATCH_SIZES) for pair in pairs
    ):
        return evidence, False
    passed = True
    for operations in v71.BATCH_SIZES:
        cases = [
            next(case for case in pair["cases"] if case["operations"] == operations)
            for pair in pairs
        ]
        for ratio in ("pooled_to_direct_p50_ratio", "pooled_to_postgrest_p50_ratio"):
            values = [case[ratio] for case in cases]
            variation = v71.coefficient_of_variation(values)
            hard_gate = operations in (8, 16)
            ratio_passed = not hard_gate or variation < 0.10
            evidence.append(
                {
                    "operations": operations,
                    "ratio": ratio,
                    "coefficient_of_variation": variation,
                    "hard_gate": hard_gate,
                    "passed": ratio_passed,
                }
            )
            passed &= ratio_passed
    return evidence, passed


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    smoke = sys.argv[1:] == ["--smoke"]
    if sys.argv[1:] not in ([], ["--smoke"]):
        raise SystemExit("use no argument for the formal campaign or --smoke")
    if cryptography.__version__ != "49.0.0":
        raise SystemExit("install the pinned v7.2 cryptography dependency")
    source_commit = None if smoke else committed_source()
    initial_source_sha256 = source_sha256()
    latest = RESULT_ROOT / "latest.json"
    if not smoke and latest.exists():
        raise SystemExit("the first v7.2 formal campaign already exists")
    command(
        "cargo", "build", "--manifest-path", str(ROOT / "Cargo.toml"),
        "--release", "--locked", "--bin", "ndabi_v71",
    )
    process_count = 1 if smoke else PROCESS_COUNT
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = None if smoke else RESULT_ROOT / campaign_id
    if campaign is not None:
        campaign.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    network = f"ndabi-v72-{suffix}"
    postgres = f"ndabi-v72-postgres-{suffix}"
    postgrest = f"ndabi-v72-postgrest-{suffix}"
    supavisor = f"ndabi-v72-supavisor-{suffix}"
    private, public_pem, jwks = v71.key_material()
    expiry = int(time.time()) + 3_600
    direct_reports = []
    pooled_reports = []
    pairs = []
    with tempfile.TemporaryDirectory(prefix="ndabi-v72-") as temporary:
        custody = Path(temporary)
        public_key = v71.write_private_file(custody, "public.pem", public_pem)
        valid_one = v71.token(private, v71.claims("user-1", expiry))
        valid_two = v71.token(private, v71.claims("user-2", expiry))
        token_paths = {
            "valid": v71.write_private_file(custody, "valid.jwt", valid_one),
            "changed_signature": v71.write_private_file(custody, "changed-signature.jwt", v71.changed_signature(valid_one)),
            "unknown_key": v71.write_private_file(custody, "unknown-key.jwt", v71.token(private, v71.claims("user-1", expiry), "unknown")),
            "wrong_issuer": v71.write_private_file(custody, "wrong-issuer.jwt", v71.token(private, v71.claims("user-1", expiry, iss="https://wrong.test/auth/v1"))),
            "wrong_audience": v71.write_private_file(custody, "wrong-audience.jwt", v71.token(private, v71.claims("user-1", expiry, aud="wrong"))),
            "expired": v71.write_private_file(custody, "expired.jwt", v71.token(private, v71.claims("user-1", int(time.time()) - 60))),
            "unsigned_subject": v71.write_private_file(custody, "unsigned-subject.jwt", v71.unsigned_subject_mutation(valid_one)),
            "elevated_role": v71.write_private_file(custody, "elevated-role.jwt", v71.token(private, v71.claims("user-1", expiry, role="service_role"))),
            "user_two": v71.write_private_file(custody, "user-two.jwt", valid_two),
        }
        try:
            command("docker", "network", "create", network)
            command(
                "docker", "run", "--detach", "--name", postgres, "--network", network,
                "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=ndabi-test-only",
                "--env", "POSTGRES_DB=ndabi", POSTGRES_IMAGE,
                "-c", "shared_preload_libraries=pg_stat_statements",
            )
            for _ in range(60):
                ready = command(
                    "docker", "exec", postgres, "pg_isready", "-U", "postgres", "-d", "ndabi", check=False
                )
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("PostgreSQL did not become ready")
            role_state, rls_state = setup_database(postgres)
            postgrest_port = start_postgrest(postgrest, network, postgres, jwks)
            supavisor_port = start_supavisor(supavisor, network, postgres)
            postgres_port = command("docker", "port", postgres, "5432/tcp").stdout.strip().rsplit(":", 1)[1]
            direct_connection = f"host=127.0.0.1 port={postgres_port} user=authenticator password=auth-test-only dbname=ndabi"
            pooled_connection = f"host=127.0.0.1 port={supavisor_port} user=authenticator.{TENANT_ID} password=auth-test-only dbname=ndabi"
            endpoint = f"http://127.0.0.1:{postgrest_port}/supabase_items"
            session_proof_passed = session_proof(postgres, supavisor)
            security = security_checks(
                pooled_connection, endpoint, token_paths, public_key, valid_one
            )
            security_passed = len(security) == 17 and all(security.values())
            for process in range(1, process_count + 1):
                arms = [
                    ("direct", direct_connection),
                    ("pooled", pooled_connection),
                ]
                if process % 2 == 0:
                    arms.reverse()
                reports = {}
                for name, connection in arms:
                    psql(postgres, "SELECT pg_stat_statements_reset()")
                    completed, report = run_arm(
                        connection, endpoint, token_paths["valid"], public_key
                    )
                    observed = data_queries(postgres)
                    report["process"] = process
                    report["transport"] = name
                    report["binary_exit_code"] = completed.returncode
                    report["observed_data_queries"] = observed
                    report["data_query_gate_passed"] = observed == EXPECTED_QUERIES_PER_ARM
                    report["campaign_gate_passed"] = (
                        report.get("passed") is True
                        and report.get("validated") is True
                        and completed.returncode == 0
                        and report["data_query_gate_passed"]
                    )
                    reports[name] = report
                    if campaign is not None:
                        write_json(campaign / f"{name}-process-{process}.json", report)
                pair = compare_pair(reports["direct"], reports["pooled"])
                pair["process"] = process
                pair["passed"] &= (
                    reports["direct"]["campaign_gate_passed"]
                    and reports["pooled"]["campaign_gate_passed"]
                )
                if campaign is not None:
                    write_json(campaign / f"pair-process-{process}.json", pair)
                direct_reports.append(reports["direct"])
                pooled_reports.append(reports["pooled"])
                pairs.append(pair)
            repeatability_evidence, repeatability_passed = (
                repeatability(pairs) if not smoke else ([], True)
            )
            final_source_sha256 = source_sha256()
            source_custody_passed = final_source_sha256 == initial_source_sha256
            if source_commit is not None:
                source_custody_passed &= source_matches_commit(repository_root(), source_commit)
            accepted = (
                not smoke
                and role_state == "f|f|f|t"
                and rls_state == "t|t"
                and session_proof_passed
                and security_passed
                and repeatability_passed
                and all(pair["passed"] for pair in pairs)
                and source_custody_passed
            )
            reports_valid = all(
                report.get("validated") is True
                for report in direct_reports + pooled_reports
            )
            aggregate = {
                "campaign": "NDABI Supavisor session campaign v7.2",
                "campaign_id": campaign_id,
                "smoke": smoke,
                "process_count": process_count,
                "source_commit": source_commit,
                "source_sha256": final_source_sha256,
                "source_custody_passed": source_custody_passed,
                "binary_sha256": file_sha256(BINARY),
                "postgres_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE).stdout.strip(),
                "postgrest_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", POSTGREST_IMAGE).stdout.strip(),
                "supavisor_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", SUPAVISOR_IMAGE).stdout.strip(),
                "pooler_mode": "session",
                "session_proof_passed": session_proof_passed,
                "authenticator_least_privilege": role_state == "f|f|f|t",
                "rls_enabled_and_forced": rls_state == "t|t",
                "security": security,
                "security_passed": security_passed,
                "repeatability": repeatability_evidence,
                "repeatability_passed": repeatability_passed,
                "summary": (
                    campaign_summary(direct_reports, pooled_reports) if reports_valid else []
                ),
                "environment": {
                    "platform": platform.platform(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "python_version": platform.python_version(),
                    "rustc_version": command("rustc", "--version").stdout.strip(),
                    "docker_server_version": command("docker", "version", "--format", "{{.Server.Version}}").stdout.strip(),
                    "executable": sys.executable,
                },
                "accepted": accepted,
            }
            if campaign is not None:
                write_json(campaign / "aggregate.json", aggregate)
                write_json(latest, aggregate)
            print(json.dumps(aggregate, indent=2))
            if smoke:
                return 0 if session_proof_passed and security_passed and all(pair["passed"] for pair in pairs) else 1
            return 0 if accepted else 1
        finally:
            command("docker", "rm", "--force", supavisor, check=False)
            command("docker", "rm", "--force", postgrest, check=False)
            command("docker", "rm", "--force", postgres, check=False)
            command("docker", "network", "rm", network, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
