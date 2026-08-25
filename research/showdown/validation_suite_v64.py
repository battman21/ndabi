#!/usr/bin/env python3
"""Run the PostgreSQL transport and Supabase-compatible campaign v6.4 once."""

from __future__ import annotations

import hashlib
import json
import struct
import time
from pathlib import Path

import validation_suite_v44 as shared
import validation_suite_v58 as supabase


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v64"
POSTGRES_IMAGE = supabase.POSTGRES_IMAGE
POSTGREST_IMAGE = supabase.POSTGREST_IMAGE
RESULT_ROOT = ROOT / "results" / "v64"
PROCESS_COUNT = 5
EXPECTED_RESULT = (
    struct.pack("<HI", 1, 2)
    + struct.pack("<qiii", 1, 1, 1, 100)
    + bytes([0xAA]) * 64
    + struct.pack("<qiii", 2, 2, 1, 200)
    + bytes([0xBB]) * 64
)
EXPECTED_RESULT_SHA256 = hashlib.sha256(EXPECTED_RESULT).hexdigest()
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-protocol/Cargo.toml",
    "crates/ndabi-protocol/src/lib.rs",
    "crates/ndabi-protocol/src/connection.rs",
    "crates/ndabi-protocol/src/transport.rs",
    "crates/ndabi-postgres-v1/Cargo.toml",
    "crates/ndabi-postgres-v1/src/lib.rs",
    "src/bin/ndabi_v64.rs",
    "validation_suite_v44.py",
    "validation_suite_v58.py",
    "validation_suite_v64.py",
    "../../specs/ndabi_transport_candidate_v0_2.md",
    "../../specs/ndabi_transport_supabase_campaign_v6_4.md",
)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = (ROOT / relative).resolve()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v6.4 formal campaign already exists")
    if not BINARY.exists():
        raise SystemExit("build the ndabi_v64 release binary before the campaign")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    network = f"ndabi-v64-{suffix}"
    postgres = f"ndabi-v64-postgres-{suffix}"
    postgrest = f"ndabi-v64-postgrest-{suffix}"
    reports = []
    try:
        supabase.command("docker", "network", "create", network)
        supabase.command(
            "docker",
            "run",
            "--detach",
            "--name",
            postgres,
            "--network",
            network,
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_PASSWORD=ndabi-test-only",
            "--env",
            "POSTGRES_DB=ndabi",
            POSTGRES_IMAGE,
        )
        for _ in range(60):
            ready = supabase.command(
                "docker",
                "exec",
                postgres,
                "pg_isready",
                "-U",
                "postgres",
                "-d",
                "ndabi",
                check=False,
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgreSQL did not become ready")

        statements = [
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
            "CREATE ROLE anon NOLOGIN",
            "CREATE ROLE authenticated NOLOGIN",
            "CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'auth-test-only'",
            "GRANT anon, authenticated TO authenticator",
            "CREATE ROLE ndabi_service NOINHERIT LOGIN PASSWORD 'service-test-only'",
            "ALTER ROLE ndabi_service SET default_transaction_read_only=on",
            "CREATE TABLE supabase_owners(id integer PRIMARY KEY,name text NOT NULL)",
            "INSERT INTO supabase_owners VALUES (1,'owner-1'),(2,'owner-2')",
            "CREATE TABLE supabase_items(id bigint PRIMARY KEY,bucket integer NOT NULL,owner integer NOT NULL REFERENCES supabase_owners(id),score integer NOT NULL,payload bytea NOT NULL,owner_sub text NOT NULL)",
            "INSERT INTO supabase_items VALUES (1,1,1,100,decode(repeat('aa',64),'hex'),'user-1'),(2,2,1,200,decode(repeat('bb',64),'hex'),'user-1'),(3,3,2,300,decode(repeat('cc',64),'hex'),'user-2')",
            "GRANT USAGE ON SCHEMA public TO authenticated, ndabi_service",
            "GRANT SELECT ON supabase_items TO authenticated, ndabi_service",
            "GRANT SELECT ON supabase_owners TO ndabi_service",
            "ALTER TABLE supabase_items ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE supabase_items FORCE ROW LEVEL SECURITY",
            "CREATE POLICY user_rows ON supabase_items FOR SELECT TO authenticated USING (owner_sub = (current_setting('request.jwt.claims', true)::json ->> 'sub'))",
            "CREATE POLICY service_rows ON supabase_items FOR SELECT TO ndabi_service USING (true)",
        ]
        for statement in statements:
            supabase.psql(postgres, statement)
        role_state = supabase.psql(
            postgres,
            "SELECT rolsuper,rolcreaterole,rolcreatedb,rolcanlogin FROM pg_roles WHERE rolname='ndabi_service'",
        ).stdout.strip()
        rls_state = supabase.psql(
            postgres,
            "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname='supabase_items'",
        ).stdout.strip()
        read_only_state = supabase.psql(
            postgres,
            "SHOW default_transaction_read_only",
            user="ndabi_service",
            password="service-test-only",
        ).stdout.strip()
        service_write = supabase.command(
            "docker",
            "exec",
            "--env",
            "PGPASSWORD=service-test-only",
            postgres,
            "psql",
            "-h",
            "127.0.0.1",
            "-U",
            "ndabi_service",
            "-d",
            "ndabi",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "INSERT INTO supabase_items VALUES (4,4,1,400,decode(repeat('dd',64),'hex'),'user-1')",
            check=False,
        )
        supabase.command(
            "docker",
            "run",
            "--detach",
            "--name",
            postgrest,
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
            f"PGRST_JWT_SECRET={supabase.JWT_SECRET.decode()}",
            "--env",
            "PGRST_LOG_LEVEL=warn",
            POSTGREST_IMAGE,
        )
        for _ in range(60):
            logs = supabase.command("docker", "logs", postgrest, check=False)
            if "API server listening" in logs.stdout + logs.stderr:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgREST did not become ready")

        postgres_port = supabase.command(
            "docker", "port", postgres, "5432/tcp"
        ).stdout.strip().rsplit(":", 1)[1]
        postgrest_port = supabase.command(
            "docker", "port", postgrest, "3000/tcp"
        ).stdout.strip().rsplit(":", 1)[1]
        connection = (
            f"host=127.0.0.1 port={postgres_port} user=ndabi_service "
            "password=service-test-only dbname=ndabi"
        )
        endpoint = f"http://127.0.0.1:{postgrest_port}/supabase_items?select=id,owner_sub&order=id"
        user_one = supabase.token("user-1")
        user_two = supabase.token("user-2")
        token_header, token_payload, token_signature = user_one.split(".")
        changed_signature = ("A" if token_signature[0] != "A" else "B") + token_signature[1:]
        changed_token = f"{token_header}.{token_payload}.{changed_signature}"
        for process in range(1, PROCESS_COUNT + 1):
            trusted = json.loads(supabase.command(str(BINARY), connection).stdout)
            one_status, one_body = supabase.request(endpoint, bearer=user_one)
            two_status, two_body = supabase.request(endpoint, bearer=user_two)
            absent_status, _ = supabase.request(endpoint)
            changed_status, _ = supabase.request(
                endpoint,
                bearer=changed_token,
            )
            expired_status, _ = supabase.request(
                endpoint, bearer=supabase.token("user-1", int(time.time()) - 60)
            )
            unsigned_status, _ = supabase.request(
                endpoint, bearer=supabase.unsigned_token()
            )
            write_status, _ = supabase.request(
                f"http://127.0.0.1:{postgrest_port}/supabase_items",
                method="POST",
                bearer=user_one,
                body=b'{"id":4,"bucket":4,"owner":1,"score":4,"payload":"\\x00","owner_sub":"user-1"}',
            )
            report = {
                "process": process,
                "trusted_service_binding": trusted["trusted_service_binding"],
                "complete_result_match": trusted["complete_result_match"],
                "transport_result_match": trusted["transport_result_match"],
                "transport_negotiated": trusted["transport_negotiated"],
                "transport_receipt_verified": trusted["transport_receipt_verified"],
                "result_bytes_passed": trusted["response_bytes"] == len(EXPECTED_RESULT),
                "result_rows_passed": trusted["response_rows"] == 2,
                "result_sha256_passed": trusted["result_sha256"] == EXPECTED_RESULT_SHA256,
                "canonical_request_passed": trusted["canonical_request_bytes"] == 160,
                "transport_result_size_passed": trusted["transport_result_frame_bytes"] == 334,
                "service_role_least_privilege": role_state == "f|f|f|t",
                "service_role_read_only": read_only_state == "on",
                "service_write_refused": service_write.returncode != 0,
                "rls_enabled_and_forced": rls_state == "t|t",
                "user_one_scope_passed": json.loads(one_body) == [
                    {"id": 1, "owner_sub": "user-1"},
                    {"id": 2, "owner_sub": "user-1"},
                ] if one_status == 200 else False,
                "user_two_scope_passed": json.loads(two_body) == [
                    {"id": 3, "owner_sub": "user-2"}
                ] if two_status == 200 else False,
                "absent_token_refused": absent_status >= 400,
                "changed_token_refused": changed_status >= 400,
                "expired_token_refused": expired_status >= 400,
                "unsigned_token_refused": unsigned_status >= 400,
                "user_write_refused": write_status >= 400,
            }
            report["passed"] = all(value for key, value in report.items() if key != "process")
            (campaign / f"process-{process}.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            reports.append(report)

        aggregate = {
            "campaign": "NDABI PostgreSQL transport and Supabase binding v6.4",
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            "binary_sha256": shared.sha256(BINARY),
            "source_sha256": source_sha256(),
            "postgres_image_id": supabase.command(
                "docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE
            ).stdout.strip(),
            "postgrest_image_id": supabase.command(
                "docker", "image", "inspect", "--format", "{{.Id}}", POSTGREST_IMAGE
            ).stdout.strip(),
            "accepted": all(report["passed"] for report in reports),
        }
        encoded = json.dumps(aggregate, indent=2) + "\n"
        (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
        latest.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if aggregate["accepted"] else 1
    finally:
        supabase.command("docker", "rm", "--force", postgrest, postgres, check=False)
        supabase.command("docker", "network", "rm", network, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
