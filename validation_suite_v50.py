#!/usr/bin/env python3
"""Run the frozen local Supabase-compatible binding v5.0 campaign once."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import validation_suite_v44 as shared


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v50"
POSTGRES_IMAGE = "postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
POSTGREST_IMAGE = "postgrest/postgrest@sha256:bea1c76a856fa39d1e542d25911cf95d02fe2bf971992d033044ff209f1504b8"
JWT_SECRET = b"ndabi-supabase-test-only-secret-0000000000000000"
RESULT_ROOT = ROOT / "results" / "v50"
PROCESS_COUNT = 5
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-session/src/lib.rs",
    "crates/ndabi-postgres/src/lib.rs",
    "src/bin/ndabi_v50.rs",
)


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update((ROOT / relative).read_bytes() + b"\0")
    return digest.hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def token() -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps({"role": "authenticated", "sub": "user-1", "exp": int(time.time()) + 3600}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    signature = b64url(hmac.new(JWT_SECRET, signing_input.encode(), hashlib.sha256).digest())
    return f"{signing_input}.{signature}"


def request(url: str, method: str = "GET", bearer: str | None = None, body: bytes | None = None) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    call = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(call, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main() -> int:
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v5.0 formal campaign already exists")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    network = f"ndabi-v50-{suffix}"
    postgres = f"ndabi-v50-postgres-{suffix}"
    postgrest = f"ndabi-v50-postgrest-{suffix}"
    reports = []
    try:
        command("docker", "network", "create", network)
        command(
            "docker", "run", "--detach", "--name", postgres, "--network", network,
            "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=ndabi-test-only",
            "--env", "POSTGRES_DB=ndabi", POSTGRES_IMAGE,
        )
        for _ in range(60):
            ready = command("docker", "exec", postgres, "pg_isready", "-U", "postgres", "-d", "ndabi", check=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgreSQL did not become ready")
        statements = [
            "CREATE ROLE anon NOLOGIN",
            "CREATE ROLE authenticated NOLOGIN",
            "CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'auth-test-only'",
            "GRANT anon, authenticated TO authenticator",
            "CREATE TABLE supabase_owners(id integer PRIMARY KEY,name text NOT NULL)",
            "INSERT INTO supabase_owners VALUES (1,'owner-1'),(2,'owner-2')",
            "CREATE TABLE supabase_items(id bigint PRIMARY KEY,bucket integer NOT NULL,owner integer NOT NULL REFERENCES supabase_owners(id),score integer NOT NULL,payload bytea NOT NULL,owner_sub text NOT NULL)",
            "INSERT INTO supabase_items VALUES (1,1,1,100,decode(repeat('aa',64),'hex'),'user-1'),(2,2,1,200,decode(repeat('bb',64),'hex'),'user-1'),(3,3,2,300,decode(repeat('cc',64),'hex'),'user-2')",
            "GRANT USAGE ON SCHEMA public TO authenticated",
            "GRANT SELECT ON supabase_items TO authenticated",
            "ALTER TABLE supabase_items ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY user_rows ON supabase_items FOR SELECT TO authenticated USING (owner_sub = (current_setting('request.jwt.claims', true)::json ->> 'sub'))",
        ]
        for statement in statements:
            command("docker", "exec", postgres, "psql", "-U", "postgres", "-d", "ndabi", "-v", "ON_ERROR_STOP=1", "-c", statement)
        command(
            "docker", "run", "--detach", "--name", postgrest, "--network", network,
            "--publish", "127.0.0.1::3000",
            "--env", f"PGRST_DB_URI=postgresql://authenticator:auth-test-only@{postgres}:5432/ndabi",
            "--env", "PGRST_DB_SCHEMAS=public", "--env", "PGRST_DB_ANON_ROLE=anon",
            "--env", f"PGRST_JWT_SECRET={JWT_SECRET.decode()}", "--env", "PGRST_LOG_LEVEL=warn",
            POSTGREST_IMAGE,
        )
        for _ in range(60):
            logs = command("docker", "logs", postgrest, check=False)
            if "API server listening" in logs.stdout + logs.stderr:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgREST did not become ready")
        postgres_port = command("docker", "port", postgres, "5432/tcp").stdout.strip().rsplit(":", 1)[1]
        postgrest_port = command("docker", "port", postgrest, "3000/tcp").stdout.strip().rsplit(":", 1)[1]
        connection = f"host=127.0.0.1 port={postgres_port} user=postgres password=ndabi-test-only dbname=ndabi"
        endpoint = f"http://127.0.0.1:{postgrest_port}/supabase_items?select=id,owner_sub&order=id"
        user_token = token()
        for process in range(1, PROCESS_COUNT + 1):
            trusted = json.loads(command(str(BINARY), connection).stdout)
            valid_status, valid_body = request(endpoint, bearer=user_token)
            rows = json.loads(valid_body) if valid_status == 200 else []
            absent_status, _ = request(endpoint)
            changed_status, _ = request(endpoint, bearer=user_token[:-1] + ("A" if user_token[-1] != "A" else "B"))
            write_status, _ = request(
                f"http://127.0.0.1:{postgrest_port}/supabase_items",
                method="POST", bearer=user_token, body=b'{"id":4,"bucket":4,"owner":1,"score":4,"payload":"\\x00","owner_sub":"user-1"}',
            )
            report = {
                "process": process,
                "trusted_service_binding": trusted["trusted_service_binding"],
                "jwt_user_rows": rows,
                "jwt_user_scope_passed": rows == [{"id": 1, "owner_sub": "user-1"}, {"id": 2, "owner_sub": "user-1"}],
                "absent_token_refused": absent_status >= 400,
                "changed_token_refused": changed_status >= 400,
                "write_refused": write_status >= 400,
            }
            report["passed"] = all(value for key, value in report.items() if key.endswith("passed") or key.endswith("refused") or key == "trusted_service_binding")
            (campaign / f"process-{process}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            reports.append(report)
        aggregate = {
            "campaign": "NDABI Supabase binding v5.0",
            "campaign_id": campaign_id,
            "process_count": PROCESS_COUNT,
            "binary_sha256": shared.sha256(BINARY),
            "source_sha256": source_sha256(),
            "postgres_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE).stdout.strip(),
            "postgrest_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", POSTGREST_IMAGE).stdout.strip(),
            "accepted": all(report["passed"] for report in reports),
            "process_results": [str(path.relative_to(ROOT)) for path in sorted(campaign.glob("process-*.json"))],
        }
        encoded = json.dumps(aggregate, indent=2) + "\n"
        (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
        latest.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0 if aggregate["accepted"] else 1
    finally:
        command("docker", "rm", "--force", postgrest, postgres, check=False)
        command("docker", "network", "rm", network, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
