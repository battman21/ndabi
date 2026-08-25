#!/usr/bin/env python3
"""Run the frozen registered PostgreSQL and Supabase-compatible RLS campaign."""

from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import time
from pathlib import Path

import cryptography

import validation_suite_v67 as shared


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_registry_postgres_v01"
POSTGRES_IMAGE = shared.POSTGRES_IMAGE
RESULT_ROOT = ROOT / "results" / "registry-postgres-v03"
PROCESS_COUNT = 5
KEY_ID = "ndabi-registry-postgres-v01"
ISSUER = "https://ndabi-registry.local/auth/v1"
AUDIENCE = "authenticated"
CAMPAIGN = "NDABI registered PostgreSQL and Supabase-compatible RLS v0.3"
REGISTERED_PROFILE = "0x50471002"
TRUE_FIELDS = (
    "changed_registry_refused",
    "legacy_identity_refused",
    "unknown_handle_refused",
    "changed_shape_refused",
    "excessive_limits_refused",
    "changed_frame_refused",
    "replay_refused",
    "receipt_verified",
    "passed",
)
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/ndabi-protocol/Cargo.toml",
    "crates/ndabi-protocol/src/lib.rs",
    "crates/ndabi-protocol/src/registry.rs",
    "crates/ndabi-postgres-v1/Cargo.toml",
    "crates/ndabi-postgres-v1/src/lib.rs",
    "crates/ndabi-supabase-v1/Cargo.toml",
    "crates/ndabi-supabase-v1/src/lib.rs",
    "crates/ndabi-supabase-v1/src/postgres_rls.rs",
    "src/bin/ndabi_registry_postgres_v01.rs",
    "validation_suite_v44.py",
    "validation_suite_v58.py",
    "validation_suite_v67.py",
    "validation_suite_registry_postgres_v01.py",
    "requirements-v67.txt",
    "../../specs/ndabi_registered_postgres_supabase_campaign_v0_3.md",
)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = (ROOT / relative).resolve()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


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
    check: bool = True,
):
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
    return shared.command(*arguments, check=check)


def expected_result(identifiers: tuple[int, ...]) -> bytes:
    output = bytearray(struct.pack("<HI", 1, len(identifiers)))
    for identifier in identifiers:
        output.extend(
            struct.pack(
                "<qiii",
                identifier,
                identifier % 1_000,
                identifier % 100,
                identifier % 10_000,
            )
        )
        output.extend(bytes([identifier % 256]) * 64)
    return bytes(output)


def expected_sha256(identifiers: tuple[int, ...]) -> str:
    return hashlib.sha256(expected_result(identifiers)).hexdigest()


def validate_report(report: dict, mode: str, identifiers: tuple[int, ...]) -> None:
    if report.get("campaign") != CAMPAIGN:
        raise ValueError("the campaign identity changed")
    if report.get("mode") != mode:
        raise ValueError("the execution mode changed")
    if report.get("registered_profile") != REGISTERED_PROFILE:
        raise ValueError("the registered profile changed")
    registry_digest = report.get("registry_digest")
    if not isinstance(registry_digest, str) or len(registry_digest) != 64:
        raise ValueError("the registry digest is invalid")
    if report.get("request_bytes") != 160:
        raise ValueError("the request size changed")
    if report.get("result_rows") != len(identifiers):
        raise ValueError("the result row count changed")
    expected = expected_result(identifiers)
    if report.get("result_bytes") != len(expected):
        raise ValueError("the result byte count changed")
    if report.get("result_sha256") != hashlib.sha256(expected).hexdigest():
        raise ValueError("the complete result changed")
    for field in TRUE_FIELDS:
        if report.get(field) is not True:
            raise ValueError(f"the {field} gate failed")


def claims(subject: str, expiry: int, **changes: object) -> dict:
    value = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject,
        "role": "authenticated",
        "iat": int(time.time()),
        "exp": expiry,
    }
    value.update(changes)
    return value


def run_report(
    connection: str,
    mode: str,
    identifiers: tuple[int, ...],
    token_path: Path | None = None,
    public_key: Path | None = None,
) -> dict:
    start = str(identifiers[0])
    rows = str(len(identifiers))
    arguments = [str(BINARY), mode, connection]
    if mode == "user":
        if token_path is None or public_key is None:
            raise ValueError("the user proof needs token material")
        arguments.extend(
            [
                str(token_path),
                str(public_key),
                KEY_ID,
                ISSUER,
                AUDIENCE,
            ]
        )
    arguments.extend([start, rows])
    completed = shared.command(*arguments, check=False)
    if completed.returncode != 0:
        raise ValueError("the registered proof process refused")
    report = json.loads(completed.stdout)
    validate_report(report, "service" if mode == "service" else "user-rls", identifiers)
    return report


def data_query_count(postgres: str) -> int:
    statement = (
        "SELECT coalesce(sum(calls),0)::bigint FROM pg_stat_statements "
        "WHERE query LIKE 'SELECT id,bucket,owner,score,payload FROM supabase_items%'"
    )
    return int(psql(postgres, statement).stdout.strip())


def reset_query_count(postgres: str) -> None:
    psql(postgres, "SELECT pg_stat_statements_reset()")


def refused_user_call(
    connection: str,
    token_path: Path,
    public_key: Path,
    start: int,
    rows: int,
) -> bool:
    completed = shared.command(
        str(BINARY),
        "user",
        connection,
        str(token_path),
        str(public_key),
        KEY_ID,
        ISSUER,
        AUDIENCE,
        str(start),
        str(rows),
        check=False,
    )
    return completed.returncode != 0


def main() -> int:
    if cryptography.__version__ != "49.0.0":
        raise SystemExit("install the pinned v6.7 cryptography dependency")
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first registered PostgreSQL campaign already exists")
    if not BINARY.exists():
        raise SystemExit("build the registered PostgreSQL release binary first")

    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    network = f"ndabi-registry-pg-{suffix}"
    postgres = f"ndabi-registry-pg-db-{suffix}"
    reports: list[dict] = []
    private, public_pem, _ = shared.key_material()
    expiry = int(time.time()) + 1_800

    with tempfile.TemporaryDirectory(prefix="ndabi-registry-pg-") as temporary:
        custody = Path(temporary)
        public_key = shared.write_private_file(custody, "public.pem", public_pem)
        valid_one = shared.token(private, claims("user-1", expiry), KEY_ID)
        valid_two = shared.token(private, claims("user-2", expiry), KEY_ID)
        token_paths = {
            "user_one": shared.write_private_file(custody, "user-one.jwt", valid_one),
            "user_two": shared.write_private_file(custody, "user-two.jwt", valid_two),
            "changed_signature": shared.write_private_file(
                custody,
                "changed-signature.jwt",
                shared.changed_signature(valid_one),
            ),
            "expired": shared.write_private_file(
                custody,
                "expired.jwt",
                shared.token(private, claims("user-1", int(time.time()) - 60), KEY_ID),
            ),
            "wrong_issuer": shared.write_private_file(
                custody,
                "wrong-issuer.jwt",
                shared.token(
                    private,
                    claims("user-1", expiry, iss="https://wrong.test/auth/v1"),
                    KEY_ID,
                ),
            ),
            "wrong_audience": shared.write_private_file(
                custody,
                "wrong-audience.jwt",
                shared.token(private, claims("user-1", expiry, aud="wrong"), KEY_ID),
            ),
            "elevated_role": shared.write_private_file(
                custody,
                "elevated-role.jwt",
                shared.token(private, claims("user-1", expiry, role="service_role"), KEY_ID),
            ),
        }

        try:
            shared.command("docker", "network", "create", network)
            shared.command(
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
                "-c",
                "shared_preload_libraries=pg_stat_statements",
            )
            for _ in range(60):
                ready = shared.command(
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

            statements = (
                "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
                "CREATE EXTENSION pg_stat_statements",
                "CREATE ROLE authenticated NOLOGIN",
                "CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'auth-test-only'",
                "GRANT authenticated TO authenticator",
                "CREATE ROLE ndabi_service NOINHERIT LOGIN PASSWORD 'service-test-only'",
                "ALTER ROLE ndabi_service SET default_transaction_read_only=on",
                "CREATE TABLE supabase_items(id bigint PRIMARY KEY,bucket integer NOT NULL,owner integer NOT NULL,score integer NOT NULL,payload bytea NOT NULL,owner_sub text NOT NULL)",
                "INSERT INTO supabase_items VALUES (1,1,1,1,decode(repeat('01',64),'hex'),'user-1'),(2,2,2,2,decode(repeat('02',64),'hex'),'user-1'),(3,3,3,3,decode(repeat('03',64),'hex'),'user-2'),(4,4,4,4,decode(repeat('04',64),'hex'),'user-2')",
                "GRANT USAGE ON SCHEMA public TO authenticated,ndabi_service",
                "GRANT SELECT ON supabase_items TO authenticated,ndabi_service",
                "ALTER TABLE supabase_items ENABLE ROW LEVEL SECURITY",
                "ALTER TABLE supabase_items FORCE ROW LEVEL SECURITY",
                "CREATE POLICY user_rows ON supabase_items FOR SELECT TO authenticated USING (owner_sub = (current_setting('request.jwt.claims',true)::json ->> 'sub'))",
                "CREATE POLICY service_rows ON supabase_items FOR SELECT TO ndabi_service USING (true)",
            )
            for statement in statements:
                psql(postgres, statement)

            postgres_port = shared.command(
                "docker", "port", postgres, "5432/tcp"
            ).stdout.strip().rsplit(":", 1)[1]
            service_connection = (
                f"host=127.0.0.1 port={postgres_port} user=ndabi_service "
                "password=service-test-only dbname=ndabi"
            )
            user_connection = (
                f"host=127.0.0.1 port={postgres_port} user=authenticator "
                "password=auth-test-only dbname=ndabi"
            )

            role_states = {
                role: psql(
                    postgres,
                    "SELECT rolsuper,rolcreaterole,rolcreatedb,rolcanlogin "
                    f"FROM pg_roles WHERE rolname='{role}'",
                ).stdout.strip()
                for role in ("ndabi_service", "authenticator", "authenticated")
            }
            rls_state = psql(
                postgres,
                "SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                "WHERE relname='supabase_items'",
            ).stdout.strip()
            service_write = psql(
                postgres,
                "INSERT INTO supabase_items VALUES (5,5,5,5,decode(repeat('05',64),'hex'),'user-1')",
                user="ndabi_service",
                password="service-test-only",
                check=False,
            )
            user_write = psql(
                postgres,
                "BEGIN;SET LOCAL ROLE authenticated;"
                "INSERT INTO supabase_items VALUES (6,6,6,6,decode(repeat('06',64),'hex'),'user-1')",
                user="authenticator",
                password="auth-test-only",
                check=False,
            )

            admission_refusals = {}
            for name in (
                "changed_signature",
                "expired",
                "wrong_issuer",
                "wrong_audience",
                "elevated_role",
            ):
                admission_refusals[name] = refused_user_call(
                    user_connection,
                    token_paths[name],
                    public_key,
                    1,
                    1,
                )
            scope_refusals = {
                "user_one_cannot_read_user_two": refused_user_call(
                    user_connection,
                    token_paths["user_one"],
                    public_key,
                    3,
                    1,
                ),
                "user_two_cannot_read_user_one": refused_user_call(
                    user_connection,
                    token_paths["user_two"],
                    public_key,
                    1,
                    1,
                ),
            }

            for process in range(1, PROCESS_COUNT + 1):
                process_reports = []
                for mode, identifiers, token_path in (
                    ("service", (1, 2), None),
                    ("user", (1, 2), token_paths["user_one"]),
                    ("user", (3, 4), token_paths["user_two"]),
                ):
                    reset_query_count(postgres)
                    report = run_report(
                        service_connection if mode == "service" else user_connection,
                        mode,
                        identifiers,
                        token_path,
                        public_key if mode == "user" else None,
                    )
                    report["data_queries"] = data_query_count(postgres)
                    report["data_query_gate_passed"] = report["data_queries"] == 1
                    report["process"] = process
                    report["identifiers"] = list(identifiers)
                    report["passed"] = report["passed"] and report["data_query_gate_passed"]
                    process_reports.append(report)
                    reports.append(report)
                (campaign / f"process-{process}.json").write_text(
                    json.dumps(process_reports, indent=2) + "\n",
                    encoding="utf-8",
                )

            registry_digests = {report["registry_digest"] for report in reports}
            security = {
                "service_role_least_privilege": role_states["ndabi_service"] == "f|f|f|t",
                "authenticator_least_privilege": role_states["authenticator"] == "f|f|f|t",
                "authenticated_role_cannot_login": role_states["authenticated"] == "f|f|f|f",
                "rls_enabled_and_forced": rls_state == "t|t",
                "service_write_refused": service_write.returncode != 0,
                "user_write_refused": user_write.returncode != 0,
                **admission_refusals,
                **scope_refusals,
            }
            accepted = (
                len(reports) == PROCESS_COUNT * 3
                and all(report["passed"] for report in reports)
                and len(registry_digests) == 1
                and all(security.values())
            )
            aggregate = {
                "campaign": CAMPAIGN,
                "campaign_id": campaign_id,
                "process_count": PROCESS_COUNT,
                "successful_execution_count": len(reports),
                "source_sha256": source_sha256(),
                "binary_sha256": file_sha256(BINARY),
                "postgres_image_id": shared.command(
                    "docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE
                ).stdout.strip(),
                "registered_profile": REGISTERED_PROFILE,
                "registry_digest": next(iter(registry_digests), None),
                "registry_digest_consistent": len(registry_digests) == 1,
                "security": security,
                "security_passed": all(security.values()),
                "accepted": accepted,
            }
            encoded = json.dumps(aggregate, indent=2) + "\n"
            (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
            latest.write_text(encoded, encoding="utf-8")
            print(encoded, end="")
            return 0 if accepted else 1
        finally:
            shared.command("docker", "rm", "--force", postgres, check=False)
            shared.command("docker", "network", "rm", network, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
