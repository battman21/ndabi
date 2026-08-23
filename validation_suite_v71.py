#!/usr/bin/env python3
"""Run the frozen Supabase indexed-batch-session campaign v7.1 once."""

from __future__ import annotations

import base64
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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import validation_suite_v58 as shared


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "target" / "release" / "ndabi_v71"
POSTGRES_IMAGE = shared.POSTGRES_IMAGE
POSTGREST_IMAGE = shared.POSTGREST_IMAGE
RESULT_ROOT = ROOT / "results" / "v71"
PROCESS_COUNT = 5
BATCH_SIZES = (2, 8, 16)
ROWS_PER_OPERATION = 8
SAMPLES = 63
WARMUPS = 7
KEY_ID = "ndabi-v71-es256"
ISSUER = "https://ndabi-v71.local/auth/v1"
AUDIENCE = "authenticated"
EXPECTED_QUERIES = sum(operations + 1 for operations in BATCH_SIZES) * (SAMPLES + WARMUPS)
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "src/lib.rs",
    "src/alloc.rs",
    "src/bin/ndabi_v71.rs",
    "validation_suite_v71.py",
    "validation_suite_v58.py",
    "requirements-v71.txt",
    "crates/ndabi-protocol/Cargo.toml",
    "crates/ndabi-protocol/src/lib.rs",
    "crates/ndabi-protocol/src/batch.rs",
    "crates/ndabi-protocol/src/connection.rs",
    "crates/ndabi-protocol/src/replay.rs",
    "crates/ndabi-protocol/src/transport.rs",
    "crates/ndabi-postgres-v1/Cargo.toml",
    "crates/ndabi-postgres-v1/src/lib.rs",
    "crates/ndabi-supabase-v1/Cargo.toml",
    "crates/ndabi-supabase-v1/src/lib.rs",
    "crates/ndabi-supabase-v1/src/postgres_rls.rs",
    "crates/ndabi-supabase-indexed-batch-session-v1/Cargo.toml",
    "crates/ndabi-supabase-indexed-batch-session-v1/src/lib.rs",
    "../../specs/ndabi_supabase_indexed_batch_campaign_v7_1.md",
)


def command(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def source_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = (ROOT / relative).resolve()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def repository_root() -> Path:
    return Path(
        command("git", "-C", str(ROOT), "rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()


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
    if not commit:
        raise SystemExit("the source commit is absent")
    if not source_matches_commit(repository, commit):
        raise SystemExit("commit every registered source file before the campaign")
    return commit


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def key_material() -> tuple[ec.EllipticCurvePrivateKey, bytes, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()
    numbers = public.public_numbers()
    public_pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwks = json.dumps(
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "alg": "ES256",
                    "kid": KEY_ID,
                    "crv": "P-256",
                    "x": b64url(numbers.x.to_bytes(32, "big")),
                    "y": b64url(numbers.y.to_bytes(32, "big")),
                }
            ]
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return private, public_pem, jwks


def token(private: ec.EllipticCurvePrivateKey, claims: dict, key_id: str = KEY_ID) -> str:
    header = {"alg": "ES256", "kid": key_id, "typ": "JWT"}
    encoded_header = b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    encoded_claims = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    signature = private.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    first, second = decode_dss_signature(signature)
    raw_signature = first.to_bytes(32, "big") + second.to_bytes(32, "big")
    return f"{signing_input.decode()}.{b64url(raw_signature)}"


def claims(subject: str, expiry: int, **changes: object) -> dict:
    value = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject,
        "role": "authenticated",
        "iat": int(time.time()),
        "exp": expiry,
        "app_metadata": {"campaign": "v7.1"},
    }
    value.update(changes)
    return value


def unsigned_subject_mutation(value: str) -> str:
    header, encoded_claims, signature = value.split(".")
    padding = "=" * (-len(encoded_claims) % 4)
    payload = json.loads(base64.urlsafe_b64decode(encoded_claims + padding))
    payload["sub"] = "user-2"
    changed = b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    return f"{header}.{changed}.{signature}"


def changed_signature(value: str) -> str:
    header, payload, encoded_signature = value.split(".")
    padding = "=" * (-len(encoded_signature) % 4)
    signature = bytearray(base64.urlsafe_b64decode(encoded_signature + padding))
    signature[0] ^= 1
    return f"{header}.{payload}.{b64url(bytes(signature))}"


def write_private_file(root: Path, name: str, value: str | bytes) -> Path:
    path = root / name
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def percentile(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    return ordered[int((len(ordered) - 1) * quantile)]


def coefficient_of_variation(values: list[float]) -> float:
    mean = statistics.mean(values)
    return statistics.pstdev(values) / mean if mean else math.inf


def measurement(case: dict, arm: str) -> dict:
    return next(item for item in case["measurements"] if item["arm"] == arm)


def validate_report(report: dict) -> None:
    if report.get("campaign") != "NDABI Supabase indexed-batch-session campaign v7.1":
        raise ValueError("the campaign identity changed")
    if report.get("samples") != SAMPLES or report.get("warmups") != WARMUPS:
        raise ValueError("the sample plan changed")
    if not isinstance(report.get("jwt_admission_ns"), int) or report["jwt_admission_ns"] <= 0:
        raise ValueError("the JWT admission timing is invalid")
    cases = report.get("cases")
    if not isinstance(cases, list) or {
        case.get("operations") for case in cases
    } != set(BATCH_SIZES):
        raise ValueError("the case matrix changed")
    for case in cases:
        operations = case["operations"]
        if case.get("rows_per_operation") != ROWS_PER_OPERATION:
            raise ValueError("the rows per operation changed")
        request_bytes = 160 + operations * 20
        if case.get("ndabi_request_bytes") != request_bytes:
            raise ValueError("the NDABI batch request size changed")
        lower_bound = case.get("postgrest_request_lower_bound_bytes")
        if not isinstance(lower_bound, int) or lower_bound <= request_bytes:
            raise ValueError("the PostgREST request lower bound is invalid")
        reduction = 1.0 - request_bytes / lower_bound
        if not math.isclose(case.get("minimum_request_reduction"), reduction, rel_tol=1e-12):
            raise ValueError("the request reduction changed")
        query_reduction = 1.0 - 1.0 / operations
        if not math.isclose(case.get("database_query_reduction"), query_reduction, rel_tol=1e-12):
            raise ValueError("the database query reduction changed")
        ndabi_queries = SAMPLES + WARMUPS
        postgrest_queries = ndabi_queries * operations
        if case.get("ndabi_data_queries") != ndabi_queries:
            raise ValueError("the NDABI query count changed")
        if case.get("expected_ndabi_data_queries") != ndabi_queries:
            raise ValueError("the expected NDABI query count changed")
        if case.get("postgrest_data_queries") != postgrest_queries:
            raise ValueError("the PostgREST query count changed")
        if case.get("expected_postgrest_data_queries") != postgrest_queries:
            raise ValueError("the expected PostgREST query count changed")
        database_rows = ndabi_queries * operations * ROWS_PER_OPERATION
        if case.get("ndabi_database_result_rows") != database_rows:
            raise ValueError("the indexed database row count changed")
        if case.get("expected_database_result_rows") != database_rows:
            raise ValueError("the expected indexed database row count changed")
        measurements = case.get("measurements")
        if not isinstance(measurements, list) or {
            item.get("arm") for item in measurements
        } != {"postgrest-user-jwt", "ndabi-indexed-batch-session"}:
            raise ValueError("the measurement arms changed")
        for item in measurements:
            wall = item.get("raw_ns")
            cpu = item.get("raw_cpu_ns")
            if not isinstance(wall, list) or len(wall) != SAMPLES:
                raise ValueError("the wall samples are incomplete")
            if not isinstance(cpu, list) or len(cpu) != SAMPLES:
                raise ValueError("the CPU samples are incomplete")
            if any(not isinstance(value, int) or value <= 0 for value in wall + cpu):
                raise ValueError("a timing sample is invalid")
            if item.get("p50_ns") != percentile(wall, 0.50):
                raise ValueError("the wall median changed")
            if item.get("p95_ns") != percentile(wall, 0.95):
                raise ValueError("the wall p95 changed")
            if item.get("p99_ns") != percentile(wall, 0.99):
                raise ValueError("the wall p99 changed")
            if item.get("p50_cpu_ns") != percentile(cpu, 0.50):
                raise ValueError("the CPU median changed")
        postgrest = measurement(case, "postgrest-user-jwt")
        ndabi = measurement(case, "ndabi-indexed-batch-session")
        wall_ratio = ndabi["p50_ns"] / postgrest["p50_ns"]
        cpu_ratio = ndabi["p50_cpu_ns"] / postgrest["p50_cpu_ns"]
        if not math.isclose(case.get("ndabi_postgrest_p50_distance"), wall_ratio, rel_tol=1e-12):
            raise ValueError("the wall ratio changed")
        if not math.isclose(case.get("ndabi_postgrest_cpu_distance"), cpu_ratio, rel_tol=1e-12):
            raise ValueError("the CPU ratio changed")
        performance = operations == 2 or wall_ratio <= 0.20
        allocation = operations != 16 or (
            ndabi["mean_allocations"] <= 200.0
            and ndabi["mean_allocated_bytes"] <= 100_000.0
        )
        if case.get("allocation_gate_passed") is not allocation:
            raise ValueError("the allocation verdict changed")
        expected = reduction >= 0.70 and performance and allocation
        if case.get("passed") is not expected:
            raise ValueError("the case verdict changed")
    if report.get("passed") is not all(case["passed"] for case in cases):
        raise ValueError("the process verdict changed")


def psql(container: str, statement: str, user: str = "postgres", password: str | None = None) -> subprocess.CompletedProcess:
    arguments = ["docker", "exec"]
    if password is not None:
        arguments.extend(["--env", f"PGPASSWORD={password}"])
    arguments.extend(
        [container, "psql", "-h", "127.0.0.1", "-U", user, "-d", "ndabi", "-At", "-v", "ON_ERROR_STOP=1", "-c", statement]
    )
    return command(*arguments)


def admission_probe(paths: dict[str, Path], public_key: Path) -> dict[str, bool]:
    results = {}
    for name, path in paths.items():
        completed = command(
            str(BINARY),
            "--admit-only",
            str(path),
            str(public_key),
            KEY_ID,
            ISSUER,
            AUDIENCE,
            check=False,
        )
        results[name] = completed.returncode == 0
    return results


def main() -> int:
    if cryptography.__version__ != "49.0.0":
        raise SystemExit("install the pinned v7.1 cryptography dependency")
    source_commit = committed_source()
    initial_source_sha256 = source_sha256()
    latest = RESULT_ROOT / "latest.json"
    if latest.exists():
        raise SystemExit("the first v7.1 formal campaign already exists")
    command(
        "cargo",
        "build",
        "--manifest-path",
        str(ROOT / "Cargo.toml"),
        "--release",
        "--locked",
        "--bin",
        "ndabi_v71",
    )
    if not BINARY.exists():
        raise SystemExit("build the ndabi_v71 release binary before the campaign")
    campaign_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    campaign = RESULT_ROOT / campaign_id
    campaign.mkdir(parents=True, exist_ok=False)
    suffix = str(time.time_ns())
    network = f"ndabi-v71-{suffix}"
    postgres = f"ndabi-v71-postgres-{suffix}"
    postgrest = f"ndabi-v71-postgrest-{suffix}"
    reports: list[dict] = []
    private, public_pem, jwks = key_material()
    expiry = int(time.time()) + 1_800
    with tempfile.TemporaryDirectory(prefix="ndabi-v71-") as temporary:
        custody = Path(temporary)
        public_key = write_private_file(custody, "public.pem", public_pem)
        valid_one = token(private, claims("user-1", expiry))
        valid_two = token(private, claims("user-2", expiry))
        token_paths = {
            "valid": write_private_file(custody, "valid.jwt", valid_one),
            "changed_signature": write_private_file(custody, "changed-signature.jwt", changed_signature(valid_one)),
            "unknown_key": write_private_file(custody, "unknown-key.jwt", token(private, claims("user-1", expiry), "unknown")),
            "wrong_issuer": write_private_file(custody, "wrong-issuer.jwt", token(private, claims("user-1", expiry, iss="https://wrong.test/auth/v1"))),
            "wrong_audience": write_private_file(custody, "wrong-audience.jwt", token(private, claims("user-1", expiry, aud="wrong"))),
            "expired": write_private_file(custody, "expired.jwt", token(private, claims("user-1", int(time.time()) - 60))),
            "unsigned_subject": write_private_file(custody, "unsigned-subject.jwt", unsigned_subject_mutation(valid_one)),
            "elevated_role": write_private_file(custody, "elevated-role.jwt", token(private, claims("user-1", expiry, role="service_role"))),
            "user_two": write_private_file(custody, "user-two.jwt", valid_two),
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
                if command("docker", "exec", postgres, "pg_isready", "-U", "postgres", "-d", "ndabi", check=False).returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("PostgreSQL did not become ready")
            statements = (
                "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
                "CREATE EXTENSION pg_stat_statements",
                "CREATE ROLE anon NOLOGIN",
                "CREATE ROLE authenticated NOLOGIN",
                "CREATE ROLE authenticator NOINHERIT LOGIN PASSWORD 'auth-test-only'",
                "GRANT authenticated TO authenticator",
                "CREATE TABLE supabase_items(id bigint PRIMARY KEY,bucket integer NOT NULL,owner integer NOT NULL,score integer NOT NULL,payload bytea NOT NULL,owner_sub text NOT NULL)",
                "INSERT INTO supabase_items SELECT value,(value%1000)::integer,(value%100)::integer,(value%10000)::integer,decode(repeat(lpad(to_hex(value%256),2,'0'),64),'hex'),CASE WHEN value<=200000 THEN 'user-1' ELSE 'user-2' END FROM generate_series(1,1000000) AS value",
                "ANALYZE supabase_items",
                "GRANT USAGE ON SCHEMA public TO authenticated",
                "GRANT SELECT ON supabase_items TO authenticated",
                "ALTER TABLE supabase_items ENABLE ROW LEVEL SECURITY",
                "ALTER TABLE supabase_items FORCE ROW LEVEL SECURITY",
                "CREATE POLICY user_rows ON supabase_items FOR SELECT TO authenticated USING (owner_sub = (current_setting('request.jwt.claims',true)::json ->> 'sub'))",
                f"CREATE FUNCTION check_token() RETURNS void LANGUAGE plpgsql AS $$DECLARE claims json:=current_setting('request.jwt.claims',true)::json; BEGIN IF claims->>'iss'<>'{ISSUER}' OR claims->>'aud'<>'{AUDIENCE}' OR claims->>'role'<>'authenticated' OR coalesce(claims->>'sub','')='' THEN RAISE insufficient_privilege; END IF; END$$",
                "REVOKE ALL ON FUNCTION check_token() FROM PUBLIC",
                "GRANT EXECUTE ON FUNCTION check_token() TO authenticated",
            )
            for statement in statements:
                psql(postgres, statement)
            role_state = psql(postgres, "SELECT rolsuper,rolcreaterole,rolcreatedb,rolcanlogin FROM pg_roles WHERE rolname='authenticator'").stdout.strip()
            rls_state = psql(postgres, "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname='supabase_items'").stdout.strip()
            command(
                "docker", "run", "--detach", "--name", postgrest, "--network", network,
                "--publish", "127.0.0.1::3000",
                "--env", f"PGRST_DB_URI=postgresql://authenticator:auth-test-only@{postgres}:5432/ndabi",
                "--env", "PGRST_DB_SCHEMAS=public", "--env", "PGRST_DB_ANON_ROLE=anon",
                "--env", f"PGRST_JWT_SECRET={jwks}", "--env", f"PGRST_JWT_AUD={AUDIENCE}",
                "--env", "PGRST_DB_PRE_REQUEST=public.check_token", "--env", "PGRST_LOG_LEVEL=warn",
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
            connection = f"host=127.0.0.1 port={postgres_port} user=authenticator password=auth-test-only dbname=ndabi"
            endpoint = f"http://127.0.0.1:{postgrest_port}/supabase_items"

            admissions = admission_probe(token_paths, public_key)
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
            authorised_probe = command(
                str(BINARY), "--ndabi-probe", connection, str(token_paths["valid"]), str(public_key),
                KEY_ID, ISSUER, AUDIENCE, "1000", "2", check=False,
            )
            cross_subject_probe = command(
                str(BINARY), "--ndabi-probe", connection, str(token_paths["valid"]), str(public_key),
                KEY_ID, ISSUER, AUDIENCE, "900000", "2", check=False,
            )
            user_two_probe = command(
                str(BINARY), "--ndabi-probe", connection, str(token_paths["user_two"]), str(public_key),
                KEY_ID, ISSUER, AUDIENCE, "900000", "2", check=False,
            )
            authorised_report = (
                json.loads(authorised_probe.stdout) if authorised_probe.returncode == 0 else {}
            )
            security.update(
                {
                    "authorised_ndabi_rows_accepted": authorised_probe.returncode == 0,
                    "cross_subject_ndabi_rows_refused": cross_subject_probe.returncode != 0,
                    "second_subject_ndabi_rows_accepted": user_two_probe.returncode == 0,
                    "changed_ndabi_frame_refused": authorised_report.get("changed_frame_refused") is True,
                    "ndabi_replay_refused_before_query": authorised_report.get("replay_refused_before_query") is True,
                    "invalid_ndabi_receipt_refused": authorised_report.get("invalid_receipt_refused") is True,
                    "valid_ndabi_result_accepted": authorised_report.get("valid_result_accepted") is True,
                }
            )
            cross_status, cross_body = shared.request(
                f"{endpoint}?select=id&id=gte.900000&id=lt.900002", bearer=valid_one
            )
            security["cross_subject_postgrest_rows_hidden"] = cross_status == 200 and json.loads(cross_body) == []
            write_status, _ = shared.request(
                endpoint,
                method="POST",
                bearer=valid_one,
                body=b'{"id":1000001,"bucket":1,"owner":1,"score":1,"payload":"\\x00","owner_sub":"user-1"}',
            )
            security["user_write_refused"] = write_status >= 400
            security_passed = all(security.values())

            for process in range(1, PROCESS_COUNT + 1):
                psql(postgres, "SELECT pg_stat_statements_reset()")
                completed = command(
                    str(BINARY), connection, endpoint, str(token_paths["valid"]), str(public_key),
                    KEY_ID, ISSUER, AUDIENCE, check=False,
                )
                try:
                    report = json.loads(completed.stdout)
                except json.JSONDecodeError as error:
                    report = {
                        "process": process,
                        "parsed": False,
                        "binary_exit_code": completed.returncode,
                        "validation_error": str(error),
                        "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
                        "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
                        "passed": False,
                    }
                else:
                    observed = int(psql(
                        postgres,
                        "SELECT coalesce(sum(calls),0)::bigint FROM pg_stat_statements WHERE query LIKE '%supabase_items%' AND query NOT LIKE '%pg_stat_statements%'",
                    ).stdout.strip())
                    report["process"] = process
                    report["parsed"] = True
                    report["binary_exit_code"] = completed.returncode
                    report["observed_data_queries"] = observed
                    report["data_query_gate_passed"] = observed == EXPECTED_QUERIES
                    validation_error = None
                    try:
                        validate_report(report)
                    except (KeyError, TypeError, ValueError) as error:
                        validation_error = str(error)
                    report["validation_error"] = validation_error
                    report["validated"] = validation_error is None
                    report["passed"] &= report["data_query_gate_passed"]
                (campaign / f"process-{process}.json").write_text(
                    json.dumps(report, indent=2) + "\n", encoding="utf-8"
                )
                reports.append(report)

            repeatability = []
            repeatability_passed = len(reports) == PROCESS_COUNT and all(
                report.get("validated") for report in reports
            )
            if repeatability_passed:
                for operations in BATCH_SIZES:
                    cases = [
                        next(
                            case
                            for case in report["cases"]
                            if case["operations"] == operations
                        )
                        for report in reports
                    ]
                    for name in ("ndabi_postgrest_p50_distance",):
                        values = [case[name] for case in cases]
                        variation = coefficient_of_variation(values)
                        repeatability.append(
                            {
                                "operations": operations,
                                "ratio": name,
                                "coefficient_of_variation": variation,
                            }
                        )
                        repeatability_passed &= variation < 0.10
            accepted = (
                repeatability_passed
                and security_passed
                and role_state == "f|f|f|t"
                and rls_state == "t|t"
                and all(report.get("passed") is True for report in reports)
                and all(report.get("binary_exit_code") == 0 for report in reports)
            )
            final_source_sha256 = source_sha256()
            source_custody_passed = (
                final_source_sha256 == initial_source_sha256
                and source_matches_commit(repository_root(), source_commit)
            )
            accepted &= source_custody_passed
            aggregate = {
                "campaign": "NDABI Supabase indexed-batch-session campaign v7.1",
                "campaign_id": campaign_id,
                "process_count": PROCESS_COUNT,
                "source_commit": source_commit,
                "source_sha256": final_source_sha256,
                "source_custody_passed": source_custody_passed,
                "binary_sha256": file_sha256(BINARY),
                "postgres_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE).stdout.strip(),
                "postgrest_image_id": command("docker", "image", "inspect", "--format", "{{.Id}}", POSTGREST_IMAGE).stdout.strip(),
                "cryptography_version": cryptography.__version__,
                "environment": {
                    "platform": platform.platform(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "python_version": platform.python_version(),
                    "rustc_version": command("rustc", "--version").stdout.strip(),
                    "docker_server_version": command(
                        "docker", "version", "--format", "{{.Server.Version}}"
                    ).stdout.strip(),
                    "executable": sys.executable,
                },
                "authenticator_least_privilege": role_state == "f|f|f|t",
                "rls_enabled_and_forced": rls_state == "t|t",
                "security": security,
                "security_passed": security_passed,
                "repeatability": repeatability,
                "repeatability_passed": repeatability_passed,
                "accepted": accepted,
            }
            encoded = json.dumps(aggregate, indent=2) + "\n"
            (campaign / "aggregate.json").write_text(encoded, encoding="utf-8")
            latest.write_text(encoded, encoding="utf-8")
            print(encoded, end="")
            return 0 if accepted else 1
        finally:
            command("docker", "rm", "--force", postgrest, check=False)
            command("docker", "rm", "--force", postgres, check=False)
            command("docker", "network", "rm", network, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
