//! Prove the sealed PostgreSQL registry against service and Supabase user connections.
//!
//! Keep this functional proof separate from accepted legacy and performance campaigns.
//! The harness executes one fixed SQL implementation and never accepts SQL from its caller.

use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use ndabi_postgres_v1::{
    digest_label, OperationBinding, RangeBackend, RangeProfile,
    POSTGRESQL_RANGE_REGISTRY_PROFILE_ID,
};
use ndabi_protocol::{
    Authority, AuthorityContext, Backend, ClientSession, MemoryReplayStore, Operation,
    PlanRegistry, ProtocolError, RegisteredBackend, ServerSession, SystemClock, FRAME_BYTES,
};
use ndabi_supabase_v1::{AdmittedIdentity, JwtVerifier, UserRangeBackend};
use postgres::{Client, NoTls};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SQL: &str =
    "SELECT id,bucket,owner,score,payload FROM supabase_items WHERE id = ANY($1) ORDER BY id";
const PLAN_HANDLE: u32 = 90;
const RESULT_SHAPE: u32 = 900;

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    mode: &'static str,
    registered_profile: String,
    registry_digest: String,
    request_bytes: usize,
    result_rows: u32,
    result_bytes: usize,
    result_sha256: String,
    changed_registry_refused: bool,
    legacy_identity_refused: bool,
    unknown_handle_refused: bool,
    changed_shape_refused: bool,
    excessive_limits_refused: bool,
    changed_frame_refused: bool,
    replay_refused: bool,
    receipt_verified: bool,
    passed: bool,
}

struct ExecutionProof {
    rows: u32,
    bytes: Vec<u8>,
    unknown_handle_refused: bool,
    changed_shape_refused: bool,
    excessive_limits_refused: bool,
    changed_frame_refused: bool,
    replay_refused: bool,
    receipt_verified: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("service") => run_service(&arguments[1..]),
        Some("user") => run_user(&arguments[1..]),
        _ => Err("use service or user mode".to_string()),
    }
}

fn run_service(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 3 {
        return Err("service mode needs a connection, start, and row count".to_string());
    }
    let start = parse_i64(&arguments[1], "service start")?;
    let rows = parse_u32(&arguments[2], "service row count")?;
    let profile = profile()?;
    let registry = registry(profile)?;
    let changed_registry_refused = changed_service_registry_refused(&arguments[0], profile)?;
    let legacy_identity_refused =
        legacy_service_identity_refused(&arguments[0], profile, &registry)?;
    let client =
        Client::connect(&arguments[0], NoTls).map_err(|_| "the service connection failed")?;
    let backend = RangeBackend::new_registered(client, profile, &registry)
        .map_err(|error| error.to_string())?;
    let authority = authority(registry.identity(), [2; 16], 9_001)?;
    let operation = profile
        .operation(start, rows)
        .map_err(|error| error.to_string())?;
    let proof = prove_registered(&registry, authority, operation, backend)?;
    emit_report(
        "service",
        &registry,
        proof,
        changed_registry_refused,
        legacy_identity_refused,
    )
}

fn run_user(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 8 {
        return Err(
            "user mode needs a connection, token, public key, key identifier, issuer, audience, start, and row count"
                .to_string(),
        );
    }
    let token = Zeroizing::new(
        std::fs::read_to_string(&arguments[1])
            .map_err(|_| "the user token cannot be read")?
            .trim()
            .to_string(),
    );
    let public_key =
        std::fs::read(&arguments[2]).map_err(|_| "the user public key cannot be read")?;
    let verifier = JwtVerifier::new_es256(
        &public_key,
        &arguments[3],
        &arguments[4],
        &arguments[5],
        300,
    )
    .map_err(|error| error.to_string())?;
    let user = verifier
        .admit(token.as_str())
        .map_err(|error| error.to_string())?;
    let start = parse_i64(&arguments[6], "user start")?;
    let rows = parse_u32(&arguments[7], "user row count")?;
    let profile = profile()?;
    let registry = registry(profile)?;
    let changed_registry_refused =
        changed_user_registry_refused(&arguments[0], profile, &registry, &user)?;
    let legacy_identity_refused =
        legacy_user_identity_refused(&arguments[0], profile, &registry, &user)?;
    let client = Client::connect(&arguments[0], NoTls).map_err(|_| "the user connection failed")?;
    let backend = UserRangeBackend::new_registered(client, profile, &registry, &user)
        .map_err(|error| error.to_string())?;
    let mut principal = [0_u8; 16];
    principal.copy_from_slice(&user.identity_digest()[..16]);
    let authority = authority(registry.identity(), principal, 9_002)?;
    let operation = profile
        .operation(start, rows)
        .map_err(|error| error.to_string())?;
    let proof = prove_registered(&registry, authority, operation, backend)?;
    emit_report(
        "user-rls",
        &registry,
        proof,
        changed_registry_refused,
        legacy_identity_refused,
    )
}

fn profile() -> Result<RangeProfile, String> {
    RangeProfile::new(
        SQL,
        OperationBinding::new(PLAN_HANDLE, RESULT_SHAPE).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn registry(profile: RangeProfile) -> Result<PlanRegistry, String> {
    profile
        .plan_registry(schema_digest(), policy_digest())
        .map_err(|error| error.to_string())
}

fn schema_digest() -> [u8; 32] {
    digest_label(
        b"ndabi/registry-postgres/schema/v1",
        b"supabase_items(id:i64,bucket:i32,owner:i32,score:i32,payload:bytes64,owner_sub:text)",
    )
}

fn policy_digest() -> [u8; 32] {
    digest_label(
        b"ndabi/registry-postgres/policy/v1",
        b"service:read-only;user:authenticated;rls:owner_sub=jwt.sub;writes:refuse",
    )
}

fn authority(
    identity: ndabi_protocol::BackendIdentity,
    principal: [u8; 16],
    session: u64,
) -> Result<Authority, String> {
    let context = AuthorityContext::new(
        *b"registry-pg-test",
        principal,
        1,
        digest_label(
            b"ndabi/registry-postgres/capability/v1",
            b"registered-range-read",
        ),
        identity,
    )
    .map_err(|error| error.to_string())?;
    let expires = unix_us()?
        .checked_add(30_000_000)
        .ok_or_else(|| "the authority expiry overflowed".to_string())?;
    Authority::new_read([90; 32], 1, session, expires, context).map_err(|error| error.to_string())
}

fn prove_registered<B: Backend>(
    registry: &PlanRegistry,
    authority: Authority,
    operation: Operation,
    backend: B,
) -> Result<ExecutionProof, String> {
    let plan = registry
        .plan(operation.plan_handle)
        .ok_or_else(|| "the registered plan is absent".to_string())?;
    let maximum_result_bytes = plan
        .maximum_result_bytes()
        .checked_add(1)
        .ok_or_else(|| "the plan result limit overflowed".to_string())?;
    let maximum_rows = plan
        .maximum_rows()
        .checked_add(1)
        .ok_or_else(|| "the plan row limit overflowed".to_string())?;
    let server = ServerSession::new(authority.clone(), maximum_result_bytes, maximum_rows)
        .map_err(|error| error.to_string())?;
    let mut backend =
        RegisteredBackend::new(registry, backend).map_err(|error| error.to_string())?;

    let unknown = Operation::new(
        operation.opcode,
        operation
            .plan_handle
            .checked_add(1)
            .ok_or_else(|| "the plan handle overflowed".to_string())?,
        operation.result_shape,
        operation.first,
        operation.second,
        operation.third,
    )
    .map_err(|error| error.to_string())?;
    let unknown_handle_refused = refusal(
        &server,
        &authority,
        &mut backend,
        unknown,
        result_bytes(operation.third)?,
        operation.third,
        ProtocolError::PlanNotRegistered,
    )?;

    let changed_shape = Operation::new(
        operation.opcode,
        operation.plan_handle,
        operation
            .result_shape
            .checked_add(1)
            .ok_or_else(|| "the result shape overflowed".to_string())?,
        operation.first,
        operation.second,
        operation.third,
    )
    .map_err(|error| error.to_string())?;
    let changed_shape_refused = refusal(
        &server,
        &authority,
        &mut backend,
        changed_shape,
        result_bytes(operation.third)?,
        operation.third,
        ProtocolError::PlanShapeMismatch,
    )?;

    let excessive_limits_refused = refusal(
        &server,
        &authority,
        &mut backend,
        operation,
        maximum_result_bytes,
        maximum_rows,
        ProtocolError::PlanLimitExceeded,
    )?;

    let changed_deadline = deadline()?;
    let mut changed_client = ClientSession::new(authority.clone());
    let mut changed_frame = changed_client
        .encode(
            operation,
            result_bytes(operation.third)?,
            operation.third,
            changed_deadline,
        )
        .map_err(|error| error.to_string())?;
    changed_frame[64] ^= 1;
    let changed_frame_refused = matches!(
        server.execute(
            &changed_frame,
            &mut backend,
            &mut MemoryReplayStore::default(),
            &SystemClock,
        ),
        Err(ProtocolError::AuthenticationFailed)
    );

    let mut client = ClientSession::new(authority);
    let frame = client
        .encode(
            operation,
            result_bytes(operation.third)?,
            operation.third,
            deadline()?,
        )
        .map_err(|error| error.to_string())?;
    let mut replay = MemoryReplayStore::default();
    let execution = server
        .execute(&frame, &mut backend, &mut replay, &SystemClock)
        .map_err(|error| error.to_string())?;
    let receipt_verified = client
        .verify_execution_receipt(&frame, execution.rows, &execution.bytes, &execution.receipt)
        .is_ok();
    let replay_refused = matches!(
        server.execute(&frame, &mut backend, &mut replay, &SystemClock),
        Err(ProtocolError::Replay)
    );

    Ok(ExecutionProof {
        rows: execution.rows,
        bytes: execution.bytes,
        unknown_handle_refused,
        changed_shape_refused,
        excessive_limits_refused,
        changed_frame_refused,
        replay_refused,
        receipt_verified,
    })
}

#[allow(clippy::too_many_arguments)]
fn refusal<B: Backend>(
    server: &ServerSession,
    authority: &Authority,
    backend: &mut B,
    operation: Operation,
    result_budget: u32,
    row_budget: u32,
    expected: ProtocolError,
) -> Result<bool, String> {
    let mut client = ClientSession::new(authority.clone());
    let frame = client
        .encode(operation, result_budget, row_budget, deadline()?)
        .map_err(|error| error.to_string())?;
    Ok(matches!(
        server.execute(
            &frame,
            backend,
            &mut MemoryReplayStore::default(),
            &SystemClock,
        ),
        Err(error) if error == expected
    ))
}

fn changed_service_registry_refused(
    connection: &str,
    profile: RangeProfile,
) -> Result<bool, String> {
    let changed = RangeProfile::new(
        SQL,
        OperationBinding::new(PLAN_HANDLE + 1, RESULT_SHAPE).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let changed_registry = registry(changed)?;
    let client = Client::connect(connection, NoTls)
        .map_err(|_| "the changed-registry service connection failed")?;
    Ok(matches!(
        RangeBackend::new_registered(client, profile, &changed_registry),
        Err(ProtocolError::PlanRegistryMismatch)
    ))
}

fn legacy_service_identity_refused(
    connection: &str,
    profile: RangeProfile,
    registry: &PlanRegistry,
) -> Result<bool, String> {
    let client =
        Client::connect(connection, NoTls).map_err(|_| "the legacy service connection failed")?;
    let backend = RangeBackend::new(client, profile, schema_digest(), policy_digest())
        .map_err(|error| error.to_string())?;
    Ok(matches!(
        RegisteredBackend::new(registry, backend),
        Err(ProtocolError::PlanRegistryMismatch)
    ))
}

fn changed_user_registry_refused(
    connection: &str,
    profile: RangeProfile,
    _registry: &PlanRegistry,
    user: &AdmittedIdentity,
) -> Result<bool, String> {
    let changed = RangeProfile::new(
        SQL,
        OperationBinding::new(PLAN_HANDLE + 1, RESULT_SHAPE).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let changed_registry = registry(changed)?;
    let client = Client::connect(connection, NoTls)
        .map_err(|_| "the changed-registry user connection failed")?;
    Ok(matches!(
        UserRangeBackend::new_registered(client, profile, &changed_registry, user),
        Err(ProtocolError::PlanRegistryMismatch)
    ))
}

fn legacy_user_identity_refused(
    connection: &str,
    profile: RangeProfile,
    registry: &PlanRegistry,
    user: &AdmittedIdentity,
) -> Result<bool, String> {
    let client =
        Client::connect(connection, NoTls).map_err(|_| "the legacy user connection failed")?;
    let backend = UserRangeBackend::new(client, profile, schema_digest(), policy_digest(), user)
        .map_err(|error| error.to_string())?;
    Ok(matches!(
        RegisteredBackend::new(registry, backend),
        Err(ProtocolError::PlanRegistryMismatch)
    ))
}

fn emit_report(
    mode: &'static str,
    registry: &PlanRegistry,
    proof: ExecutionProof,
    changed_registry_refused: bool,
    legacy_identity_refused: bool,
) -> Result<(), String> {
    let passed = proof.rows > 0
        && changed_registry_refused
        && legacy_identity_refused
        && proof.unknown_handle_refused
        && proof.changed_shape_refused
        && proof.excessive_limits_refused
        && proof.changed_frame_refused
        && proof.replay_refused
        && proof.receipt_verified;
    let report = Report {
        campaign: "NDABI registered PostgreSQL and Supabase-compatible RLS v0.3",
        mode,
        registered_profile: format!("0x{POSTGRESQL_RANGE_REGISTRY_PROFILE_ID:08x}"),
        registry_digest: hex(&registry.digest()),
        request_bytes: FRAME_BYTES,
        result_rows: proof.rows,
        result_bytes: proof.bytes.len(),
        result_sha256: hex(&Sha256::digest(&proof.bytes)),
        changed_registry_refused,
        legacy_identity_refused,
        unknown_handle_refused: proof.unknown_handle_refused,
        changed_shape_refused: proof.changed_shape_refused,
        excessive_limits_refused: proof.excessive_limits_refused,
        changed_frame_refused: proof.changed_frame_refused,
        replay_refused: proof.replay_refused,
        receipt_verified: proof.receipt_verified,
        passed,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
    );
    if passed {
        Ok(())
    } else {
        Err("the registered database proof failed".to_string())
    }
}

fn result_bytes(rows: u32) -> Result<u32, String> {
    rows.checked_mul(84)
        .and_then(|bytes| bytes.checked_add(6))
        .ok_or_else(|| "the result budget overflowed".to_string())
}

fn deadline() -> Result<u64, String> {
    unix_us()?
        .checked_add(5_000_000)
        .ok_or_else(|| "the deadline overflowed".to_string())
}

fn unix_us() -> Result<u64, String> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock failed")?
        .as_micros();
    u64::try_from(micros).map_err(|_| "the system clock exceeded u64 microseconds".to_string())
}

fn parse_i64(value: &str, label: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|_| format!("the {label} is invalid"))
}

fn parse_u32(value: &str, label: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("the {label} is invalid"))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("a string write cannot fail");
    }
    output
}
