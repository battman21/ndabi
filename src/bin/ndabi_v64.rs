use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use ndabi_postgres_v1::{
    digest_label, memory_replay_store, AuthorityContext, OperationBinding, RangeBackend,
    RangeProfile, ServerSession, WireClientSession, FRAME_BYTES,
};
use ndabi_protocol::{
    transport_frame_bytes, Authority, SystemClock, TransportConfig, TransportConnection,
    TransportFields, TransportKind, TransportRole,
};
use postgres::{Client, NoTls};
use serde::Serialize;
use sha2::{Digest, Sha256};

const SQL: &str =
    "SELECT id,bucket,owner,score,payload FROM supabase_items WHERE id = ANY($1) ORDER BY id";
const MAXIMUM_FRAME_BYTES: u32 = 4_096;
const MAXIMUM_CHUNK_BYTES: u32 = 1_024;

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    trusted_service_binding: bool,
    complete_result_match: bool,
    transport_result_match: bool,
    transport_negotiated: bool,
    transport_receipt_verified: bool,
    response_bytes: usize,
    response_rows: u32,
    result_sha256: String,
    canonical_request_bytes: usize,
    transport_result_frame_bytes: usize,
    authority_context_bound: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let connection = std::env::args()
        .nth(1)
        .ok_or_else(|| "a PostgreSQL connection is required".to_string())?;
    let client = Client::connect(&connection, NoTls).map_err(|_| "the connection failed")?;
    let profile = RangeProfile::new(
        SQL,
        OperationBinding::new(64, 640).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let schema_digest = digest_label(
        b"ndabi/supabase/schema/v1",
        b"supabase_items(id:i64,bucket:i32,owner:i32,score:i32,payload:bytes64,owner_sub:text)",
    );
    let policy_digest = digest_label(
        b"ndabi/supabase/policy/v1",
        b"service:select-only;user:owner_sub=jwt.sub;writes:refuse",
    );
    let identity = profile
        .identity(schema_digest, policy_digest)
        .map_err(|error| error.to_string())?;
    let context = AuthorityContext::new(
        *b"supabase-tenant1",
        *b"ndabi-service-v1",
        1,
        digest_label(
            b"ndabi/supabase/capability/v1",
            b"read:range:supabase_items",
        ),
        identity,
    )
    .map_err(|error| error.to_string())?;
    let context_digest = context.digest();
    let now = unix_us()?;
    let deadline = now
        .checked_add(5_000_000)
        .ok_or_else(|| "the deadline overflowed".to_string())?;
    let expires = now
        .checked_add(10_000_000)
        .ok_or_else(|| "the authority expiry overflowed".to_string())?;
    let authority = Authority::new_read([64; 32], 1, 64, expires, context)
        .map_err(|error| error.to_string())?;
    let mut wire_client = WireClientSession::new(authority.clone());
    let operation = profile.operation(1, 2).map_err(|error| error.to_string())?;
    let request = wire_client
        .encode(operation, 1_024, 2, deadline)
        .map_err(|error| error.to_string())?;

    let config = TransportConfig::new(0, MAXIMUM_FRAME_BYTES, MAXIMUM_CHUNK_BYTES, 4)
        .map_err(|error| error.to_string())?;
    let mut transport_client =
        TransportConnection::new(authority.clone(), TransportRole::Client, config);
    let mut transport_server =
        TransportConnection::new(authority.clone(), TransportRole::Server, config);
    negotiate(&mut transport_client, &mut transport_server, now)?;
    let client_request = transport_client
        .register_v1_request(&request)
        .map_err(|error| error.to_string())?;

    let mut backend = RangeBackend::new(client, profile, schema_digest, policy_digest)
        .map_err(|error| error.to_string())?;
    let wire_server = ServerSession::new(authority, 1_024, 2).map_err(|error| error.to_string())?;
    let mut replay = memory_replay_store();
    let execution = wire_server
        .execute(&request, &mut backend, &mut replay, &SystemClock)
        .map_err(|error| error.to_string())?;
    let server_request = transport_server
        .register_v1_request(&request)
        .map_err(|error| error.to_string())?;
    if client_request != server_request
        || execution.operation.result_shape != server_request.result_shape
    {
        return Err("the transport request binding changed".to_string());
    }

    let receipt = transport_server
        .result_receipt(server_request.nonce, execution.rows, &execution.bytes)
        .map_err(|error| error.to_string())?;
    let result_fields = TransportFields {
        correlation_nonce: server_request.nonce,
        rows: execution.rows,
        result_shape: server_request.result_shape,
        execution_receipt: receipt,
        ..TransportFields::empty()
    };
    let mut transport_result =
        vec![0; transport_frame_bytes(execution.bytes.len()).map_err(|error| error.to_string())?];
    transport_server
        .encode(
            TransportKind::Result,
            result_fields,
            &execution.bytes,
            &mut transport_result,
        )
        .map_err(|error| error.to_string())?;
    let decoded = transport_client
        .decode(&transport_result, unix_us()?)
        .map_err(|error| error.to_string())?;

    let expected = expected_rows();
    let complete_result_match = execution.bytes == expected;
    let transport_result_match = decoded.payload == expected;
    let transport_negotiated =
        transport_client.negotiated().is_some() && transport_server.negotiated().is_some();
    let transport_receipt_verified = transport_client
        .result_receipt(server_request.nonce, execution.rows, &execution.bytes)
        .is_err();
    let authority_context_bound =
        context_digest.iter().any(|byte| *byte != 0) && request[96..128] == context_digest;
    let trusted_service_binding = complete_result_match
        && transport_result_match
        && transport_negotiated
        && transport_receipt_verified
        && execution.rows == 2
        && authority_context_bound;
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            campaign: "NDABI PostgreSQL transport and Supabase binding v6.4",
            trusted_service_binding,
            complete_result_match,
            transport_result_match,
            transport_negotiated,
            transport_receipt_verified,
            response_bytes: execution.bytes.len(),
            response_rows: execution.rows,
            result_sha256: sha256_hex(&execution.bytes),
            canonical_request_bytes: FRAME_BYTES,
            transport_result_frame_bytes: transport_result.len(),
            authority_context_bound,
        })
        .map_err(|_| "the report encoding failed")?
    );
    if trusted_service_binding {
        Ok(())
    } else {
        Err("the trusted Supabase transport result is invalid".to_string())
    }
}

fn negotiate(
    client: &mut TransportConnection,
    server: &mut TransportConnection,
    now_unix_us: u64,
) -> Result<(), String> {
    transfer(
        client,
        server,
        TransportKind::Hello,
        TransportFields {
            auxiliary: MAXIMUM_FRAME_BYTES,
            ..TransportFields::empty()
        },
        &negotiation_payload(2, 2),
        now_unix_us,
    )?;
    transfer(
        server,
        client,
        TransportKind::Accept,
        TransportFields {
            auxiliary: MAXIMUM_FRAME_BYTES,
            ..TransportFields::empty()
        },
        &negotiation_payload(2, 0),
        now_unix_us,
    )
}

fn transfer(
    sender: &mut TransportConnection,
    receiver: &mut TransportConnection,
    kind: TransportKind,
    fields: TransportFields,
    payload: &[u8],
    now_unix_us: u64,
) -> Result<(), String> {
    let mut frame =
        vec![0; transport_frame_bytes(payload.len()).map_err(|error| error.to_string())?];
    sender
        .encode(kind, fields, payload, &mut frame)
        .map_err(|error| error.to_string())?;
    receiver
        .decode(&frame, now_unix_us)
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn negotiation_payload(first: u16, second: u16) -> [u8; 8] {
    let mut payload = [0; 8];
    payload[0..2].copy_from_slice(&first.to_le_bytes());
    payload[2..4].copy_from_slice(&second.to_le_bytes());
    payload[4..8].copy_from_slice(&MAXIMUM_CHUNK_BYTES.to_le_bytes());
    payload
}

fn expected_rows() -> Vec<u8> {
    let mut output = Vec::with_capacity(174);
    output.extend_from_slice(&1_u16.to_le_bytes());
    output.extend_from_slice(&2_u32.to_le_bytes());
    for (id, bucket, owner, score, payload) in [
        (1_i64, 1_i32, 1_i32, 100_i32, 0xaa_u8),
        (2_i64, 2_i32, 1_i32, 200_i32, 0xbb_u8),
    ] {
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&bucket.to_le_bytes());
        output.extend_from_slice(&owner.to_le_bytes());
        output.extend_from_slice(&score.to_le_bytes());
        output.extend_from_slice(&[payload; 64]);
    }
    output
}

fn unix_us() -> Result<u64, String> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock failed")?
        .as_micros();
    u64::try_from(micros).map_err(|_| "the system clock exceeded the protocol range".to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("a string write cannot fail");
    }
    output
}
