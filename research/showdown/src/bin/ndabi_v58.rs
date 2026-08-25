use std::time::{SystemTime, UNIX_EPOCH};

use ndabi_postgres_v1::{
    digest_label, memory_replay_store, AuthorityContext, OperationBinding, RangeBackend,
    RangeProfile, ServerSession, WireClientSession, FRAME_BYTES,
};
use ndabi_protocol::{Authority, SystemClock};
use postgres::{Client, NoTls};
use serde::Serialize;

const SQL: &str =
    "SELECT id,bucket,owner,score,payload FROM supabase_items WHERE id = ANY($1) ORDER BY id";

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    trusted_service_binding: bool,
    complete_result_match: bool,
    response_bytes: usize,
    response_rows: u32,
    receipt_nonzero: bool,
    frame_bytes: usize,
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
        OperationBinding::new(58, 580).map_err(|error| error.to_string())?,
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
    let authority = Authority::new_read([58; 32], 1, 58, expires, context)
        .map_err(|error| error.to_string())?;
    let mut encoder = WireClientSession::new(authority.clone());
    let operation = profile.operation(1, 2).map_err(|error| error.to_string())?;
    let frame = encoder
        .encode(operation, 1_024, 2, deadline)
        .map_err(|error| error.to_string())?;
    let mut backend = RangeBackend::new(client, profile, schema_digest, policy_digest)
        .map_err(|error| error.to_string())?;
    let server = ServerSession::new(authority, 1_024, 2).map_err(|error| error.to_string())?;
    let mut replay = memory_replay_store();
    let result = server
        .execute(&frame, &mut backend, &mut replay, &SystemClock)
        .map_err(|error| error.to_string())?;
    let expected = expected_rows();
    let complete_result_match = result.bytes == expected;
    let receipt_nonzero = result.receipt.iter().any(|byte| *byte != 0);
    let authority_context_bound =
        context_digest.iter().any(|byte| *byte != 0) && frame[96..128] == context_digest;
    let trusted_service_binding =
        complete_result_match && result.rows == 2 && receipt_nonzero && authority_context_bound;
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            campaign: "NDABI canonical Supabase binding v5.8",
            trusted_service_binding,
            complete_result_match,
            response_bytes: result.bytes.len(),
            response_rows: result.rows,
            receipt_nonzero,
            frame_bytes: FRAME_BYTES,
            authority_context_bound,
        })
        .map_err(|_| "the report encoding failed")?
    );
    if trusted_service_binding {
        Ok(())
    } else {
        Err("the trusted Supabase binding result is invalid".to_string())
    }
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
