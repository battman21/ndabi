//! Prove one cached dynamic program through an admitted Supabase-compatible RLS session.
//!
//! The probe connects as a non-superuser authenticator.
//! The adapter then assumes only the authenticated role and installs exact JWT claims.

use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ndabi_isa::{
    capability_digest, verify_operands, verify_program, Field, OperandBuilder, ParameterDescriptor,
    ParameterValue, ProgramBuilder, Relation, ScalarType, Schema, SortDirection, SortTerm,
    VerifyLimits,
};
use ndabi_postgres::isa::{FieldBinding, PostgresCatalogue, RelationBinding};
use ndabi_postgres_v1::digest_label;
use ndabi_protocol::{
    Authority, AuthorityContext, BackendIdentity, ClientSession, DynamicProgramStore,
    MemoryReplayStore, ProtocolError, ServerSession, SystemClock,
};
use ndabi_supabase_v1::{JwtVerifier, UserDynamicPostgresBackend};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use p256::SecretKey;
use postgres::{Client, NoTls};
use rand_core::OsRng;
use serde_json::json;

const READ: u64 = 1;
const RESULT_BUDGET: u32 = 4_096;
const ROW_BUDGET: u32 = 8;
const KEY_ID: &str = "ndabi-supabase-dynamic-probe";
const ISSUER: &str = "https://ndabi.test/auth/v1";
const AUDIENCE: &str = "authenticated";

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let connection = std::env::var("NDABI_SUPABASE_TEST_CONNECTION")?;
    let subject = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "user-a".to_string());
    if subject != "user-a" && subject != "user-b" {
        return Err("the probe subject must be user-a or user-b".into());
    }

    let admission = admission_evidence(&subject)?;
    let user = admission.user;
    let schema = schema()?;
    let catalogue = catalogue(&schema)?;
    let program_bytes = program(&schema)?;
    let program = verify_program(&program_bytes, &schema, READ, VerifyLimits::default())?;
    let operand_bytes = operands(&program)?;
    let operands = verify_operands(&operand_bytes, &program)?;
    let identity = BackendIdentity::new(
        41,
        43,
        schema.digest(),
        digest_label(
            b"policy",
            b"forced-rls:owner_sub=request.jwt.claims.sub;authenticated;read-only",
        ),
        digest_label(b"profile", b"dynamic-supabase-v1"),
    )?;
    let context = AuthorityContext::new(
        user.tenant_id(),
        user.principal_id(),
        47,
        capability_digest(READ),
        identity,
    )?;
    let deadline = user.session_expires_unix_us();
    let authority = Authority::new_read([53; 32], 59, 61, deadline, context)?;
    let postgres = Client::connect(&connection, NoTls)?;
    let mut backend =
        UserDynamicPostgresBackend::new(postgres, identity, schema, catalogue, READ, &user)?;
    let server = ServerSession::new(authority.clone(), RESULT_BUDGET, ROW_BUDGET)?;
    let mut client = ClientSession::new(authority.clone());
    let mut replay = MemoryReplayStore::default();
    let mut store = DynamicProgramStore::new(16, 4_096, 65_536)?;

    let registration = client.encode_dynamic_program_registration(&program, deadline)?;
    let accepted = server.register_dynamic_program(
        &registration,
        &mut store,
        &backend,
        &mut replay,
        &SystemClock,
    )?;
    let handle = client.verify_dynamic_program_accepted(&registration, &accepted)?;
    let frame =
        client.encode_cached_dynamic(handle, &operands, RESULT_BUDGET, ROW_BUDGET, deadline)?;
    let execution = server.execute_cached_dynamic(
        &frame,
        &mut store,
        &mut backend,
        &mut replay,
        &SystemClock,
    )?;
    client.verify_execution_receipt(
        &frame,
        execution.rows,
        &execution.bytes,
        &execution.receipt,
    )?;

    let decoded = decode_users(&execution.bytes)?;
    let expected = expected_users(&subject);
    if decoded != expected || execution.rows != u32::try_from(expected.len())? {
        return Err("row-level security returned an unexpected result".into());
    }

    let replay_refused = matches!(
        server.execute_cached_dynamic(&frame, &mut store, &mut backend, &mut replay, &SystemClock,),
        Err(ProtocolError::Replay)
    );
    let mut changed_frame = frame.clone();
    let changed_index = changed_frame
        .len()
        .checked_sub(33)
        .ok_or("the cached frame is incomplete")?;
    changed_frame[changed_index] ^= 1;
    let mutation_refused = matches!(
        server.execute_cached_dynamic(
            &changed_frame,
            &mut store,
            &mut backend,
            &mut MemoryReplayStore::default(),
            &SystemClock,
        ),
        Err(ProtocolError::AuthenticationFailed)
    );
    let principal_refused = principal_mismatch_refused(
        &program,
        &operands,
        identity,
        &authority,
        deadline,
        &mut backend,
    )?;
    if !admission.refusals || !replay_refused || !mutation_refused || !principal_refused {
        return Err("one dynamic Supabase refusal gate failed".into());
    }

    let full_frame =
        client.encode_dynamic(&program, &operands, RESULT_BUDGET, ROW_BUDGET, deadline)?;
    let request_reduction_percent = 100.0 * (1.0 - frame.len() as f64 / full_frame.len() as f64);
    println!(
        "{}",
        json!({
            "schema": "ndabi-dynamic-supabase-rls-probe-v0.1",
            "subject": subject,
            "rows": decoded,
            "row_count": execution.rows,
            "result_digest": blake3::hash(&execution.bytes).to_hex().to_string(),
            "full_request_bytes": full_frame.len(),
            "cached_request_bytes": frame.len(),
            "request_reduction_percent": request_reduction_percent,
            "prepared_programs": backend.prepared_programs(),
            "exact_results": true,
            "receipt_verified": true,
            "rls_isolated": true,
            "replay_refused": replay_refused,
            "mutation_refused": mutation_refused,
            "principal_refused": principal_refused,
            "jwt_refusals": admission.refusals,
        })
    );
    Ok(())
}

fn principal_mismatch_refused(
    program: &ndabi_isa::VerifiedProgram<'_>,
    operands: &ndabi_isa::VerifiedOperands<'_>,
    identity: BackendIdentity,
    authority: &Authority,
    deadline: u64,
    backend: &mut UserDynamicPostgresBackend,
) -> Result<bool, Box<dyn Error>> {
    let context = AuthorityContext::new(
        authority.context().tenant(),
        [0xee; 16],
        47,
        capability_digest(READ),
        identity,
    )?;
    let mismatched = Authority::new_read([71; 32], 73, 79, deadline, context)?;
    let mut client = ClientSession::new(mismatched.clone());
    let frame = client.encode_dynamic(program, operands, RESULT_BUDGET, ROW_BUDGET, deadline)?;
    let server = ServerSession::new(mismatched, RESULT_BUDGET, ROW_BUDGET)?;
    Ok(matches!(
        server.execute_dynamic(
            &frame,
            backend,
            &mut MemoryReplayStore::default(),
            &SystemClock,
        ),
        Err(ProtocolError::AuthorityMismatch)
    ))
}

struct AdmissionEvidence {
    user: ndabi_supabase_v1::AdmittedIdentity,
    refusals: bool,
}

fn admission_evidence(subject: &str) -> Result<AdmissionEvidence, Box<dyn Error>> {
    let secret = SecretKey::random(&mut OsRng);
    let private = secret.to_pkcs8_der()?;
    let public = secret.public_key().to_public_key_pem(LineEnding::LF)?;
    let verifier = JwtVerifier::new_es256(public.as_bytes(), KEY_ID, ISSUER, AUDIENCE, 300)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let encoding_key = EncodingKey::from_ec_der(private.as_bytes());
    let token = signed_token(&encoding_key, subject, AUDIENCE, "authenticated", now + 300)?;
    let user = verifier.admit(&token)?;
    let changed = changed_signature(&token)?;
    let wrong_audience = signed_token(
        &encoding_key,
        subject,
        "another-audience",
        "authenticated",
        now + 300,
    )?;
    let wrong_role = signed_token(&encoding_key, subject, AUDIENCE, "service_role", now + 300)?;
    let expired = signed_token(
        &encoding_key,
        subject,
        AUDIENCE,
        "authenticated",
        now.saturating_sub(1),
    )?;
    Ok(AdmissionEvidence {
        user,
        refusals: verifier.admit(&changed).is_err()
            && verifier.admit(&wrong_audience).is_err()
            && verifier.admit(&wrong_role).is_err()
            && verifier.admit(&expired).is_err(),
    })
}

fn signed_token(
    key: &EncodingKey,
    subject: &str,
    audience: &str,
    role: &str,
    expires_unix_s: u64,
) -> Result<String, Box<dyn Error>> {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".to_string());
    header.kid = Some(KEY_ID.to_string());
    let claims = json!({
        "iss": ISSUER,
        "aud": audience,
        "sub": subject,
        "role": role,
        "exp": expires_unix_s,
    });
    Ok(encode(&header, &claims, key)?)
}

fn changed_signature(token: &str) -> Result<String, Box<dyn Error>> {
    let mut changed = token.as_bytes().to_vec();
    let signature = changed
        .iter()
        .rposition(|byte| *byte == b'.')
        .and_then(|offset| offset.checked_add(1))
        .filter(|offset| *offset < changed.len())
        .ok_or("the JWT signature is absent")?;
    changed[signature] = if changed[signature] == b'A' {
        b'B'
    } else {
        b'A'
    };
    Ok(String::from_utf8(changed)?)
}

fn schema() -> Result<Schema, Box<dyn Error>> {
    Ok(Schema::new(vec![Relation::new(
        11,
        READ,
        vec![
            Field::new(101, ScalarType::I64, false, READ)?,
            Field::new(102, ScalarType::I64, false, READ)?,
            Field::new(103, ScalarType::Utf8, false, READ)?,
        ],
    )?])?)
}

fn catalogue(schema: &Schema) -> Result<PostgresCatalogue, Box<dyn Error>> {
    Ok(PostgresCatalogue::new(
        schema,
        vec![RelationBinding::new(
            11,
            "public",
            "supabase_items",
            vec![
                FieldBinding::new(101, "id")?,
                FieldBinding::new(102, "score")?,
                FieldBinding::new(103, "owner_sub")?,
            ],
        )?],
    )?)
}

fn program(schema: &Schema) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut builder = ProgramBuilder::new(schema.digest(), 16)?;
    let limit = builder.parameter(ParameterDescriptor::new(ScalarType::U64, 8)?)?;
    let scan = builder.scan(11)?;
    let projected = builder.project(scan, &[101, 103])?;
    let sorted = builder.sort(
        projected,
        &[SortTerm {
            field: 101,
            direction: SortDirection::Ascending,
        }],
    )?;
    let limited = builder.limit(sorted, limit)?;
    builder.return_result(limited)?;
    Ok(builder.finish()?)
}

fn operands(program: &ndabi_isa::VerifiedProgram<'_>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut builder = OperandBuilder::new(program);
    builder.push(ParameterValue::U64(4))?;
    Ok(builder.finish()?)
}

fn expected_users(subject: &str) -> Vec<(i64, String)> {
    let ids = if subject == "user-a" {
        [2, 4, 6, 8]
    } else {
        [1, 3, 5, 7]
    };
    ids.into_iter()
        .map(|id| (id, subject.to_string()))
        .collect()
}

fn decode_users(bytes: &[u8]) -> Result<Vec<(i64, String)>, Box<dyn Error>> {
    if bytes.len() < 80 || &bytes[0..4] != b"NDIR" {
        return Err("the dynamic result header is invalid".into());
    }
    let declared_bytes = u32::from_le_bytes(bytes[8..12].try_into()?) as usize;
    let rows = u32::from_le_bytes(bytes[12..16].try_into()?) as usize;
    let columns = u16::from_le_bytes(bytes[16..18].try_into()?);
    if declared_bytes != bytes.len() || columns != 2 {
        return Err("the dynamic result shape is invalid".into());
    }
    let mut offset = 80;
    let mut decoded = Vec::with_capacity(rows);
    for _ in 0..rows {
        if bytes.get(offset) != Some(&0b11) {
            return Err("the dynamic result presence bitmap is invalid".into());
        }
        offset += 1;
        let id_end = offset
            .checked_add(8)
            .ok_or("the result offset overflowed")?;
        let id = i64::from_le_bytes(
            bytes
                .get(offset..id_end)
                .ok_or("the id is absent")?
                .try_into()?,
        );
        offset = id_end;
        let length_end = offset
            .checked_add(4)
            .ok_or("the result offset overflowed")?;
        let length = u32::from_le_bytes(
            bytes
                .get(offset..length_end)
                .ok_or("the owner length is absent")?
                .try_into()?,
        ) as usize;
        offset = length_end;
        let owner_end = offset
            .checked_add(length)
            .ok_or("the result offset overflowed")?;
        let owner = std::str::from_utf8(
            bytes
                .get(offset..owner_end)
                .ok_or("the owner value is absent")?,
        )?
        .to_string();
        offset = owner_end;
        decoded.push((id, owner));
    }
    if offset != bytes.len() {
        return Err("the dynamic result has trailing bytes".into());
    }
    Ok(decoded)
}
