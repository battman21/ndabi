//! Prove the sealed MongoDB registry against one authenticated Docker engine.
//!
//! Keep fixture destruction behind an exact sentinel and a generated database name.
//! The execution path accepts only one finite identifier-window handle.

use std::fmt::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mongodb::bson::{spec::BinarySubtype, Binary};
use mongodb::event::{command::CommandEvent, EventHandler};
use mongodb::options::ClientOptions;
use mongodb::sync::Client;
use ndabi_mongodb_v1::{
    IdWindowBackend, IdWindowProfile, OperationBinding, MAX_BATCH_ITEMS,
    MONGODB_ID_WINDOW_REGISTRY_PROFILE_ID, ROW_BYTES,
};
use ndabi_protocol::{
    digest_label, Authority, AuthorityContext, Backend, ClientSession, MemoryReplayStore,
    Operation, PlanRegistry, ProtocolError, RegisteredBackend, ServerSession, SystemClock,
    FRAME_BYTES,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const PREPARE_SENTINEL: &str = "I_UNDERSTAND_THIS_DROPS_THE_EPHEMERAL_DATABASE";
const FIXTURE_ROWS: i64 = 256;
const PLAN_HANDLE: u32 = 91;
const RESULT_SHAPE: u32 = 910;

#[derive(Serialize)]
struct SeedItem {
    #[serde(rename = "_id")]
    id: i64,
    bucket: i32,
    owner: i32,
    score: i32,
    payload: Binary,
}

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    registered_profile: String,
    registry_digest: String,
    request_bytes: usize,
    response_bytes: usize,
    response_rows: u32,
    result_sha256: String,
    complete_result_match: bool,
    changed_registry_refused: bool,
    legacy_identity_refused: bool,
    unknown_handle_refused: bool,
    changed_shape_refused: bool,
    excessive_limits_refused: bool,
    changed_frame_refused: bool,
    replay_refused: bool,
    receipt_verified: bool,
    find_commands: usize,
    get_more_commands: usize,
    passed: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, uri, database, sentinel] if command == "prepare-ephemeral" => {
            prepare(uri, database, sentinel)
        }
        [command, uri, database] if command == "run" => execute(uri, database),
        _ => Err("use prepare-ephemeral or run with the required arguments".to_string()),
    }
}

fn prepare(uri: &str, database: &str, sentinel: &str) -> Result<(), String> {
    validate_database(database)?;
    if sentinel != PREPARE_SENTINEL {
        return Err("the destructive sentinel is invalid".to_string());
    }
    let client = Client::with_uri_str(uri).map_err(|_| "the MongoDB connection failed")?;
    let database = client.database(database);
    database
        .drop()
        .run()
        .map_err(|_| "the ephemeral database drop failed")?;
    let collection = database.collection::<SeedItem>("items");
    let items = (0..FIXTURE_ROWS)
        .map(|id| SeedItem {
            id,
            bucket: (id % 1_024) as i32,
            owner: (id % 4_096) as i32,
            score: (id % 10_000) as i32,
            payload: Binary {
                subtype: BinarySubtype::Generic,
                bytes: vec![(id % 251) as u8; 64],
            },
        })
        .collect::<Vec<_>>();
    collection
        .insert_many(items)
        .ordered(true)
        .run()
        .map_err(|_| "the fixture insertion failed")?;
    let count = collection
        .estimated_document_count()
        .run()
        .map_err(|_| "the fixture count failed")?;
    if count != FIXTURE_ROWS as u64 {
        return Err("the fixture count is invalid".to_string());
    }
    Ok(())
}

fn execute(uri: &str, database: &str) -> Result<(), String> {
    validate_database(database)?;
    let profile = profile(database)?;
    let registry = registry(&profile)?;
    let changed_registry_refused = changed_registry_refused(uri, database, &profile)?;
    let legacy_identity_refused = legacy_identity_refused(uri, &profile, &registry)?;

    let find_commands = Arc::new(AtomicUsize::new(0));
    let get_more_commands = Arc::new(AtomicUsize::new(0));
    let find_counter = Arc::clone(&find_commands);
    let get_more_counter = Arc::clone(&get_more_commands);
    let handler = EventHandler::callback(move |event| {
        if let CommandEvent::Started(event) = event {
            match event.command_name.as_str() {
                "find" => {
                    find_counter.fetch_add(1, Ordering::Relaxed);
                }
                "getMore" => {
                    get_more_counter.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    });
    let mut options = ClientOptions::parse(uri)
        .run()
        .map_err(|_| "the MongoDB options failed")?;
    options.command_event_handler = Some(handler);
    let client = Client::with_options(options).map_err(|_| "the MongoDB client failed")?;
    let backend = IdWindowBackend::from_client_registered(client, profile.clone(), &registry)
        .map_err(|error| error.to_string())?;
    let mut backend =
        RegisteredBackend::new(&registry, backend).map_err(|error| error.to_string())?;

    let authority = authority(registry.identity())?;
    let operation = profile
        .operation(10, MAX_BATCH_ITEMS as u32, 1)
        .map_err(|error| error.to_string())?;
    let plan = registry
        .plan(operation.plan_handle)
        .ok_or_else(|| "the registered plan is absent".to_string())?;
    let excessive_result_bytes = plan
        .maximum_result_bytes()
        .checked_add(1)
        .ok_or_else(|| "the result limit overflowed".to_string())?;
    let excessive_rows = plan
        .maximum_rows()
        .checked_add(1)
        .ok_or_else(|| "the row limit overflowed".to_string())?;
    let server = ServerSession::new(authority.clone(), excessive_result_bytes, excessive_rows)
        .map_err(|error| error.to_string())?;

    let unknown = Operation::new(
        operation.opcode,
        operation.plan_handle + 1,
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
        plan.maximum_result_bytes(),
        plan.maximum_rows(),
        ProtocolError::PlanNotRegistered,
    )?;
    let changed_shape = Operation::new(
        operation.opcode,
        operation.plan_handle,
        operation.result_shape + 1,
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
        plan.maximum_result_bytes(),
        plan.maximum_rows(),
        ProtocolError::PlanShapeMismatch,
    )?;
    let excessive_limits_refused = refusal(
        &server,
        &authority,
        &mut backend,
        operation,
        excessive_result_bytes,
        excessive_rows,
        ProtocolError::PlanLimitExceeded,
    )?;

    let mut changed_client = ClientSession::new(authority.clone());
    let mut changed_frame = changed_client
        .encode(
            operation,
            plan.maximum_result_bytes(),
            plan.maximum_rows(),
            deadline()?,
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
            plan.maximum_result_bytes(),
            plan.maximum_rows(),
            deadline()?,
        )
        .map_err(|error| error.to_string())?;
    let mut replay = MemoryReplayStore::default();
    let result = server
        .execute(&frame, &mut backend, &mut replay, &SystemClock)
        .map_err(|error| error.to_string())?;
    let receipt_verified = client
        .verify_execution_receipt(&frame, result.rows, &result.bytes, &result.receipt)
        .is_ok();
    let replay_refused = matches!(
        server.execute(&frame, &mut backend, &mut replay, &SystemClock),
        Err(ProtocolError::Replay)
    );

    let expected = expected_rows();
    let complete_result_match = result.bytes == expected;
    let find_commands = find_commands.load(Ordering::Relaxed);
    let get_more_commands = get_more_commands.load(Ordering::Relaxed);
    let passed = complete_result_match
        && result.rows == MAX_BATCH_ITEMS as u32
        && changed_registry_refused
        && legacy_identity_refused
        && unknown_handle_refused
        && changed_shape_refused
        && excessive_limits_refused
        && changed_frame_refused
        && replay_refused
        && receipt_verified
        && find_commands == 1
        && get_more_commands == 0;
    let report = Report {
        campaign: "NDABI registered MongoDB profile v0.1",
        registered_profile: format!("0x{MONGODB_ID_WINDOW_REGISTRY_PROFILE_ID:08x}"),
        registry_digest: hex(&registry.digest()),
        request_bytes: FRAME_BYTES,
        response_bytes: result.bytes.len(),
        response_rows: result.rows,
        result_sha256: hex(&Sha256::digest(&result.bytes)),
        complete_result_match,
        changed_registry_refused,
        legacy_identity_refused,
        unknown_handle_refused,
        changed_shape_refused,
        excessive_limits_refused,
        changed_frame_refused,
        replay_refused,
        receipt_verified,
        find_commands,
        get_more_commands,
        passed,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
    );
    if passed {
        Ok(())
    } else {
        Err("the registered MongoDB proof failed".to_string())
    }
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

fn profile(database: &str) -> Result<IdWindowProfile, String> {
    IdWindowProfile::new(
        database,
        "items",
        OperationBinding::new(PLAN_HANDLE, RESULT_SHAPE).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn registry(profile: &IdWindowProfile) -> Result<PlanRegistry, String> {
    profile
        .plan_registry(schema_digest(), policy_digest())
        .map_err(|error| error.to_string())
}

fn schema_digest() -> [u8; 32] {
    digest_label(
        b"ndabi/registry-mongodb/schema/v1",
        b"items(_id:i64,bucket:i32,owner:i32,score:i32,payload:bytes64)",
    )
}

fn policy_digest() -> [u8; 32] {
    digest_label(
        b"ndabi/registry-mongodb/policy/v1",
        b"reader:find-only;collection:items;writes:refuse",
    )
}

fn authority(identity: ndabi_protocol::BackendIdentity) -> Result<Authority, String> {
    let context = AuthorityContext::new(
        *b"registry-mongo01",
        *b"mongodb-reader01",
        1,
        digest_label(
            b"ndabi/registry-mongodb/capability/v1",
            b"registered-id-window-read",
        ),
        identity,
    )
    .map_err(|error| error.to_string())?;
    let expires = unix_us()?
        .checked_add(30_000_000)
        .ok_or_else(|| "the authority expiry overflowed".to_string())?;
    Authority::new_read([91; 32], 1, 9_101, expires, context).map_err(|error| error.to_string())
}

fn changed_registry_refused(
    uri: &str,
    database: &str,
    profile: &IdWindowProfile,
) -> Result<bool, String> {
    let changed = IdWindowProfile::new(
        database,
        "items",
        OperationBinding::new(PLAN_HANDLE + 1, RESULT_SHAPE).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let changed_registry = registry(&changed)?;
    let client = Client::with_uri_str(uri).map_err(|_| "the changed MongoDB client failed")?;
    Ok(matches!(
        IdWindowBackend::from_client_registered(client, profile.clone(), &changed_registry),
        Err(ProtocolError::PlanRegistryMismatch)
    ))
}

fn legacy_identity_refused(
    uri: &str,
    profile: &IdWindowProfile,
    registry: &PlanRegistry,
) -> Result<bool, String> {
    let client = Client::with_uri_str(uri).map_err(|_| "the legacy MongoDB client failed")?;
    let backend =
        IdWindowBackend::from_client(client, profile.clone(), schema_digest(), policy_digest())
            .map_err(|error| error.to_string())?;
    Ok(matches!(
        RegisteredBackend::new(registry, backend),
        Err(ProtocolError::PlanRegistryMismatch)
    ))
}

fn expected_rows() -> Vec<u8> {
    let mut output = Vec::with_capacity(MAX_BATCH_ITEMS * ROW_BYTES);
    for id in 10..10 + MAX_BATCH_ITEMS as i64 {
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&((id % 1_024) as i32).to_le_bytes());
        output.extend_from_slice(&((id % 4_096) as i32).to_le_bytes());
        output.extend_from_slice(&((id % 10_000) as i32).to_le_bytes());
        output.extend_from_slice(&[(id % 251) as u8; 64]);
    }
    output
}

fn validate_database(database: &str) -> Result<(), String> {
    if !database.starts_with("ndabi_registry_mongo_")
        || database.len() > 63
        || !database
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("the campaign database name is invalid".to_string());
    }
    Ok(())
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
    u64::try_from(micros).map_err(|_| "the system clock exceeded the protocol range".to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("a string write cannot fail");
    }
    output
}
