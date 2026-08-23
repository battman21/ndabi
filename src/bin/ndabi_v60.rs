use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mongodb::bson::{spec::BinarySubtype, Binary};
use mongodb::event::{command::CommandEvent, EventHandler};
use mongodb::options::ClientOptions;
use mongodb::sync::Client;
use ndabi_mongodb_v1::{
    IdWindowBackend, IdWindowProfile, OperationBinding, MAX_BATCH_ITEMS, ROW_BYTES,
};
use ndabi_protocol::{
    digest_label, Authority, AuthorityContext, ClientSession, MemoryReplayStore, ServerSession,
    SystemClock, FRAME_BYTES,
};
use serde::Serialize;

const PREPARE_SENTINEL: &str = "I_UNDERSTAND_THIS_DROPS_THE_EPHEMERAL_DATABASE";
const FIXTURE_ROWS: i64 = 256;

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
    frame_bytes: usize,
    response_bytes: usize,
    response_rows: u32,
    complete_result_match: bool,
    receipt_nonzero: bool,
    authority_context_bound: bool,
    find_commands: usize,
    get_more_commands: usize,
    refusals_passed: u32,
    refusals_total: u32,
    passed: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| "a command is required".to_string())?;
    let uri = arguments
        .next()
        .ok_or_else(|| "a MongoDB connection is required".to_string())?;
    let database = arguments
        .next()
        .ok_or_else(|| "a campaign database is required".to_string())?;
    match command.as_str() {
        "prepare-ephemeral" => {
            let sentinel = arguments
                .next()
                .ok_or_else(|| "the destructive sentinel is required".to_string())?;
            if arguments.next().is_some() {
                return Err("too many arguments".to_string());
            }
            prepare(&uri, &database, &sentinel)
        }
        "run" => {
            if arguments.next().is_some() {
                return Err("too many arguments".to_string());
            }
            execute(&uri, &database)
        }
        _ => Err("the command is unknown".to_string()),
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
    let profile = IdWindowProfile::new(
        database,
        "items",
        OperationBinding::new(60, 600).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let schema_digest = digest_label(
        b"ndabi/mongodb/schema/v1",
        b"items(_id:i64,bucket:i32,owner:i32,score:i32,payload:bytes64)",
    );
    let policy_digest = digest_label(
        b"ndabi/mongodb/policy/v1",
        b"reader:find-only;collection:items;writes:refuse",
    );
    let identity = profile
        .identity(schema_digest, policy_digest)
        .map_err(|error| error.to_string())?;
    let context = AuthorityContext::new(
        *b"mongodb-tenant01",
        *b"mongodb-reader01",
        1,
        digest_label(b"ndabi/mongodb/capability/v1", b"read:id-window"),
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
    let authority = Authority::new_read([60; 32], 1, 60, expires, context)
        .map_err(|error| error.to_string())?;
    let operation = profile
        .operation(10, MAX_BATCH_ITEMS as u32, 1)
        .map_err(|error| error.to_string())?;
    let result_budget =
        u32::try_from(MAX_BATCH_ITEMS * ROW_BYTES).map_err(|_| "the result budget overflowed")?;
    let mut encoder = ClientSession::new(authority.clone());
    let frame = encoder
        .encode(operation, result_budget, MAX_BATCH_ITEMS as u32, deadline)
        .map_err(|error| error.to_string())?;
    let server = ServerSession::new(authority.clone(), result_budget, MAX_BATCH_ITEMS as u32)
        .map_err(|error| error.to_string())?;
    let mut backend =
        IdWindowBackend::from_client(client, profile.clone(), schema_digest, policy_digest)
            .map_err(|error| error.to_string())?;
    let mut replay = MemoryReplayStore::default();
    let result = server
        .execute(&frame, &mut backend, &mut replay, &SystemClock)
        .map_err(|error| error.to_string())?;
    let complete_result_match = result.bytes == expected_rows();
    let receipt_nonzero = result.receipt.iter().any(|byte| *byte != 0);
    let authority_context_bound = frame[96..128] == context_digest;

    let mut refusals_passed = 0;
    refusals_passed += u32::from(
        server
            .execute(&frame, &mut backend, &mut replay, &SystemClock)
            .is_err(),
    );
    let mut changed = frame;
    changed[64] ^= 1;
    refusals_passed += u32::from(
        server
            .execute(
                &changed,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &SystemClock,
            )
            .is_err(),
    );
    let budget_frame = ClientSession::new(authority.clone())
        .encode(
            operation,
            result_budget - 1,
            MAX_BATCH_ITEMS as u32,
            deadline,
        )
        .map_err(|error| error.to_string())?;
    refusals_passed += u32::from(
        server
            .execute(
                &budget_frame,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &SystemClock,
            )
            .is_err(),
    );
    let find_commands = find_commands.load(Ordering::Relaxed);
    let get_more_commands = get_more_commands.load(Ordering::Relaxed);
    let passed = complete_result_match
        && result.rows == MAX_BATCH_ITEMS as u32
        && receipt_nonzero
        && authority_context_bound
        && find_commands == 1
        && get_more_commands == 0
        && refusals_passed == 3
        && backend.executions() == 1;
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            campaign: "NDABI canonical MongoDB binding v6.0",
            frame_bytes: FRAME_BYTES,
            response_bytes: result.bytes.len(),
            response_rows: result.rows,
            complete_result_match,
            receipt_nonzero,
            authority_context_bound,
            find_commands,
            get_more_commands,
            refusals_passed,
            refusals_total: 3,
            passed,
        })
        .map_err(|_| "the report encoding failed")?
    );
    if passed {
        Ok(())
    } else {
        Err("the canonical MongoDB binding failed".to_string())
    }
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
    if !database.starts_with("ndabi_v60_")
        || database.len() > 63
        || !database
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("the campaign database name is invalid".to_string());
    }
    Ok(())
}

fn unix_us() -> Result<u64, String> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock failed")?
        .as_micros();
    u64::try_from(micros).map_err(|_| "the system clock exceeded the protocol range".to_string())
}
