//! Compare a persistent NDABI gateway with human-facing and native PostgreSQL surfaces.
//!
//! The gateway keeps authority, replay state, a database connection, and a prepared plan alive.
//! The benchmark keeps each competing connection alive and compares exact canonical results.

use std::array;
use std::hint::black_box;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ndabi_showdown::alloc::{begin_measurement, end_measurement, AllocationDelta};
use postgres::{Client, NoTls, Row, Statement};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const ROWS: i64 = 100_000;
const BATCH_SIZES: [usize; 2] = [32, 128];
const LATENCY_WARMUP: usize = 5;
const LATENCY_SAMPLES: usize = 63;
const CONCURRENCY_LEVELS: [usize; 4] = [1, 8, 32, 128];
const CONCURRENCY_WARMUP: usize = 3;
const CONCURRENCY_BLOCKS: usize = 7;
const REQUESTS_PER_BLOCK: usize = 3;
const SESSION_BASE: u32 = 0x4000_0000;
const CAPABILITY_HANDLE: u32 = 0x4000_1001;
const SCHEMA_HANDLE: u32 = 0x4000_2001;
const PLAN_HANDLE: u32 = 0x4000_3001;
const RESULT_SHAPE: u32 = 0x4000_4001;
const MAX_RESULT_BYTES: u32 = 1024 * 1024;
const ROOT_KEY: [u8; 32] = [0x40; 32];
const RECEIPT_AUTHORITY: [u8; 32] = [0x74; 32];
const HELLO_MAGIC: [u8; 4] = *b"NDH1";
const HELLO_BYTES: usize = 40;
const EXECUTE_MAGIC: [u8; 4] = *b"NDE1";
const EXECUTE_BYTES: usize = 56;
const EXECUTE_TAG_OFFSET: usize = 40;
const EXECUTE_TAG_BYTES: usize = 16;
const OPERATION_READ: u16 = 1 << 0;
const OPERATION_IDEMPOTENT: u16 = 1 << 2;
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const SET_SQL: &str = "SELECT item.id, item.bucket, item.payload \
    FROM unnest($1::bigint[]) WITH ORDINALITY AS request(id, ordinal) \
    JOIN ndabi_v41_items AS item ON item.id = request.id \
    ORDER BY request.ordinal";
const SINGLE_SQL: &str = "SELECT id, bucket, payload FROM ndabi_v41_items WHERE id = $1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Arm {
    Postgrest,
    SimpleSequential,
    PreparedSequential,
    NativeSet,
    EmbeddedNdabi,
    NdabiGateway,
}

impl Arm {
    const ALL: [Self; 6] = [
        Self::Postgrest,
        Self::SimpleSequential,
        Self::PreparedSequential,
        Self::NativeSet,
        Self::EmbeddedNdabi,
        Self::NdabiGateway,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::Postgrest => "postgrest-json",
            Self::SimpleSequential => "simple-sql-sequential",
            Self::PreparedSequential => "prepared-sql-sequential",
            Self::NativeSet => "native-prepared-set",
            Self::EmbeddedNdabi => "ndabi-embedded",
            Self::NdabiGateway => "ndabi-gateway",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Postgrest => 0,
            Self::SimpleSequential => 1,
            Self::PreparedSequential => 2,
            Self::NativeSet => 3,
            Self::EmbeddedNdabi => 4,
            Self::NdabiGateway => 5,
        }
    }
}

#[derive(Clone, Debug)]
struct Outcome {
    bytes: Vec<u8>,
    receipt: [u8; 32],
    request_bytes: Option<usize>,
    response_bytes: Option<usize>,
    adapter_cpu_ns: Option<u64>,
    adapter_allocation: Option<AllocationDelta>,
}

struct DatabaseState {
    client: Client,
    single: Statement,
    set: Statement,
}

impl DatabaseState {
    fn connect(connection: &str) -> Result<Self, String> {
        let mut client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
        let count: i64 = client
            .query_one("SELECT COUNT(*) FROM ndabi_v41_items", &[])
            .map_err(|error| format!("prepare the v4.1 dataset before measurement: {error}"))?
            .get(0);
        if count != ROWS {
            return Err(format!(
                "the v4.1 dataset has {count} rows instead of {ROWS}"
            ));
        }
        let single = client
            .prepare(SINGLE_SQL)
            .map_err(|error| error.to_string())?;
        let set = client.prepare(SET_SQL).map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            single,
            set,
        })
    }

    fn simple_sequential(&mut self, ids: &[i64]) -> Result<Outcome, String> {
        let mut bytes = Vec::with_capacity(ids.len() * 76);
        for id in ids {
            let rows = self
                .client
                .query(SINGLE_SQL, &[id])
                .map_err(|error| error.to_string())?;
            append_rows(&mut bytes, &rows)?;
        }
        Ok(local_outcome(bytes))
    }

    fn prepared_sequential(&mut self, ids: &[i64]) -> Result<Outcome, String> {
        let mut bytes = Vec::with_capacity(ids.len() * 76);
        for id in ids {
            let rows = self
                .client
                .query(&self.single, &[id])
                .map_err(|error| error.to_string())?;
            append_rows(&mut bytes, &rows)?;
        }
        Ok(local_outcome(bytes))
    }

    fn set(&mut self, ids: &[i64]) -> Result<Outcome, String> {
        let rows = self
            .client
            .query(&self.set, &[&ids])
            .map_err(|error| error.to_string())?;
        let mut bytes = Vec::with_capacity(ids.len() * 76);
        append_rows(&mut bytes, &rows)?;
        Ok(local_outcome(bytes))
    }
}

pub fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments
        .next()
        .ok_or_else(|| "supply prepare, gateway, or client".to_string())?;
    match mode.as_str() {
        "prepare" => {
            let connection = required_argument(&mut arguments, "PostgreSQL connection")?;
            require_no_arguments(arguments)?;
            prepare_database(&connection)
        }
        "gateway" => {
            let listen = required_argument(&mut arguments, "gateway listen address")?;
            let connection = required_argument(&mut arguments, "PostgreSQL connection")?;
            require_no_arguments(arguments)?;
            run_gateway(&listen, &connection)
        }
        "client" => {
            let connection = required_argument(&mut arguments, "PostgreSQL connection")?;
            let gateway = required_argument(&mut arguments, "gateway address")?;
            let postgrest = required_argument(&mut arguments, "PostgREST address")?;
            require_no_arguments(arguments)?;
            run_client(&connection, &gateway, &postgrest)
        }
        _ => Err("use ndabi_v41 prepare|gateway|client with the required addresses".into()),
    }
}

fn required_argument(
    arguments: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, String> {
    arguments.next().ok_or_else(|| format!("supply the {name}"))
}

fn require_no_arguments(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    if arguments.next().is_some() {
        Err("too many v4.1 arguments".into())
    } else {
        Ok(())
    }
}

fn prepare_database(connection: &str) -> Result<(), String> {
    let mut client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS ndabi_v41_items (\
             id BIGINT PRIMARY KEY, bucket INTEGER NOT NULL, payload BYTEA NOT NULL);\
             TRUNCATE ndabi_v41_items;\
             INSERT INTO ndabi_v41_items \
             SELECT value, (value % 1024)::INTEGER, \
             decode(repeat(lpad(to_hex(value % 256), 2, '0'), 64), 'hex') \
             FROM generate_series(0, 99999) AS value;\
             ANALYZE ndabi_v41_items;\
             DO $$ BEGIN \
               IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ndabi_anon') THEN \
                 CREATE ROLE ndabi_anon NOLOGIN; \
               END IF; \
             END $$;\
             REVOKE ALL ON ndabi_v41_items FROM PUBLIC;\
             GRANT USAGE ON SCHEMA public TO ndabi_anon;\
             GRANT SELECT ON ndabi_v41_items TO ndabi_anon;\
             CHECKPOINT;",
        )
        .map_err(|error| error.to_string())?;
    println!("{{\"schema\":\"ndabi-postgresql-embedded-v4.1-prepare\",\"rows\":{ROWS}}}");
    Ok(())
}

fn run_gateway(listen: &str, connection: &str) -> Result<(), String> {
    let listener = TcpListener::bind(listen).map_err(|error| error.to_string())?;
    let generation = campaign_generation()?;
    let sessions = Arc::new(AtomicU32::new(SESSION_BASE));
    let connection = Arc::new(connection.to_string());
    println!("{{\"schema\":\"ndabi-gateway-v4.1-ready\"}}");
    io::stdout().flush().map_err(|error| error.to_string())?;
    for accepted in listener.incoming() {
        let stream = accepted.map_err(|error| error.to_string())?;
        let session_handle = sessions.fetch_add(1, Ordering::Relaxed);
        if session_handle == 0 || session_handle == u32::MAX {
            return Err("the gateway session handle space ended".into());
        }
        let connection = Arc::clone(&connection);
        thread::spawn(move || {
            if let Err(error) =
                handle_gateway_connection(stream, &connection, generation, session_handle)
            {
                eprintln!("gateway connection refused: {error}");
            }
        });
    }
    Ok(())
}

fn handle_gateway_connection(
    mut stream: TcpStream,
    connection: &str,
    generation: u64,
    session_handle: u32,
) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|error| error.to_string())?;
    let expires_unix_us = now_unix_us()?.saturating_add(900_000_000);
    let binding = CompactBinding::new(generation, session_handle, expires_unix_us);
    let mut verifier = CompactVerifier::new(binding);
    let mut database = DatabaseState::connect(connection)?;
    write_hello(&mut stream, generation, session_handle, expires_unix_us)?;
    let mut decoded_ids = Vec::with_capacity(128);
    while let Some(frame) = read_message(&mut stream)? {
        let cpu_start = thread_cpu_ns()?;
        let allocation_start = begin_measurement();
        let result = (|| {
            let pending = verifier.verify_pending_at(&frame, now_unix_us()?)?;
            pending.ids(&mut decoded_ids)?;
            let outcome = database.set(&decoded_ids)?;
            if outcome.bytes.len() > pending.result_budget as usize {
                return Err("the gateway result exceeded the authenticated budget".into());
            }
            verifier.commit_pending(pending)?;
            Ok::<Outcome, String>(outcome)
        })();
        let allocation = end_measurement(allocation_start);
        let server_cpu_ns = thread_cpu_ns()?.saturating_sub(cpu_start);
        match result {
            Ok(outcome) => write_gateway_success(&mut stream, outcome, server_cpu_ns, allocation)?,
            Err(_) => write_gateway_rejection(&mut stream)?,
        }
    }
    Ok(())
}

fn write_hello(
    stream: &mut TcpStream,
    generation: u64,
    session_handle: u32,
    expires_unix_us: u64,
) -> Result<(), String> {
    let mut hello = [0u8; HELLO_BYTES];
    hello[0..4].copy_from_slice(&HELLO_MAGIC);
    hello[4..12].copy_from_slice(&generation.to_le_bytes());
    hello[12..16].copy_from_slice(&session_handle.to_le_bytes());
    hello[16..24].copy_from_slice(&expires_unix_us.to_le_bytes());
    hello[24..28].copy_from_slice(&MAX_RESULT_BYTES.to_le_bytes());
    hello[28..32].copy_from_slice(&CAPABILITY_HANDLE.to_le_bytes());
    hello[32..36].copy_from_slice(&SCHEMA_HANDLE.to_le_bytes());
    stream.write_all(&hello).map_err(|error| error.to_string())
}

fn write_gateway_success(
    stream: &mut TcpStream,
    outcome: Outcome,
    server_cpu_ns: u64,
    allocation: AllocationDelta,
) -> Result<(), String> {
    let payload_len = u32::try_from(outcome.bytes.len()).map_err(|error| error.to_string())?;
    let mut response = Vec::with_capacity(outcome.bytes.len() + 69);
    response.push(0);
    response.extend_from_slice(&payload_len.to_le_bytes());
    response.extend_from_slice(&outcome.bytes);
    response.extend_from_slice(&outcome.receipt);
    response.extend_from_slice(&server_cpu_ns.to_le_bytes());
    response.extend_from_slice(&allocation.allocations.to_le_bytes());
    response.extend_from_slice(&allocation.allocated_bytes.to_le_bytes());
    response.extend_from_slice(&allocation.peak_additional_live_bytes.to_le_bytes());
    write_message(stream, &response)
}

fn write_gateway_rejection(stream: &mut TcpStream) -> Result<(), String> {
    write_message(stream, &[1])
}

fn read_message(stream: &mut TcpStream) -> Result<Option<Vec<u8>>, String> {
    let mut first = [0u8; 1];
    match stream.read(&mut first) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("one-byte read returned too many bytes"),
        Err(error) => return Err(error.to_string()),
    }
    let mut rest = [0u8; 3];
    stream
        .read_exact(&mut rest)
        .map_err(|error| error.to_string())?;
    let length = u32::from_le_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err("the gateway message length is invalid".into());
    }
    let mut bytes = vec![0u8; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(Some(bytes))
}

fn write_message(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    let length = u32::try_from(bytes.len()).map_err(|error| error.to_string())?;
    stream
        .write_all(&length.to_le_bytes())
        .and_then(|_| stream.write_all(bytes))
        .map_err(|error| error.to_string())
}

fn append_rows(output: &mut Vec<u8>, rows: &[Row]) -> Result<(), String> {
    for row in rows {
        let id: i64 = row.get(0);
        let bucket: i32 = row.get(1);
        let payload: Vec<u8> = row.get(2);
        if payload.len() != 64 {
            return Err("the PostgreSQL payload length changed".into());
        }
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&bucket.to_le_bytes());
        output.extend_from_slice(&payload);
    }
    Ok(())
}

fn local_outcome(bytes: Vec<u8>) -> Outcome {
    let receipt = receipt(&bytes);
    Outcome {
        bytes,
        receipt,
        request_bytes: None,
        response_bytes: None,
        adapter_cpu_ns: None,
        adapter_allocation: None,
    }
}

fn receipt(bytes: &[u8]) -> [u8; 32] {
    let mut receipt = Sha256::new();
    receipt.update(b"ndabi/postgresql/gateway-receipt/v1");
    receipt.update(RECEIPT_AUTHORITY);
    receipt.update(Sha256::digest(bytes));
    receipt.finalize().into()
}

#[derive(Clone, Copy)]
struct CompactBinding {
    generation: u64,
    session_handle: u32,
    expires_unix_us: u64,
    key: [u8; 32],
}

impl CompactBinding {
    fn new(generation: u64, session_handle: u32, expires_unix_us: u64) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(&ROOT_KEY);
        hasher.update(b"ndabi/postgresql/gateway-execute/v1");
        hasher.update(&generation.to_le_bytes());
        hasher.update(&session_handle.to_le_bytes());
        hasher.update(&expires_unix_us.to_le_bytes());
        hasher.update(&CAPABILITY_HANDLE.to_le_bytes());
        hasher.update(&SCHEMA_HANDLE.to_le_bytes());
        hasher.update(&PLAN_HANDLE.to_le_bytes());
        hasher.update(&RESULT_SHAPE.to_le_bytes());
        Self {
            generation,
            session_handle,
            expires_unix_us,
            key: *hasher.finalize().as_bytes(),
        }
    }

    fn tag(self, authenticated: &[u8]) -> [u8; EXECUTE_TAG_BYTES] {
        let digest = blake3::keyed_hash(&self.key, authenticated);
        let mut tag = [0u8; EXECUTE_TAG_BYTES];
        tag.copy_from_slice(&digest.as_bytes()[..EXECUTE_TAG_BYTES]);
        tag
    }
}

#[derive(Clone, Copy)]
struct CompactPending {
    nonce: u64,
    start: i64,
    count: u16,
    result_budget: u32,
}

impl CompactPending {
    fn ids(self, output: &mut Vec<i64>) -> Result<(), String> {
        output.clear();
        output.reserve(self.count as usize);
        for offset in 0..i64::from(self.count) {
            output.push(
                self.start
                    .checked_add(offset)
                    .ok_or_else(|| "the compact identifier range overflowed".to_string())?,
            );
        }
        Ok(())
    }
}

struct CompactVerifier {
    binding: CompactBinding,
    next_nonce: u64,
}

impl CompactVerifier {
    fn new(binding: CompactBinding) -> Self {
        Self {
            binding,
            next_nonce: 1,
        }
    }

    fn verify_pending_at(&self, frame: &[u8], now_unix_us: u64) -> Result<CompactPending, String> {
        if frame.len() != EXECUTE_BYTES {
            return Err("the gateway refused the compact frame length".into());
        }
        let expected_tag = self.binding.tag(&frame[..EXECUTE_TAG_OFFSET]);
        if expected_tag.ct_eq(&frame[EXECUTE_TAG_OFFSET..]).unwrap_u8() != 1 {
            return Err("the gateway refused the compact authenticator".into());
        }
        if frame[..4] != EXECUTE_MAGIC
            || get_u32(frame, 4) != self.binding.session_handle
            || get_u64(frame, 8) != self.binding.generation
            || now_unix_us > self.binding.expires_unix_us
        {
            return Err("the gateway refused the compact authority".into());
        }
        let nonce = get_u64(frame, 16);
        let start = i64::from_le_bytes(
            frame[24..32]
                .try_into()
                .expect("the compact start field is bounded"),
        );
        let count = u16::from_le_bytes(
            frame[32..34]
                .try_into()
                .expect("the compact count field is bounded"),
        );
        let operation_flags = u16::from_le_bytes(
            frame[34..36]
                .try_into()
                .expect("the compact operation field is bounded"),
        );
        let result_budget = get_u32(frame, 36);
        let expected_budget = u32::from(count)
            .checked_mul(76)
            .ok_or_else(|| "the compact result budget overflowed".to_string())?;
        if nonce != self.next_nonce
            || count == 0
            || usize::from(count) > *BATCH_SIZES.iter().max().expect("batch sizes exist")
            || operation_flags != OPERATION_READ | OPERATION_IDEMPOTENT
            || result_budget != expected_budget
        {
            return Err("the gateway refused the compact execution contract".into());
        }
        Ok(CompactPending {
            nonce,
            start,
            count,
            result_budget,
        })
    }

    fn commit_pending(&mut self, pending: CompactPending) -> Result<(), String> {
        if pending.nonce != self.next_nonce {
            return Err("the gateway refused a stale compact execution".into());
        }
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or_else(|| "the compact nonce space ended".to_string())?;
        Ok(())
    }
}

fn encode_compact(
    binding: CompactBinding,
    generation: u64,
    session_handle: u32,
    ids: &[i64],
    nonce: u64,
) -> Result<[u8; EXECUTE_BYTES], String> {
    let first = *ids
        .first()
        .ok_or_else(|| "the compact request has no identifiers".to_string())?;
    for (offset, identifier) in ids.iter().enumerate() {
        let expected = first
            .checked_add(i64::try_from(offset).map_err(|error| error.to_string())?)
            .ok_or_else(|| "the compact identifier range overflowed".to_string())?;
        if *identifier != expected {
            return Err("the compact profile requires an ordered identifier range".into());
        }
    }
    let count = u16::try_from(ids.len()).map_err(|error| error.to_string())?;
    let result_budget = u32::from(count)
        .checked_mul(76)
        .ok_or_else(|| "the compact result budget overflowed".to_string())?;
    let mut frame = [0u8; EXECUTE_BYTES];
    frame[..4].copy_from_slice(&EXECUTE_MAGIC);
    frame[4..8].copy_from_slice(&session_handle.to_le_bytes());
    frame[8..16].copy_from_slice(&generation.to_le_bytes());
    frame[16..24].copy_from_slice(&nonce.to_le_bytes());
    frame[24..32].copy_from_slice(&first.to_le_bytes());
    frame[32..34].copy_from_slice(&count.to_le_bytes());
    frame[34..36].copy_from_slice(&(OPERATION_READ | OPERATION_IDEMPOTENT).to_le_bytes());
    frame[36..40].copy_from_slice(&result_budget.to_le_bytes());
    let tag = binding.tag(&frame[..EXECUTE_TAG_OFFSET]);
    frame[EXECUTE_TAG_OFFSET..].copy_from_slice(&tag);
    Ok(frame)
}

struct EmbeddedAdapter {
    binding: CompactBinding,
    verifier: CompactVerifier,
    generation: u64,
    session_handle: u32,
    next_nonce: u64,
    decoded_ids: Vec<i64>,
}

impl EmbeddedAdapter {
    fn new(session_handle: u32) -> Result<Self, String> {
        let generation = campaign_generation()?;
        let expires_unix_us = now_unix_us()?.saturating_add(900_000_000);
        let binding = CompactBinding::new(generation, session_handle, expires_unix_us);
        Ok(Self {
            binding,
            verifier: CompactVerifier::new(binding),
            generation,
            session_handle,
            next_nonce: 1,
            decoded_ids: Vec::with_capacity(128),
        })
    }

    fn execute(
        &mut self,
        database: &mut DatabaseState,
        ids: &[i64],
        diagnostics: bool,
    ) -> Result<Outcome, String> {
        let cpu_start = diagnostics.then(thread_cpu_ns).transpose()?;
        let allocation_start = diagnostics.then(begin_measurement);
        let frame = encode_compact(
            self.binding,
            self.generation,
            self.session_handle,
            ids,
            self.next_nonce,
        )?;
        let pending = self.verifier.verify_pending_at(&frame, now_unix_us()?)?;
        pending.ids(&mut self.decoded_ids)?;
        let mut outcome = database.set(&self.decoded_ids)?;
        if outcome.bytes.len() > pending.result_budget as usize {
            return Err("the embedded result exceeded the authenticated budget".into());
        }
        self.verifier.commit_pending(pending)?;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or_else(|| "the embedded nonce space ended".to_string())?;
        outcome.request_bytes = Some(frame.len());
        outcome.response_bytes = Some(outcome.bytes.len() + outcome.receipt.len());
        outcome.adapter_allocation = allocation_start.map(end_measurement);
        outcome.adapter_cpu_ns = cpu_start
            .map(|started| thread_cpu_ns().map(|ended| ended.saturating_sub(started)))
            .transpose()?;
        Ok(outcome)
    }
}

struct GatewayConnection {
    stream: TcpStream,
    binding: CompactBinding,
    generation: u64,
    session_handle: u32,
    next_nonce: u64,
}

impl GatewayConnection {
    fn connect(address: &str) -> Result<Self, String> {
        let mut stream = TcpStream::connect(address).map_err(|error| error.to_string())?;
        stream
            .set_nodelay(true)
            .map_err(|error| error.to_string())?;
        let mut hello = [0u8; HELLO_BYTES];
        stream
            .read_exact(&mut hello)
            .map_err(|error| error.to_string())?;
        if hello[0..4] != HELLO_MAGIC || hello[36..40] != [0; 4] {
            return Err("the gateway hello is invalid".into());
        }
        let generation = get_u64(&hello, 4);
        let session_handle = get_u32(&hello, 12);
        let expires_unix_us = get_u64(&hello, 16);
        let max_result_bytes = get_u32(&hello, 24);
        if get_u32(&hello, 28) != CAPABILITY_HANDLE
            || get_u32(&hello, 32) != SCHEMA_HANDLE
            || max_result_bytes != MAX_RESULT_BYTES
        {
            return Err("the gateway authority contract changed".into());
        }
        let binding = CompactBinding::new(generation, session_handle, expires_unix_us);
        Ok(Self {
            stream,
            binding,
            generation,
            session_handle,
            next_nonce: 1,
        })
    }

    fn encode(&self, ids: &[i64], nonce: u64) -> Result<[u8; EXECUTE_BYTES], String> {
        encode_compact(
            self.binding,
            self.generation,
            self.session_handle,
            ids,
            nonce,
        )
    }

    fn request(&mut self, ids: &[i64]) -> Result<Outcome, String> {
        let frame = self.encode(ids, self.next_nonce)?;
        self.next_nonce = self.next_nonce.saturating_add(1);
        self.send_raw(&frame)?
            .ok_or_else(|| "the gateway refused a valid frame".to_string())
    }

    fn send_raw(&mut self, frame: &[u8]) -> Result<Option<Outcome>, String> {
        write_message(&mut self.stream, frame)?;
        let response = read_message(&mut self.stream)?
            .ok_or_else(|| "the gateway closed without a response".to_string())?;
        if response == [1] {
            return Ok(None);
        }
        if response.first() != Some(&0) || response.len() < 69 {
            return Err("the gateway response is invalid".into());
        }
        decode_gateway_response(&response, frame.len() + 4).map(Some)
    }
}

fn decode_gateway_response(response: &[u8], request_bytes: usize) -> Result<Outcome, String> {
    let payload_len = get_u32(response, 1) as usize;
    let expected_len = payload_len
        .checked_add(69)
        .ok_or_else(|| "the gateway response length overflowed".to_string())?;
    if response.len() != expected_len {
        return Err("the gateway response length changed".into());
    }
    let payload_end = 5 + payload_len;
    let bytes = response[5..payload_end].to_vec();
    let mut received_receipt = [0u8; 32];
    received_receipt.copy_from_slice(&response[payload_end..payload_end + 32]);
    let expected_receipt = receipt(&bytes);
    if received_receipt != expected_receipt {
        return Err("the gateway receipt changed".into());
    }
    let offset = payload_end + 32;
    let server_cpu_ns = get_u64(response, offset);
    let allocation = AllocationDelta {
        allocations: get_u64(response, offset + 8),
        allocated_bytes: get_u64(response, offset + 16),
        peak_additional_live_bytes: get_u64(response, offset + 24),
    };
    Ok(Outcome {
        bytes,
        receipt: received_receipt,
        request_bytes: Some(request_bytes),
        response_bytes: Some(response.len() + 4),
        adapter_cpu_ns: Some(server_cpu_ns),
        adapter_allocation: Some(allocation),
    })
}

#[derive(Deserialize)]
struct PostgrestRow {
    id: i64,
    bucket: i32,
    payload: String,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
    wire_bytes: usize,
}

struct HttpConnection {
    stream: TcpStream,
    address: String,
    buffered: Vec<u8>,
}

impl HttpConnection {
    fn connect(address: &str) -> Result<Self, String> {
        let stream = TcpStream::connect(address).map_err(|error| error.to_string())?;
        stream
            .set_nodelay(true)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            stream,
            address: address.to_string(),
            buffered: Vec::with_capacity(16 * 1024),
        })
    }

    fn query(&mut self, ids: &[i64]) -> Result<Outcome, String> {
        let identifiers = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
        let path =
            format!("/ndabi_v41_items?id=in.({identifiers})&select=id,bucket,payload&order=id.asc");
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n",
            self.address
        );
        let request_bytes = request.len();
        let response = self.exchange(request.as_bytes())?;
        if response.status != 200 {
            return Err(format!("PostgREST returned status {}", response.status));
        }
        let rows: Vec<PostgrestRow> =
            serde_json::from_slice(&response.body).map_err(|error| error.to_string())?;
        let mut bytes = Vec::with_capacity(ids.len() * 76);
        for row in rows {
            bytes.extend_from_slice(&row.id.to_le_bytes());
            bytes.extend_from_slice(&row.bucket.to_le_bytes());
            decode_bytea_hex(&row.payload, &mut bytes)?;
        }
        if bytes.len() != ids.len() * 76 {
            return Err("PostgREST returned the wrong result length".into());
        }
        let receipt = receipt(&bytes);
        Ok(Outcome {
            bytes,
            receipt,
            request_bytes: Some(request_bytes),
            response_bytes: Some(response.wire_bytes),
            adapter_cpu_ns: None,
            adapter_allocation: None,
        })
    }

    fn prove_write_refusal(&mut self) -> Result<bool, String> {
        let body = b"{\"id\":100001,\"bucket\":1,\"payload\":\"\\\\x00\"}";
        let request = format!(
            "POST /ndabi_v41_items HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            self.address,
            body.len()
        );
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(body);
        Ok(self.exchange(&bytes)?.status >= 400)
    }

    fn exchange(&mut self, request: &[u8]) -> Result<HttpResponse, String> {
        self.stream
            .write_all(request)
            .map_err(|error| error.to_string())?;
        let header_end = self.read_until(b"\r\n\r\n")?;
        let header_bytes = self.buffered[..header_end].to_vec();
        self.buffered.drain(..header_end);
        let header = std::str::from_utf8(&header_bytes).map_err(|error| error.to_string())?;
        let status = header
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| "the PostgREST status is absent".to_string())?
            .parse::<u16>()
            .map_err(|error| error.to_string())?;
        let mut content_length = None;
        let mut chunked = false;
        for line in header.lines().skip(1) {
            let lower = line.to_ascii_lowercase();
            if let Some(value) = lower.strip_prefix("content-length:") {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|error| error.to_string())?,
                );
            }
            if lower == "transfer-encoding: chunked" {
                chunked = true;
            }
        }
        if let Some(length) = content_length {
            self.read_at_least(length)?;
            let body = self.buffered.drain(..length).collect::<Vec<_>>();
            return Ok(HttpResponse {
                status,
                body,
                wire_bytes: header_bytes.len() + length,
            });
        }
        if chunked {
            let (body, encoded_bytes) = self.read_chunked()?;
            return Ok(HttpResponse {
                status,
                body,
                wire_bytes: header_bytes.len() + encoded_bytes,
            });
        }
        Err("PostgREST returned no bounded response length".into())
    }

    fn read_until(&mut self, marker: &[u8]) -> Result<usize, String> {
        loop {
            if let Some(index) = find_bytes(&self.buffered, marker) {
                return Ok(index + marker.len());
            }
            self.read_more()?;
        }
    }

    fn read_at_least(&mut self, length: usize) -> Result<(), String> {
        while self.buffered.len() < length {
            self.read_more()?;
        }
        Ok(())
    }

    fn read_more(&mut self) -> Result<(), String> {
        let mut block = [0u8; 8192];
        let count = self
            .stream
            .read(&mut block)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("PostgREST closed a partial response".into());
        }
        self.buffered.extend_from_slice(&block[..count]);
        if self.buffered.len() > MAX_MESSAGE_BYTES {
            return Err("the PostgREST response exceeded the campaign limit".into());
        }
        Ok(())
    }

    fn read_chunked(&mut self) -> Result<(Vec<u8>, usize), String> {
        let mut body = Vec::new();
        let mut consumed = 0usize;
        loop {
            let line_end = self.read_until(b"\r\n")?;
            let line = std::str::from_utf8(&self.buffered[..line_end - 2])
                .map_err(|error| error.to_string())?;
            let size_text = line.split(';').next().unwrap_or(line);
            let size =
                usize::from_str_radix(size_text.trim(), 16).map_err(|error| error.to_string())?;
            self.buffered.drain(..line_end);
            consumed = consumed.saturating_add(line_end);
            if size == 0 {
                let trailer_end = self.read_until(b"\r\n")?;
                self.buffered.drain(..trailer_end);
                consumed = consumed.saturating_add(trailer_end);
                return Ok((body, consumed));
            }
            self.read_at_least(size + 2)?;
            body.extend(self.buffered.drain(..size));
            if self.buffered.get(..2) != Some(b"\r\n") {
                return Err("the PostgREST chunk terminator changed".into());
            }
            self.buffered.drain(..2);
            consumed = consumed.saturating_add(size + 2);
        }
    }
}

fn decode_bytea_hex(value: &str, output: &mut Vec<u8>) -> Result<(), String> {
    let hex = value
        .strip_prefix("\\x")
        .ok_or_else(|| "PostgREST returned non-hexadecimal bytea".to_string())?;
    if hex.len() != 128 {
        return Err("PostgREST returned the wrong bytea length".into());
    }
    for pair in hex.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
        output.push(u8::from_str_radix(text, 16).map_err(|error| error.to_string())?);
    }
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct Resources {
    database: DatabaseState,
    embedded: EmbeddedAdapter,
    gateway: GatewayConnection,
    postgrest: HttpConnection,
}

impl Resources {
    fn connect(connection: &str, gateway: &str, postgrest: &str) -> Result<Self, String> {
        Ok(Self {
            database: DatabaseState::connect(connection)?,
            embedded: EmbeddedAdapter::new(SESSION_BASE + 0x1000)?,
            gateway: GatewayConnection::connect(gateway)?,
            postgrest: HttpConnection::connect(postgrest)?,
        })
    }

    fn execute(&mut self, arm: Arm, ids: &[i64], diagnostics: bool) -> Result<Outcome, String> {
        match arm {
            Arm::Postgrest => self.postgrest.query(ids),
            Arm::SimpleSequential => self.database.simple_sequential(ids),
            Arm::PreparedSequential => self.database.prepared_sequential(ids),
            Arm::NativeSet => self.database.set(ids),
            Arm::EmbeddedNdabi => self.embedded.execute(&mut self.database, ids, diagnostics),
            Arm::NdabiGateway => self.gateway.request(ids),
        }
    }
}

#[derive(Clone, Debug)]
struct Sample {
    wall_ns: u64,
    client_cpu_ns: u64,
    request_bytes: Option<usize>,
    response_bytes: Option<usize>,
    adapter_cpu_ns: Option<u64>,
    adapter_allocation: Option<AllocationDelta>,
}

#[derive(Serialize)]
struct Measurement {
    id: &'static str,
    samples: usize,
    median_batch_ns: u64,
    p95_batch_ns: u64,
    p99_batch_ns: u64,
    operations_per_second: f64,
    median_client_cpu_ns: u64,
    request_bytes: Option<usize>,
    response_bytes: Option<usize>,
    median_adapter_cpu_ns: Option<u64>,
    mean_adapter_allocations: Option<f64>,
    mean_adapter_allocated_bytes: Option<f64>,
    adapter_peak_additional_live_bytes: Option<u64>,
    raw_batch_ns: Vec<u64>,
    raw_client_cpu_ns: Vec<u64>,
}

#[derive(Serialize)]
struct LatencyCase {
    batch_size: usize,
    canonical_sha256: String,
    receipt_sha256: String,
    measurements: Vec<Measurement>,
    embedded_native_distance: f64,
    embedded_prepared_speedup: f64,
    embedded_postgrest_speedup: f64,
    embedded_request_compression: f64,
    gateway_native_distance: f64,
    gateway_prepared_speedup: f64,
    gateway_postgrest_speedup: f64,
    request_compression: f64,
}

#[derive(Serialize)]
struct ConcurrencyMeasurement {
    id: &'static str,
    completed_requests: usize,
    p95_request_ns: u64,
    operations_per_second: f64,
    raw_request_ns: Vec<u64>,
}

#[derive(Serialize)]
struct ConcurrencyCase {
    concurrency: usize,
    measurements: Vec<ConcurrencyMeasurement>,
    embedded_native_throughput: f64,
    embedded_native_p95_distance: f64,
    embedded_postgrest_throughput: f64,
    gateway_native_throughput: f64,
    gateway_native_p95_distance: f64,
    gateway_postgrest_throughput: f64,
}

#[derive(Serialize)]
struct SecurityProof {
    embedded_changed_frame_refused: bool,
    embedded_replay_refused: bool,
    embedded_cross_session_frame_refused: bool,
    embedded_expired_frame_refused: bool,
    changed_frame_refused: bool,
    replay_refused: bool,
    cross_session_frame_refused: bool,
    postgrest_write_refused: bool,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    status: &'static str,
    client_architecture: &'static str,
    client_operating_system: &'static str,
    generated_at_unix_seconds: u64,
    rows: i64,
    latency_cases: Vec<LatencyCase>,
    concurrency_cases: Vec<ConcurrencyCase>,
    security: SecurityProof,
    correctness_gate_passed: bool,
    client_max_rss_kib: u64,
    limitations: [&'static str; 6],
}

fn run_client(connection: &str, gateway: &str, postgrest: &str) -> Result<(), String> {
    let security = prove_security(gateway, postgrest)?;
    let mut latency_cases = Vec::with_capacity(BATCH_SIZES.len());
    for batch_size in BATCH_SIZES {
        latency_cases.push(run_latency_case(
            connection, gateway, postgrest, batch_size,
        )?);
    }
    let mut concurrency_cases = Vec::with_capacity(CONCURRENCY_LEVELS.len());
    for concurrency in CONCURRENCY_LEVELS {
        concurrency_cases.push(run_concurrency_case(
            connection,
            gateway,
            postgrest,
            concurrency,
        )?);
    }
    let expected_requests = CONCURRENCY_BLOCKS * REQUESTS_PER_BLOCK;
    let correctness_gate_passed = security.embedded_changed_frame_refused
        && security.embedded_replay_refused
        && security.embedded_cross_session_frame_refused
        && security.embedded_expired_frame_refused
        && security.changed_frame_refused
        && security.replay_refused
        && security.cross_session_frame_refused
        && security.postgrest_write_refused
        && concurrency_cases.iter().all(|case| {
            case.measurements.iter().all(|measurement| {
                measurement.completed_requests == case.concurrency * expected_requests
            })
        });
    let report = Report {
        schema: "ndabi-postgresql-embedded-v4.1",
        status: "local-docker-process-diagnostic",
        client_architecture: std::env::consts::ARCH,
        client_operating_system: std::env::consts::OS,
        generated_at_unix_seconds: now_unix_seconds()?,
        rows: ROWS,
        latency_cases,
        concurrency_cases,
        security,
        correctness_gate_passed,
        client_max_rss_kib: maximum_rss_kib()?,
        limitations: [
            "Docker Desktop uses a Linux virtual machine, not physical Linux.",
            "The campaign uses a local container bridge without TLS.",
            "PostgREST represents a REST shape, not hosted Supabase.",
            "The gateway uses fixed research authority material.",
            "PostgreSQL protocol bytes remain unmeasured.",
            "Service CPU and energy remain outside the v4.1 hard gates.",
        ],
    };
    serde_json::to_writer_pretty(io::stdout().lock(), &report)
        .map_err(|error| error.to_string())?;
    println!();
    if correctness_gate_passed {
        Ok(())
    } else {
        Err("the v4.1 process correctness gate failed".into())
    }
}

fn prove_security(gateway: &str, postgrest: &str) -> Result<SecurityProof, String> {
    let ids = [ROWS - 2, ROWS - 1];
    let embedded_binding = CompactBinding::new(7, SESSION_BASE + 0x2000, u64::MAX);
    let embedded_frame = encode_compact(embedded_binding, 7, SESSION_BASE + 0x2000, &ids, 1)?;
    let mut embedded_verifier = CompactVerifier::new(embedded_binding);
    let embedded_pending = embedded_verifier.verify_pending_at(&embedded_frame, 0)?;
    let mut embedded_changed = embedded_frame;
    embedded_changed[24] ^= 1;
    let embedded_changed_frame_refused = embedded_verifier
        .verify_pending_at(&embedded_changed, 0)
        .is_err();
    embedded_verifier.commit_pending(embedded_pending)?;
    let embedded_replay_refused = embedded_verifier
        .verify_pending_at(&embedded_frame, 0)
        .is_err();
    let cross_binding = CompactBinding::new(7, SESSION_BASE + 0x2001, u64::MAX);
    let embedded_cross_session_frame_refused = CompactVerifier::new(cross_binding)
        .verify_pending_at(&embedded_frame, 0)
        .is_err();
    let expired_binding = CompactBinding::new(7, SESSION_BASE + 0x2002, 5);
    let expired_frame = encode_compact(expired_binding, 7, SESSION_BASE + 0x2002, &ids, 1)?;
    let embedded_expired_frame_refused = CompactVerifier::new(expired_binding)
        .verify_pending_at(&expired_frame, 6)
        .is_err();

    let mut first = GatewayConnection::connect(gateway)?;
    let frame = first.encode(&ids, 1)?;
    if first.send_raw(&frame)?.is_none() {
        return Err("the gateway refused the security control frame".into());
    }
    let replay_refused = first.send_raw(&frame)?.is_none();

    let mut second = GatewayConnection::connect(gateway)?;
    let cross_session_frame_refused = second.send_raw(&frame)?.is_none();
    let mut changed = second.encode(&ids, 1)?;
    let last = changed
        .last_mut()
        .ok_or_else(|| "the security frame is empty".to_string())?;
    *last ^= 1;
    let changed_frame_refused = second.send_raw(&changed)?.is_none();

    let mut postgrest_connection = HttpConnection::connect(postgrest)?;
    let postgrest_write_refused = postgrest_connection.prove_write_refusal()?;
    Ok(SecurityProof {
        embedded_changed_frame_refused,
        embedded_replay_refused,
        embedded_cross_session_frame_refused,
        embedded_expired_frame_refused,
        changed_frame_refused,
        replay_refused,
        cross_session_frame_refused,
        postgrest_write_refused,
    })
}

fn run_latency_case(
    connection: &str,
    gateway: &str,
    postgrest: &str,
    batch_size: usize,
) -> Result<LatencyCase, String> {
    let ids = case_ids(batch_size)?;
    let mut resources = Resources::connect(connection, gateway, postgrest)?;
    let expected = resources.database.set(&ids)?;
    for cycle in 0..LATENCY_WARMUP {
        for offset in 0..Arm::ALL.len() {
            let arm = Arm::ALL[(cycle + offset) % Arm::ALL.len()];
            let outcome = resources.execute(arm, &ids, false)?;
            require_equal(&expected, &outcome, arm)?;
        }
    }
    let mut samples: [Vec<Sample>; 6] = array::from_fn(|_| Vec::with_capacity(LATENCY_SAMPLES));
    for cycle in 0..LATENCY_SAMPLES {
        for offset in 0..Arm::ALL.len() {
            let arm = Arm::ALL[(cycle + offset) % Arm::ALL.len()];
            let cpu_start = thread_cpu_ns()?;
            let started = Instant::now();
            let outcome = resources.execute(arm, &ids, true)?;
            let wall_ns = elapsed_ns(started);
            let client_cpu_ns = thread_cpu_ns()?.saturating_sub(cpu_start);
            require_equal(&expected, &outcome, arm)?;
            samples[arm.index()].push(Sample {
                wall_ns,
                client_cpu_ns,
                request_bytes: outcome.request_bytes,
                response_bytes: outcome.response_bytes,
                adapter_cpu_ns: outcome.adapter_cpu_ns,
                adapter_allocation: outcome.adapter_allocation,
            });
            black_box(outcome);
        }
    }
    let measurements = Arm::ALL
        .iter()
        .map(|arm| finish_measurement(*arm, batch_size, &samples[arm.index()]))
        .collect::<Result<Vec<_>, _>>()?;
    let native = measurement(&measurements, Arm::NativeSet)?;
    let prepared = measurement(&measurements, Arm::PreparedSequential)?;
    let postgrest_measurement = measurement(&measurements, Arm::Postgrest)?;
    let embedded = measurement(&measurements, Arm::EmbeddedNdabi)?;
    let ndabi = measurement(&measurements, Arm::NdabiGateway)?;
    let postgrest_request = postgrest_measurement
        .request_bytes
        .ok_or_else(|| "PostgREST request bytes are absent".to_string())?;
    let embedded_request = embedded
        .request_bytes
        .ok_or_else(|| "NDABI request bytes are absent".to_string())?;
    Ok(LatencyCase {
        batch_size,
        canonical_sha256: hex(&Sha256::digest(&expected.bytes)),
        receipt_sha256: hex(&expected.receipt),
        embedded_native_distance: ratio(embedded.p95_batch_ns, native.p95_batch_ns),
        embedded_prepared_speedup: ratio(prepared.p95_batch_ns, embedded.p95_batch_ns),
        embedded_postgrest_speedup: ratio(
            postgrest_measurement.p95_batch_ns,
            embedded.p95_batch_ns,
        ),
        embedded_request_compression: 1.0 - embedded_request as f64 / postgrest_request as f64,
        gateway_native_distance: ratio(ndabi.p95_batch_ns, native.p95_batch_ns),
        gateway_prepared_speedup: ratio(prepared.p95_batch_ns, ndabi.p95_batch_ns),
        gateway_postgrest_speedup: ratio(postgrest_measurement.p95_batch_ns, ndabi.p95_batch_ns),
        request_compression: 1.0
            - ndabi
                .request_bytes
                .ok_or_else(|| "gateway request bytes are absent".to_string())?
                as f64
                / postgrest_request as f64,
        measurements,
    })
}

fn finish_measurement(
    arm: Arm,
    operations: usize,
    samples: &[Sample],
) -> Result<Measurement, String> {
    let mut wall = samples
        .iter()
        .map(|sample| sample.wall_ns)
        .collect::<Vec<_>>();
    wall.sort_unstable();
    let mut client_cpu = samples
        .iter()
        .map(|sample| sample.client_cpu_ns)
        .collect::<Vec<_>>();
    client_cpu.sort_unstable();
    let total_ns = wall.iter().map(|value| u128::from(*value)).sum::<u128>();
    let gateway_cpu = optional_values(samples, |sample| sample.adapter_cpu_ns)?;
    let allocations = optional_values(samples, |sample| {
        sample.adapter_allocation.map(|value| value.allocations)
    })?;
    let allocated_bytes = optional_values(samples, |sample| {
        sample.adapter_allocation.map(|value| value.allocated_bytes)
    })?;
    let peaks = optional_values(samples, |sample| {
        sample
            .adapter_allocation
            .map(|value| value.peak_additional_live_bytes)
    })?;
    Ok(Measurement {
        id: arm.id(),
        samples: samples.len(),
        median_batch_ns: percentile(&wall, 0.50),
        p95_batch_ns: percentile(&wall, 0.95),
        p99_batch_ns: percentile(&wall, 0.99),
        operations_per_second: (samples.len() * operations) as f64
            / (total_ns as f64 / 1_000_000_000.0),
        median_client_cpu_ns: percentile(&client_cpu, 0.50),
        request_bytes: uniform_optional(samples, |sample| sample.request_bytes)?,
        response_bytes: uniform_optional(samples, |sample| sample.response_bytes)?,
        median_adapter_cpu_ns: gateway_cpu.as_ref().map(|values| percentile(values, 0.50)),
        mean_adapter_allocations: allocations.as_ref().map(|values| mean_u64(values)),
        mean_adapter_allocated_bytes: allocated_bytes.as_ref().map(|values| mean_u64(values)),
        adapter_peak_additional_live_bytes: peaks
            .as_ref()
            .and_then(|values| values.iter().max().copied()),
        raw_batch_ns: wall,
        raw_client_cpu_ns: client_cpu,
    })
}

fn optional_values(
    samples: &[Sample],
    value: impl Fn(&Sample) -> Option<u64>,
) -> Result<Option<Vec<u64>>, String> {
    let values = samples.iter().map(value).collect::<Vec<_>>();
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    if values.iter().any(Option::is_none) {
        return Err("a diagnostic is present for only part of one arm".into());
    }
    Ok(Some(values.into_iter().flatten().collect()))
}

fn uniform_optional(
    samples: &[Sample],
    value: impl Fn(&Sample) -> Option<usize>,
) -> Result<Option<usize>, String> {
    let values = samples.iter().map(value).collect::<Vec<_>>();
    let first = values.iter().flatten().next().copied();
    if let Some(first) = first {
        if values.iter().flatten().any(|candidate| *candidate != first) {
            return Err("the application wire size changed within one arm".into());
        }
        if values.iter().any(Option::is_none) {
            return Err("an application wire size is partially absent".into());
        }
    }
    Ok(first)
}

fn mean_u64(values: &[u64]) -> f64 {
    values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64
}

struct WorkerResult {
    raw: [Vec<u64>; 6],
    arm_elapsed_ns: [u64; 6],
}

fn run_concurrency_case(
    connection: &str,
    gateway: &str,
    postgrest: &str,
    concurrency: usize,
) -> Result<ConcurrencyCase, String> {
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let phase_barrier = Arc::new(Barrier::new(concurrency));
    let setup_failed = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(concurrency);
    for worker in 0..concurrency {
        let connection = connection.to_string();
        let gateway = gateway.to_string();
        let postgrest = postgrest.to_string();
        let barrier = Arc::clone(&barrier);
        let phase_barrier = Arc::clone(&phase_barrier);
        let setup_failed = Arc::clone(&setup_failed);
        handles.push(thread::spawn(move || {
            run_worker(
                &connection,
                &gateway,
                &postgrest,
                barrier,
                phase_barrier,
                setup_failed,
                worker,
            )
        }));
    }
    barrier.wait();
    let mut workers = Vec::with_capacity(concurrency);
    for handle in handles {
        workers.push(
            handle
                .join()
                .map_err(|_| "a v4.1 worker panicked".to_string())??,
        );
    }
    let expected_per_worker = CONCURRENCY_BLOCKS * REQUESTS_PER_BLOCK;
    let mut measurements = Vec::with_capacity(Arm::ALL.len());
    for arm in Arm::ALL {
        let mut raw = Vec::with_capacity(concurrency * expected_per_worker);
        let mut critical_ns = 0u64;
        for worker in &workers {
            raw.extend_from_slice(&worker.raw[arm.index()]);
            critical_ns = critical_ns.max(worker.arm_elapsed_ns[arm.index()]);
        }
        raw.sort_unstable();
        let completed_requests = raw.len();
        let operations = completed_requests * 32;
        measurements.push(ConcurrencyMeasurement {
            id: arm.id(),
            completed_requests,
            p95_request_ns: percentile(&raw, 0.95),
            operations_per_second: operations as f64
                / (critical_ns.max(1) as f64 / 1_000_000_000.0),
            raw_request_ns: raw,
        });
    }
    let native = concurrency_measurement(&measurements, Arm::NativeSet)?;
    let postgrest_measurement = concurrency_measurement(&measurements, Arm::Postgrest)?;
    let embedded = concurrency_measurement(&measurements, Arm::EmbeddedNdabi)?;
    let ndabi = concurrency_measurement(&measurements, Arm::NdabiGateway)?;
    Ok(ConcurrencyCase {
        concurrency,
        embedded_native_throughput: embedded.operations_per_second / native.operations_per_second,
        embedded_native_p95_distance: ratio(embedded.p95_request_ns, native.p95_request_ns),
        embedded_postgrest_throughput: embedded.operations_per_second
            / postgrest_measurement.operations_per_second,
        gateway_native_throughput: ndabi.operations_per_second / native.operations_per_second,
        gateway_native_p95_distance: ratio(ndabi.p95_request_ns, native.p95_request_ns),
        gateway_postgrest_throughput: ndabi.operations_per_second
            / postgrest_measurement.operations_per_second,
        measurements,
    })
}

fn run_worker(
    connection: &str,
    gateway: &str,
    postgrest: &str,
    barrier: Arc<Barrier>,
    phase_barrier: Arc<Barrier>,
    setup_failed: Arc<AtomicBool>,
    worker: usize,
) -> Result<WorkerResult, String> {
    let prepared = (|| {
        let ids = case_ids(32)?;
        let mut resources = Resources::connect(connection, gateway, postgrest)?;
        let expected = resources.database.set(&ids)?;
        for cycle in 0..CONCURRENCY_WARMUP {
            for offset in 0..Arm::ALL.len() {
                let arm = Arm::ALL[(cycle + offset + worker) % Arm::ALL.len()];
                let outcome = resources.execute(arm, &ids, false)?;
                require_equal(&expected, &outcome, arm)?;
            }
        }
        Ok::<_, String>((ids, resources, expected))
    })();
    if prepared.is_err() {
        setup_failed.store(true, Ordering::Release);
    }
    // Every worker observes setup failure after the barrier and refuses the phase together.
    barrier.wait();
    if setup_failed.load(Ordering::Acquire) {
        return match prepared {
            Err(error) => Err(format!("the concurrent setup failed: {error}")),
            Ok(_) => Err("another concurrent worker failed setup".into()),
        };
    }
    let (ids, mut resources, expected) = prepared?;
    let mut raw: [Vec<u64>; 6] =
        array::from_fn(|_| Vec::with_capacity(CONCURRENCY_BLOCKS * REQUESTS_PER_BLOCK));
    let mut arm_elapsed_ns = [0u64; 6];
    let mut worker_error = None;
    for block in 0..CONCURRENCY_BLOCKS {
        for offset in 0..Arm::ALL.len() {
            let arm = Arm::ALL[(block + offset) % Arm::ALL.len()];
            phase_barrier.wait();
            let block_started = Instant::now();
            if worker_error.is_none() {
                for _ in 0..REQUESTS_PER_BLOCK {
                    let started = Instant::now();
                    match resources.execute(arm, &ids, false) {
                        Ok(outcome) => {
                            raw[arm.index()].push(elapsed_ns(started));
                            if let Err(error) = require_equal(&expected, &outcome, arm) {
                                worker_error = Some(error);
                                break;
                            }
                        }
                        Err(error) => {
                            worker_error = Some(error);
                            break;
                        }
                    }
                }
            }
            phase_barrier.wait();
            arm_elapsed_ns[arm.index()] =
                arm_elapsed_ns[arm.index()].saturating_add(elapsed_ns(block_started));
        }
    }
    if let Some(error) = worker_error {
        return Err(error);
    }
    Ok(WorkerResult {
        raw,
        arm_elapsed_ns,
    })
}

fn case_ids(batch_size: usize) -> Result<Vec<i64>, String> {
    let start = ROWS
        .checked_sub(i64::try_from(batch_size).map_err(|error| error.to_string())?)
        .ok_or_else(|| "the v4.1 batch exceeds the dataset".to_string())?;
    Ok((start..ROWS).collect())
}

fn measurement(values: &[Measurement], arm: Arm) -> Result<&Measurement, String> {
    values
        .iter()
        .find(|measurement| measurement.id == arm.id())
        .ok_or_else(|| format!("the {} measurement is absent", arm.id()))
}

fn concurrency_measurement(
    values: &[ConcurrencyMeasurement],
    arm: Arm,
) -> Result<&ConcurrencyMeasurement, String> {
    values
        .iter()
        .find(|measurement| measurement.id == arm.id())
        .ok_or_else(|| format!("the {} concurrency measurement is absent", arm.id()))
}

fn require_equal(expected: &Outcome, actual: &Outcome, arm: Arm) -> Result<(), String> {
    if expected.bytes != actual.bytes || expected.receipt != actual.receipt {
        return Err(format!(
            "{} changed the canonical result or receipt",
            arm.id()
        ));
    }
    Ok(())
}

fn campaign_generation() -> Result<u64, String> {
    now_unix_us()?
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(u64::from(std::process::id())))
        .ok_or_else(|| "the v4.1 generation overflowed".to_string())
}

fn now_unix_us() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_micros(),
    )
    .map_err(|error| error.to_string())
}

fn now_unix_seconds() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs())
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn thread_cpu_ns() -> Result<u64, String> {
    let mut timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut timespec) };
    if result != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let seconds = u64::try_from(timespec.tv_sec).map_err(|error| error.to_string())?;
    let nanoseconds = u64::try_from(timespec.tv_nsec).map_err(|error| error.to_string())?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| "the thread CPU clock overflowed".to_string())
}

fn maximum_rss_kib() -> Result<u64, String> {
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if result != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    u64::try_from(usage.ru_maxrss).map_err(|error| error.to_string())
}

fn percentile(sorted: &[u64], quantile: f64) -> u64 {
    sorted[((sorted.len() - 1) as f64 * quantile).ceil() as usize]
}

fn ratio(left: u64, right: u64) -> f64 {
    left as f64 / right.max(1) as f64
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("the fixed message field is bounded"),
    )
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("the fixed message field is bounded"),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_uses_the_registered_nearest_rank() {
        let values = (1..=100).collect::<Vec<_>>();
        assert_eq!(percentile(&values, 0.50), 51);
        assert_eq!(percentile(&values, 0.95), 96);
        assert_eq!(percentile(&values, 0.99), 100);
    }

    #[test]
    fn bytea_decoder_accepts_only_the_frozen_hex_shape() {
        let mut output = Vec::new();
        let value = format!("\\x{}", "ab".repeat(64));
        decode_bytea_hex(&value, &mut output).expect("decode bytea");
        assert_eq!(output, vec![0xab; 64]);
        assert!(decode_bytea_hex("plain", &mut output).is_err());
    }

    #[test]
    fn message_round_trip_preserves_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("test address");
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connect test client");
            write_message(&mut stream, b"ndabi").expect("write test message");
        });
        let (mut stream, _) = listener.accept().expect("accept test client");
        assert_eq!(
            read_message(&mut stream).expect("read message"),
            Some(b"ndabi".to_vec())
        );
        writer.join().expect("join test writer");
    }

    #[test]
    fn compact_verifier_authenticates_before_it_commits_replay_state() {
        let binding = CompactBinding::new(7, SESSION_BASE, u64::MAX);
        let mut verifier = CompactVerifier::new(binding);
        let mut frame = vec![0u8; EXECUTE_BYTES];
        frame[..4].copy_from_slice(&EXECUTE_MAGIC);
        frame[4..8].copy_from_slice(&SESSION_BASE.to_le_bytes());
        frame[8..16].copy_from_slice(&7u64.to_le_bytes());
        frame[16..24].copy_from_slice(&1u64.to_le_bytes());
        frame[24..32].copy_from_slice(&99_968i64.to_le_bytes());
        frame[32..34].copy_from_slice(&32u16.to_le_bytes());
        frame[34..36].copy_from_slice(&(OPERATION_READ | OPERATION_IDEMPOTENT).to_le_bytes());
        frame[36..40].copy_from_slice(&(32u32 * 76).to_le_bytes());
        let tag = binding.tag(&frame[..EXECUTE_TAG_OFFSET]);
        frame[EXECUTE_TAG_OFFSET..].copy_from_slice(&tag);

        let pending = verifier
            .verify_pending_at(&frame, 0)
            .expect("verify control frame");
        let mut changed = frame.clone();
        changed[24] ^= 1;
        assert!(verifier.verify_pending_at(&changed, 0).is_err());
        verifier
            .commit_pending(pending)
            .expect("commit control frame");
        assert!(verifier.verify_pending_at(&frame, 0).is_err());
    }

    #[test]
    fn response_decoder_refuses_a_changed_receipt() {
        let outcome = local_outcome(vec![0x40; 76]);
        let mut response = Vec::new();
        response.push(0);
        response.extend_from_slice(&76u32.to_le_bytes());
        response.extend_from_slice(&outcome.bytes);
        response.extend_from_slice(&outcome.receipt);
        response.extend_from_slice(&[0; 32]);
        decode_gateway_response(&response, EXECUTE_BYTES + 4).expect("decode control response");
        response[5 + 76] ^= 1;
        assert!(decode_gateway_response(&response, EXECUTE_BYTES + 4).is_err());
    }
}
