//! Measure complete v0.2 result transport cost around one canonical PostgreSQL profile.
//!
//! Negotiation occurs once per steady session. Every measured v0.2 sample still authenticates the request and result.

use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ndabi_postgres_v1::{
    digest_label, memory_replay_store, AuthorityContext, OperationBinding, RangeBackend,
    RangeProfile, ServerSession as RangeServerSession, WireClientSession, FRAME_BYTES,
};
use ndabi_protocol::{
    decode_transport, encode_transport, transport_frame_bytes, Authority, BackendIdentity,
    MemoryReplayStore, ProtocolError, SystemClock, TransportConfig, TransportConnection,
    TransportDirection, TransportFields, TransportKind, TransportRole, TRANSPORT_MIN_FRAME_BYTES,
};
use ndabi_showdown::alloc::{begin_measurement, end_measurement, AllocationDelta};
use postgres::{Client, NoTls, Row, Statement};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[global_allocator]
static GLOBAL: ndabi_showdown::alloc::CountingAllocator = ndabi_showdown::alloc::CountingAllocator;

const SQL: &str =
    "SELECT id,bucket,owner,score,payload FROM ndabi_v65_items WHERE id = ANY($1) ORDER BY id";
const COUNTS: [u32; 4] = [1, 32, 128, 1_024];
const STARTS: [i64; 4] = [1_000, 10_000, 100_000, 500_000];
const SAMPLES: usize = 63;
const WARMUPS: usize = 7;
const EXPIRY_UNIX_US: u64 = 4_102_444_800_000_000;
const MAXIMUM_FRAME_BYTES: u32 = 131_072;
const MAXIMUM_CHUNK_BYTES: u32 = 65_536;
const ARMS: [Arm; 3] = [Arm::Native, Arm::V1, Arm::V2];

#[derive(Clone, Copy)]
enum Arm {
    Native = 0,
    V1 = 1,
    V2 = 2,
}

impl Arm {
    fn id(self) -> &'static str {
        match self {
            Self::Native => "native-prepared",
            Self::V1 => "canonical-v1",
            Self::V2 => "canonical-v2-transport",
        }
    }
}

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    samples: usize,
    warmups: usize,
    cases: Vec<CaseReport>,
    security: SecurityReport,
    passed: bool,
}

#[derive(Serialize)]
struct CaseReport {
    rows: u32,
    request_bytes: usize,
    result_bytes: usize,
    transport_result_frame_bytes: usize,
    result_sha256: String,
    measurements: Vec<Measurement>,
    data_queries: [u64; 3],
    expected_data_queries: u64,
    v1_native_p50_distance: f64,
    v2_native_p50_distance: f64,
    v2_v1_p50_distance: f64,
    v2_v1_p95_distance: f64,
    v2_v1_cpu_distance: f64,
    passed: bool,
}

#[derive(Serialize)]
struct Measurement {
    arm: &'static str,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    p50_cpu_ns: u64,
    mean_allocations: f64,
    mean_allocated_bytes: f64,
    peak_additional_live_bytes: u64,
    raw_ns: Vec<u64>,
    raw_cpu_ns: Vec<u64>,
}

#[derive(Serialize)]
struct SecurityReport {
    request_mutation_refused: bool,
    replay_refused_before_query: bool,
    invalid_receipt_refused: bool,
    invalid_receipt_preserved_pending_request: bool,
    reflected_result_refused: bool,
    valid_result_accepted_after_refusals: bool,
    successful_data_queries: u64,
    passed: bool,
}

struct Outcome {
    bytes: Vec<u8>,
    verified: bool,
}

struct Sample {
    wall_ns: u64,
    cpu_ns: u64,
    allocation: AllocationDelta,
}

struct V1State {
    profile: RangeProfile,
    client: WireClientSession,
    server: RangeServerSession,
    backend: RangeBackend,
    replay: MemoryReplayStore,
}

struct V2State {
    profile: RangeProfile,
    wire_client: WireClientSession,
    wire_server: RangeServerSession,
    transport_client: TransportConnection,
    transport_server: TransportConnection,
    backend: RangeBackend,
    replay: MemoryReplayStore,
    result_frame: Vec<u8>,
}

struct NativeState {
    client: Client,
    deadline_statement: Statement,
    statement: Statement,
    ids: Vec<i64>,
    data_queries: u64,
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
    let mut cases = Vec::with_capacity(COUNTS.len());
    for (case_index, rows) in COUNTS.into_iter().enumerate() {
        cases.push(measure_case(
            &connection,
            rows,
            STARTS[case_index],
            case_index,
        )?);
    }
    let security = security_suite(&connection)?;
    let passed = cases.iter().all(|case| case.passed) && security.passed;
    serde_json::to_writer(
        std::io::stdout(),
        &Report {
            campaign: "NDABI PostgreSQL transport performance v6.5",
            samples: SAMPLES,
            warmups: WARMUPS,
            cases,
            security,
            passed,
        },
    )
    .map_err(|error| error.to_string())?;
    println!();
    if passed {
        Ok(())
    } else {
        Err("the PostgreSQL transport performance gate failed".to_string())
    }
}

fn measure_case(
    connection: &str,
    rows: u32,
    start: i64,
    case_index: usize,
) -> Result<CaseReport, String> {
    let profile = profile()?;
    let identity = identity(profile)?;
    let expected = expected_rows(start, rows);
    let result_budget = u32::try_from(expected.len()).map_err(|error| error.to_string())?;
    let ids = (0..i64::from(rows))
        .map(|offset| start + offset)
        .collect::<Vec<_>>();
    let mut native = NativeState::new(connection, ids)?;
    let mut v1 = V1State::new(
        connection,
        profile,
        identity,
        rows,
        result_budget,
        case_index,
    )?;
    let mut v2 = V2State::new(
        connection,
        profile,
        identity,
        rows,
        result_budget,
        case_index,
    )?;
    let before_queries = [
        native.data_queries,
        v1.backend.data_queries(),
        v2.backend.data_queries(),
    ];
    let mut samples: [Vec<Sample>; 3] = std::array::from_fn(|_| Vec::with_capacity(SAMPLES));
    for sample_index in 0..WARMUPS + SAMPLES {
        for arm_offset in 0..ARMS.len() {
            let arm = ARMS[(case_index + sample_index + arm_offset) % ARMS.len()];
            let deadline = deadline()?;
            let cpu_started = thread_cpu_ns()?;
            let allocation_started = begin_measurement();
            let started = Instant::now();
            let outcome = match arm {
                Arm::Native => native.execute()?,
                Arm::V1 => v1.execute(start, rows, result_budget, deadline)?,
                Arm::V2 => v2.execute(start, rows, result_budget, deadline)?,
            };
            let wall_ns = elapsed_ns(started)?;
            let allocation = end_measurement(allocation_started);
            let cpu_ns = thread_cpu_ns()?.saturating_sub(cpu_started);
            if outcome.bytes != expected || !outcome.verified {
                return Err(format!("the {} result changed for {rows} rows", arm.id()));
            }
            black_box(&outcome.bytes);
            if sample_index >= WARMUPS {
                samples[arm as usize].push(Sample {
                    wall_ns,
                    cpu_ns,
                    allocation,
                });
            }
        }
    }
    let data_queries = [
        native.data_queries - before_queries[0],
        v1.backend.data_queries() - before_queries[1],
        v2.backend.data_queries() - before_queries[2],
    ];
    let expected_data_queries = (WARMUPS + SAMPLES) as u64;
    let measurements = ARMS
        .into_iter()
        .map(|arm| summarise(arm, std::mem::take(&mut samples[arm as usize])))
        .collect::<Vec<_>>();
    let native_measurement = &measurements[Arm::Native as usize];
    let v1_measurement = &measurements[Arm::V1 as usize];
    let v2_measurement = &measurements[Arm::V2 as usize];
    let v1_native_p50_distance = ratio(v1_measurement.p50_ns, native_measurement.p50_ns);
    let v2_native_p50_distance = ratio(v2_measurement.p50_ns, native_measurement.p50_ns);
    let v2_v1_p50_distance = ratio(v2_measurement.p50_ns, v1_measurement.p50_ns);
    let v2_v1_p95_distance = ratio(v2_measurement.p95_ns, v1_measurement.p95_ns);
    let v2_v1_cpu_distance = ratio(v2_measurement.p50_cpu_ns, v1_measurement.p50_cpu_ns);
    let passed = data_queries == [expected_data_queries; 3]
        && v1_native_p50_distance <= 1.25
        && v2_native_p50_distance <= 1.35
        && v2_v1_p50_distance <= 1.25
        && v2_v1_cpu_distance <= 1.50;
    Ok(CaseReport {
        rows,
        request_bytes: FRAME_BYTES,
        result_bytes: expected.len(),
        transport_result_frame_bytes: transport_frame_bytes(expected.len())
            .map_err(|error| error.to_string())?,
        result_sha256: hex(&Sha256::digest(&expected)),
        measurements,
        data_queries,
        expected_data_queries,
        v1_native_p50_distance,
        v2_native_p50_distance,
        v2_v1_p50_distance,
        v2_v1_p95_distance,
        v2_v1_cpu_distance,
        passed,
    })
}

impl V1State {
    fn new(
        connection: &str,
        profile: RangeProfile,
        identity: BackendIdentity,
        rows: u32,
        result_budget: u32,
        case_index: usize,
    ) -> Result<Self, String> {
        let authority = authority(identity, 650 + case_index as u64)?;
        Ok(Self {
            profile,
            client: WireClientSession::new(authority.clone()),
            server: RangeServerSession::new(authority, result_budget, rows)
                .map_err(|error| error.to_string())?,
            backend: connect_backend(connection, profile)?,
            replay: memory_replay_store(),
        })
    }

    fn execute(
        &mut self,
        start: i64,
        rows: u32,
        result_budget: u32,
        deadline: u64,
    ) -> Result<Outcome, String> {
        let request = self
            .client
            .encode(
                self.profile
                    .operation(start, rows)
                    .map_err(|error| error.to_string())?,
                result_budget,
                rows,
                deadline,
            )
            .map_err(|error| error.to_string())?;
        let execution = self
            .server
            .execute(&request, &mut self.backend, &mut self.replay, &SystemClock)
            .map_err(|error| error.to_string())?;
        Ok(Outcome {
            verified: execution.receipt.iter().any(|byte| *byte != 0),
            bytes: execution.bytes,
        })
    }
}

impl V2State {
    fn new(
        connection: &str,
        profile: RangeProfile,
        identity: BackendIdentity,
        rows: u32,
        result_budget: u32,
        case_index: usize,
    ) -> Result<Self, String> {
        let authority = authority(identity, 660 + case_index as u64)?;
        let (transport_client, transport_server) = transport_pair(authority.clone())?;
        Ok(Self {
            profile,
            wire_client: WireClientSession::new(authority.clone()),
            wire_server: RangeServerSession::new(authority, result_budget, rows)
                .map_err(|error| error.to_string())?,
            transport_client,
            transport_server,
            backend: connect_backend(connection, profile)?,
            replay: memory_replay_store(),
            result_frame: Vec::with_capacity(MAXIMUM_FRAME_BYTES as usize),
        })
    }

    fn execute(
        &mut self,
        start: i64,
        rows: u32,
        result_budget: u32,
        deadline: u64,
    ) -> Result<Outcome, String> {
        let request = self
            .wire_client
            .encode(
                self.profile
                    .operation(start, rows)
                    .map_err(|error| error.to_string())?,
                result_budget,
                rows,
                deadline,
            )
            .map_err(|error| error.to_string())?;
        let client_request = self
            .transport_client
            .register_v1_request(&request)
            .map_err(|error| error.to_string())?;
        let execution = self
            .wire_server
            .execute(&request, &mut self.backend, &mut self.replay, &SystemClock)
            .map_err(|error| error.to_string())?;
        let server_request = self
            .transport_server
            .register_v1_request(&request)
            .map_err(|error| error.to_string())?;
        if client_request != server_request {
            return Err("the transport request metadata changed".to_string());
        }
        let receipt = self
            .transport_server
            .result_receipt(server_request.nonce, execution.rows, &execution.bytes)
            .map_err(|error| error.to_string())?;
        self.result_frame.resize(
            transport_frame_bytes(execution.bytes.len()).map_err(|error| error.to_string())?,
            0,
        );
        self.transport_server
            .encode(
                TransportKind::Result,
                TransportFields {
                    correlation_nonce: server_request.nonce,
                    rows: execution.rows,
                    result_shape: server_request.result_shape,
                    execution_receipt: receipt,
                    ..TransportFields::empty()
                },
                &execution.bytes,
                &mut self.result_frame,
            )
            .map_err(|error| error.to_string())?;
        let decoded = self
            .transport_client
            .decode(&self.result_frame, unix_us()?)
            .map_err(|error| error.to_string())?;
        if decoded.payload != execution.bytes {
            return Err("the transport payload changed".to_string());
        }
        Ok(Outcome {
            bytes: execution.bytes,
            verified: true,
        })
    }
}

impl NativeState {
    fn new(connection: &str, ids: Vec<i64>) -> Result<Self, String> {
        let mut client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
        client
            .batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            .map_err(|error| error.to_string())?;
        let deadline_statement = client
            .prepare("SELECT set_config('statement_timeout', $1, false)")
            .map_err(|error| error.to_string())?;
        let statement = client.prepare(SQL).map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            deadline_statement,
            statement,
            ids,
            data_queries: 0,
        })
    }

    fn execute(&mut self) -> Result<Outcome, String> {
        self.client
            .query_one(&self.deadline_statement, &[&"60000ms"])
            .map_err(|error| error.to_string())?;
        let rows = self
            .client
            .query(&self.statement, &[&self.ids])
            .map_err(|error| error.to_string())?;
        self.data_queries = self.data_queries.saturating_add(1);
        if rows.len() != self.ids.len() {
            return Err("the native query returned an incomplete result".to_string());
        }
        Ok(Outcome {
            bytes: encode_rows(&rows, &self.ids)?,
            verified: true,
        })
    }
}

fn security_suite(connection: &str) -> Result<SecurityReport, String> {
    let profile = profile()?;
    let identity = identity(profile)?;
    let authority = authority(identity, 699)?;
    let mut wire_client = WireClientSession::new(authority.clone());
    let request = wire_client
        .encode(
            profile
                .operation(42, 2)
                .map_err(|error| error.to_string())?,
            174,
            2,
            deadline()?,
        )
        .map_err(|error| error.to_string())?;
    let (mut transport_client, mut transport_server) = transport_pair(authority.clone())?;
    let mut changed = request;
    changed[60] ^= 1;
    let request_mutation_refused = matches!(
        transport_client.register_v1_request(&changed),
        Err(ProtocolError::AuthenticationFailed)
    );
    let client_request = transport_client
        .register_v1_request(&request)
        .map_err(|error| error.to_string())?;
    let server_request = transport_server
        .register_v1_request(&request)
        .map_err(|error| error.to_string())?;
    let wire_server =
        RangeServerSession::new(authority.clone(), 174, 2).map_err(|error| error.to_string())?;
    let mut backend = connect_backend(connection, profile)?;
    let mut replay = memory_replay_store();
    let execution = wire_server
        .execute(&request, &mut backend, &mut replay, &SystemClock)
        .map_err(|error| error.to_string())?;
    let queries_after_success = backend.data_queries();
    let replay_refused_before_query = matches!(
        wire_server.execute(&request, &mut backend, &mut replay, &SystemClock),
        Err(ProtocolError::Replay)
    ) && backend.data_queries() == queries_after_success;

    let fields = TransportFields {
        correlation_nonce: client_request.nonce,
        rows: execution.rows,
        result_shape: client_request.result_shape,
        execution_receipt: [9; 32],
        ..TransportFields::empty()
    };
    let mut invalid =
        vec![0; transport_frame_bytes(execution.bytes.len()).map_err(|error| error.to_string())?];
    encode_transport(
        &authority,
        TransportDirection::ServerToClient,
        TransportKind::Result,
        fields,
        &execution.bytes,
        &mut invalid,
    )
    .map_err(|error| error.to_string())?;
    let invalid_receipt_refused = matches!(
        transport_client.decode(&invalid, unix_us()?),
        Err(ProtocolError::ReceiptMismatch)
    );
    let invalid_receipt_preserved_pending_request = transport_client
        .result_receipt(client_request.nonce, execution.rows, &execution.bytes)
        .is_ok();
    let receipt = transport_server
        .result_receipt(server_request.nonce, execution.rows, &execution.bytes)
        .map_err(|error| error.to_string())?;
    let mut valid = vec![0; invalid.len()];
    transport_server
        .encode(
            TransportKind::Result,
            TransportFields {
                execution_receipt: receipt,
                ..fields
            },
            &execution.bytes,
            &mut valid,
        )
        .map_err(|error| error.to_string())?;
    let reflected_result_refused = matches!(
        decode_transport(
            &authority,
            TransportDirection::ClientToServer,
            &valid,
            MAXIMUM_FRAME_BYTES - TRANSPORT_MIN_FRAME_BYTES as u32,
            unix_us()?,
        ),
        Err(ProtocolError::AuthenticationFailed)
    );
    let valid_result_accepted_after_refusals = transport_client.decode(&valid, unix_us()?).is_ok();
    let successful_data_queries = backend.data_queries();
    let passed = request_mutation_refused
        && replay_refused_before_query
        && invalid_receipt_refused
        && invalid_receipt_preserved_pending_request
        && reflected_result_refused
        && valid_result_accepted_after_refusals
        && successful_data_queries == 1;
    Ok(SecurityReport {
        request_mutation_refused,
        replay_refused_before_query,
        invalid_receipt_refused,
        invalid_receipt_preserved_pending_request,
        reflected_result_refused,
        valid_result_accepted_after_refusals,
        successful_data_queries,
        passed,
    })
}

fn transport_pair(
    authority: Authority,
) -> Result<(TransportConnection, TransportConnection), String> {
    let config = TransportConfig::new(0, MAXIMUM_FRAME_BYTES, MAXIMUM_CHUNK_BYTES, 1)
        .map_err(|error| error.to_string())?;
    let mut client = TransportConnection::new(authority.clone(), TransportRole::Client, config);
    let mut server = TransportConnection::new(authority, TransportRole::Server, config);
    transfer(
        &mut client,
        &mut server,
        TransportKind::Hello,
        TransportFields {
            auxiliary: MAXIMUM_FRAME_BYTES,
            ..TransportFields::empty()
        },
        &negotiation_payload(2, 2),
    )?;
    transfer(
        &mut server,
        &mut client,
        TransportKind::Accept,
        TransportFields {
            auxiliary: MAXIMUM_FRAME_BYTES,
            ..TransportFields::empty()
        },
        &negotiation_payload(2, 0),
    )?;
    Ok((client, server))
}

fn transfer(
    sender: &mut TransportConnection,
    receiver: &mut TransportConnection,
    kind: TransportKind,
    fields: TransportFields,
    payload: &[u8],
) -> Result<(), String> {
    let mut frame =
        vec![0; transport_frame_bytes(payload.len()).map_err(|error| error.to_string())?];
    sender
        .encode(kind, fields, payload, &mut frame)
        .map_err(|error| error.to_string())?;
    receiver
        .decode(&frame, unix_us()?)
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

fn profile() -> Result<RangeProfile, String> {
    RangeProfile::new(
        SQL,
        OperationBinding::new(65, 650).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn identity(profile: RangeProfile) -> Result<BackendIdentity, String> {
    profile
        .identity(schema_digest(), policy_digest())
        .map_err(|error| error.to_string())
}

fn authority(identity: BackendIdentity, session: u64) -> Result<Authority, String> {
    let context = AuthorityContext::new(
        *b"pgtrans-tenant01",
        *b"pgtrans-reader01",
        1,
        digest_label(
            b"ndabi/postgresql/transport/capability/v1",
            b"read:ndabi_v65_items:ordered-range",
        ),
        identity,
    )
    .map_err(|error| error.to_string())?;
    Authority::new_read([65; 32], 1, session, EXPIRY_UNIX_US, context)
        .map_err(|error| error.to_string())
}

fn connect_backend(connection: &str, profile: RangeProfile) -> Result<RangeBackend, String> {
    let client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    RangeBackend::new(client, profile, schema_digest(), policy_digest())
        .map_err(|error| error.to_string())
}

fn schema_digest() -> [u8; 32] {
    digest_label(
        b"ndabi/postgresql/transport/schema/v1",
        b"ndabi_v65_items(id:i64,bucket:i32,owner:i32,score:i32,payload:bytes64)",
    )
}

fn policy_digest() -> [u8; 32] {
    digest_label(
        b"ndabi/postgresql/transport/policy/v1",
        b"select-only;fixed-table;fixed-projection;ascending-range",
    )
}

fn expected_rows(start: i64, rows: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(6 + rows as usize * 84);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&rows.to_le_bytes());
    for offset in 0..i64::from(rows) {
        let id = start + offset;
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.extend_from_slice(&((id % 1_000) as i32).to_le_bytes());
        bytes.extend_from_slice(&((id % 100) as i32).to_le_bytes());
        bytes.extend_from_slice(&((id % 10_000) as i32).to_le_bytes());
        bytes.extend_from_slice(&[(id % 256) as u8; 64]);
    }
    bytes
}

fn encode_rows(rows: &[Row], ids: &[i64]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(6 + ids.len() * 84);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for (row, expected_id) in rows.iter().zip(ids) {
        let id: i64 = row.try_get(0).map_err(|error| error.to_string())?;
        let bucket: i32 = row.try_get(1).map_err(|error| error.to_string())?;
        let owner: i32 = row.try_get(2).map_err(|error| error.to_string())?;
        let score: i32 = row.try_get(3).map_err(|error| error.to_string())?;
        let payload: Vec<u8> = row.try_get(4).map_err(|error| error.to_string())?;
        if id != *expected_id || payload.len() != 64 {
            return Err("the native row changed".to_string());
        }
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.extend_from_slice(&bucket.to_le_bytes());
        bytes.extend_from_slice(&owner.to_le_bytes());
        bytes.extend_from_slice(&score.to_le_bytes());
        bytes.extend_from_slice(&payload);
    }
    Ok(bytes)
}

fn summarise(arm: Arm, samples: Vec<Sample>) -> Measurement {
    let wall = samples
        .iter()
        .map(|sample| sample.wall_ns)
        .collect::<Vec<_>>();
    let cpu = samples
        .iter()
        .map(|sample| sample.cpu_ns)
        .collect::<Vec<_>>();
    Measurement {
        arm: arm.id(),
        p50_ns: percentile(&wall, 0.50),
        p95_ns: percentile(&wall, 0.95),
        p99_ns: percentile(&wall, 0.99),
        p50_cpu_ns: percentile(&cpu, 0.50),
        mean_allocations: mean(samples.iter().map(|sample| sample.allocation.allocations)),
        mean_allocated_bytes: mean(
            samples
                .iter()
                .map(|sample| sample.allocation.allocated_bytes),
        ),
        peak_additional_live_bytes: samples
            .iter()
            .map(|sample| sample.allocation.peak_additional_live_bytes)
            .max()
            .unwrap_or(0),
        raw_ns: wall,
        raw_cpu_ns: cpu,
    }
}

fn mean(values: impl Iterator<Item = u64>) -> f64 {
    let values = values.collect::<Vec<_>>();
    values.iter().sum::<u64>() as f64 / values.len() as f64
}

fn percentile(values: &[u64], quantile: f64) -> u64 {
    let mut ordered = values.to_vec();
    ordered.sort_unstable();
    let index = ((ordered.len() - 1) as f64 * quantile).ceil() as usize;
    ordered[index]
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    numerator as f64 / denominator as f64
}

fn elapsed_ns(started: Instant) -> Result<u64, String> {
    u64::try_from(started.elapsed().as_nanos()).map_err(|error| error.to_string())
}

fn deadline() -> Result<u64, String> {
    unix_us()?
        .checked_add(60_000_000)
        .ok_or_else(|| "the deadline overflowed".to_string())
}

fn unix_us() -> Result<u64, String> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_micros();
    u64::try_from(micros).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn thread_cpu_ns() -> Result<u64, String> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let status = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) };
    if status != 0 || time.tv_sec < 0 || time.tv_nsec < 0 {
        return Err("the thread CPU clock failed".to_string());
    }
    let seconds = u64::try_from(time.tv_sec).map_err(|error| error.to_string())?;
    let nanoseconds = u64::try_from(time.tv_nsec).map_err(|error| error.to_string())?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| "the thread CPU clock overflowed".to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("a string write cannot fail");
    }
    output
}
