//! Compare restart-scoped and resumable NDABI admission against equal native controls.
//!
//! Resumable arms advance replay state and execute the query in one PostgreSQL transaction.
//! Ephemeral arms rotate authority after a restart and avoid a durable write per request.

use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ndabi_showdown::alloc::{begin_measurement, end_measurement, AllocationDelta};
use ndabi_showdown::column_v03::{
    ColumnBatchFrame, ColumnBatchView, ColumnVerifier, OPERATION_IDEMPOTENT, OPERATION_READ,
};
use ndabi_showdown::replay_v01::ReplayIdentity;
use ndabi_showdown::session_v01::EphemeralEpoch;
use postgres::{Client, NoTls, Row, Statement, Transaction};
use serde::Serialize;
use sha2::{Digest, Sha256};

const ROWS: i64 = 100_000;
const BATCH_SIZES: [usize; 2] = [32, 128];
const SAMPLES: usize = 63;
const WARMUP: usize = 5;
const CONCURRENCY_LEVELS: [usize; 4] = [1, 8, 32, 128];
const CONCURRENT_SAMPLES: usize = 31;
const CONCURRENT_WARMUP: usize = 3;
const PAIRED_BLOCKS: usize = 9;
const PAIRED_REQUESTS_PER_BLOCK: usize = 7;
const SESSION_BASE: u32 = 0x3400_0000;
const CAPABILITY_HANDLE: u32 = 0x3400_1001;
const SCHEMA_HANDLE: u32 = 0x3400_2001;
const PLAN_HANDLE: u32 = 0x3400_3001;
const RESULT_SHAPE: u32 = 0x3400_4001;
const EPOCH_KEY: [u8; 32] = [0x34; 32];
const RESTARTED_KEY: [u8; 32] = [0x35; 32];
const RECEIPT_AUTHORITY: [u8; 32] = [0x74; 32];
const NATIVE_EPHEMERAL_PROFILE: u32 = 0x3400_0001;
const NATIVE_DURABLE_PROFILE: u32 = 0x3400_0002;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Arm {
    NativeEphemeral,
    NdabiEphemeral,
    NativeDurable,
    NdabiDurable,
}

impl Arm {
    const ALL: [Self; 4] = [
        Self::NativeEphemeral,
        Self::NdabiEphemeral,
        Self::NativeDurable,
        Self::NdabiDurable,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::NativeEphemeral => "native-ephemeral",
            Self::NdabiEphemeral => "ndabi-ephemeral",
            Self::NativeDurable => "native-resumable",
            Self::NdabiDurable => "ndabi-resumable",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::NativeEphemeral => 0,
            Self::NdabiEphemeral => 1,
            Self::NativeDurable => 2,
            Self::NdabiDurable => 3,
        }
    }
}

#[derive(Clone, Debug)]
struct Outcome {
    bytes: Vec<u8>,
    receipt: [u8; 32],
}

#[derive(Debug)]
struct Sample {
    elapsed_ns: u64,
    allocations: u64,
    allocated_bytes: u64,
    peak_additional_live_bytes: u64,
}

#[derive(Serialize)]
struct Measurement {
    id: &'static str,
    samples: usize,
    operations_per_batch: usize,
    median_batch_ns: u64,
    p95_batch_ns: u64,
    p99_batch_ns: u64,
    operations_per_second: f64,
    allocations_per_batch: f64,
    allocated_bytes_per_batch: f64,
    peak_additional_live_bytes: u64,
    raw_batch_ns: Vec<u64>,
}

#[derive(Serialize)]
struct Gate {
    id: String,
    passed: bool,
    observed: String,
    target: &'static str,
}

#[derive(Serialize)]
struct LatencyCase {
    batch_size: usize,
    frame_bytes: usize,
    canonical_sha256: String,
    receipt_sha256: String,
    measurements: Vec<Measurement>,
    ephemeral_distance: f64,
    resumable_distance: f64,
    gates: Vec<Gate>,
}

#[derive(Serialize)]
struct ConcurrencyMeasurement {
    id: &'static str,
    concurrency: usize,
    completed_requests: usize,
    p95_request_ns: u64,
    operations_per_second: f64,
    raw_request_ns: Vec<u64>,
}

#[derive(Serialize)]
struct ConcurrencyCase {
    concurrency: usize,
    measurements: Vec<ConcurrencyMeasurement>,
    ephemeral_throughput_ratio: f64,
    resumable_throughput_ratio: f64,
    ephemeral_p95_distance: f64,
    resumable_p95_distance: f64,
    gates: Vec<Gate>,
}

#[derive(Serialize)]
struct SecurityProof {
    restart_invalidated_old_frame: bool,
    killed_transaction_left_no_nonce: bool,
    committed_replay_refused: bool,
    borrowed_decode_allocations: u64,
    borrowed_decode_allocated_bytes: u64,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    status: &'static str,
    client_architecture: &'static str,
    client_operating_system: &'static str,
    generated_at_unix_seconds: u64,
    postgresql_version: String,
    rows: i64,
    latency_cases: Vec<LatencyCase>,
    concurrency_cases: Vec<ConcurrencyCase>,
    security: SecurityProof,
    hard_gate_passed: bool,
    limitations: [&'static str; 5],
}

#[derive(Serialize)]
struct PairedReport {
    schema: &'static str,
    status: &'static str,
    client_architecture: &'static str,
    client_operating_system: &'static str,
    generated_at_unix_seconds: u64,
    postgresql_version: String,
    rows: i64,
    latency_cases: Vec<LatencyCase>,
    concurrency_cases: Vec<ConcurrencyCase>,
    security: SecurityProof,
    correctness_gate_passed: bool,
    limitations: [&'static str; 5],
}

struct PairedWorkerResult {
    raw: [Vec<u64>; 4],
    arm_elapsed_ns: [u64; 4],
}

struct DatabaseState {
    client: Client,
    set: Statement,
    advance: Statement,
}

struct ProtocolSession {
    frames: Vec<Vec<u8>>,
    next_frame: usize,
    verifier: ColumnVerifier,
}

struct NativeSession {
    identity: ReplayIdentity,
    next_nonce: u64,
    last_nonce: u64,
    expires_unix_us: u64,
}

struct CaseState {
    ids: Vec<i64>,
    native_ephemeral: NativeSession,
    ndabi_ephemeral: ProtocolSession,
    native_durable: NativeSession,
    ndabi_durable: ProtocolSession,
    decoded_ids: Vec<i64>,
}

pub fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let connection = arguments
        .next()
        .ok_or_else(|| "supply the PostgreSQL connection string".to_string())?;
    let mode = arguments.next();
    if arguments.next().is_some() || !matches!(mode.as_deref(), None | Some("--prepare")) {
        return Err("use ndabi_v34 CONNECTION [--prepare]".into());
    }
    if mode.as_deref() == Some("--prepare") {
        prepare_database(&connection)?;
        println!("{{\"schema\":\"ndabi-postgresql-v3.4-prepare\",\"rows\":{ROWS}}}");
        return Ok(());
    }
    run_campaign(&connection)
}

pub fn run_v35() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let connection = arguments
        .next()
        .ok_or_else(|| "supply the PostgreSQL connection string".to_string())?;
    let mode = arguments.next();
    if arguments.next().is_some() || !matches!(mode.as_deref(), None | Some("--prepare")) {
        return Err("use ndabi_v35 CONNECTION [--prepare]".into());
    }
    if mode.as_deref() == Some("--prepare") {
        prepare_database(&connection)?;
        println!("{{\"schema\":\"ndabi-postgresql-v3.5-prepare\",\"rows\":{ROWS}}}");
        return Ok(());
    }
    run_paired_campaign(&connection)
}

fn run_paired_campaign(connection: &str) -> Result<(), String> {
    let generation = campaign_generation()?;
    let mut database = create_database(connection)?;
    let restart_invalidated_old_frame = prove_restart_invalidation(generation)?;
    let killed_transaction_left_no_nonce =
        prove_killed_transaction(connection, generation.saturating_add(1))?;
    let committed_replay_refused =
        prove_committed_replay(&mut database, generation.saturating_add(2))?;
    let decode_allocation = prove_borrowed_decode(generation.saturating_add(3))?;
    let mut latency_cases = Vec::with_capacity(BATCH_SIZES.len());
    for batch_size in BATCH_SIZES {
        latency_cases.push(run_latency_case(
            &mut database,
            batch_size,
            generation.saturating_add(u64::try_from(batch_size).expect("bounded batch")),
        )?);
    }
    let mut concurrency_cases = Vec::with_capacity(CONCURRENCY_LEVELS.len());
    for concurrency in CONCURRENCY_LEVELS {
        concurrency_cases.push(run_paired_concurrency_case(
            connection,
            concurrency,
            generation.saturating_add(
                20_000 + u64::try_from(concurrency).expect("bounded concurrency") * 1_000,
            ),
        )?);
    }
    let security = SecurityProof {
        restart_invalidated_old_frame,
        killed_transaction_left_no_nonce,
        committed_replay_refused,
        borrowed_decode_allocations: decode_allocation.allocations,
        borrowed_decode_allocated_bytes: decode_allocation.allocated_bytes,
    };
    let expected_requests = concurrency_expected_requests();
    let correctness_gate_passed = restart_invalidated_old_frame
        && killed_transaction_left_no_nonce
        && committed_replay_refused
        && decode_allocation.allocations == 0
        && decode_allocation.allocated_bytes == 0
        && concurrency_cases.iter().all(|case| {
            case.measurements.iter().all(|measurement| {
                measurement.completed_requests == case.concurrency * expected_requests
            })
        });
    let postgresql_version = database
        .client
        .query_one("SHOW server_version", &[])
        .map_err(|error| error.to_string())?
        .get::<_, String>(0);
    let report = PairedReport {
        schema: "ndabi-postgresql-paired-replay-v3.5",
        status: "paired-process-diagnostic",
        client_architecture: std::env::consts::ARCH,
        client_operating_system: std::env::consts::OS,
        generated_at_unix_seconds: now_unix_seconds()?,
        postgresql_version,
        rows: ROWS,
        latency_cases,
        concurrency_cases,
        security,
        correctness_gate_passed,
        limitations: [
            "Docker Desktop uses a Linux virtual machine, not physical Linux.",
            "The campaign uses a local container bridge without TLS.",
            "Each concurrent worker uses an independent replay identity.",
            "The PostgreSQL server allocation and energy costs remain unmeasured.",
            "The campaign excludes malicious rollback and multi-node replay state.",
        ],
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)
        .map_err(|error| error.to_string())?;
    println!();
    if correctness_gate_passed {
        Ok(())
    } else {
        Err("the v3.5 process correctness gate failed".into())
    }
}

fn run_campaign(connection: &str) -> Result<(), String> {
    let generation = campaign_generation()?;
    let mut database = create_database(connection)?;
    let restart_invalidated_old_frame = prove_restart_invalidation(generation)?;
    let killed_transaction_left_no_nonce =
        prove_killed_transaction(connection, generation.saturating_add(1))?;
    let committed_replay_refused =
        prove_committed_replay(&mut database, generation.saturating_add(2))?;
    let decode_allocation = prove_borrowed_decode(generation.saturating_add(3))?;

    let mut latency_cases = Vec::with_capacity(BATCH_SIZES.len());
    for batch_size in BATCH_SIZES {
        latency_cases.push(run_latency_case(
            &mut database,
            batch_size,
            generation.saturating_add(u64::try_from(batch_size).expect("bounded batch")),
        )?);
    }

    let mut concurrency_cases = Vec::with_capacity(CONCURRENCY_LEVELS.len());
    for concurrency in CONCURRENCY_LEVELS {
        concurrency_cases.push(run_concurrency_case(
            connection,
            concurrency,
            generation.saturating_add(
                10_000 + u64::try_from(concurrency).expect("bounded concurrency") * 1_000,
            ),
        )?);
    }

    let security = SecurityProof {
        restart_invalidated_old_frame,
        killed_transaction_left_no_nonce,
        committed_replay_refused,
        borrowed_decode_allocations: decode_allocation.allocations,
        borrowed_decode_allocated_bytes: decode_allocation.allocated_bytes,
    };
    let hard_gate_passed = restart_invalidated_old_frame
        && killed_transaction_left_no_nonce
        && committed_replay_refused
        && decode_allocation.allocations == 0
        && decode_allocation.allocated_bytes == 0
        && latency_cases
            .iter()
            .flat_map(|case| &case.gates)
            .all(|gate| gate.passed)
        && concurrency_cases
            .iter()
            .flat_map(|case| &case.gates)
            .all(|gate| gate.passed);
    let postgresql_version = database
        .client
        .query_one("SHOW server_version", &[])
        .map_err(|error| error.to_string())?
        .get::<_, String>(0);
    let report = Report {
        schema: "ndabi-postgresql-replay-v3.4",
        status: "local-diagnostic",
        client_architecture: std::env::consts::ARCH,
        client_operating_system: std::env::consts::OS,
        generated_at_unix_seconds: now_unix_seconds()?,
        postgresql_version,
        rows: ROWS,
        latency_cases,
        concurrency_cases,
        security,
        hard_gate_passed,
        limitations: [
            "Docker Desktop uses a Linux virtual machine, not physical Linux.",
            "The campaign uses a local container bridge without TLS.",
            "Each concurrent worker uses an independent replay identity.",
            "The PostgreSQL server allocation and energy costs remain unmeasured.",
            "The campaign excludes malicious rollback and multi-node replay state.",
        ],
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)
        .map_err(|error| error.to_string())?;
    println!();
    if hard_gate_passed {
        Ok(())
    } else {
        Err("the v3.4 hard gate failed".into())
    }
}

fn prepare_database(connection: &str) -> Result<(), String> {
    let mut client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS ndabi_v34_items (\
             id BIGINT PRIMARY KEY, bucket INTEGER NOT NULL, payload BYTEA NOT NULL);\
             CREATE TABLE IF NOT EXISTS ndabi_v34_replay (\
             profile BIGINT NOT NULL, session_handle BIGINT NOT NULL, \
             capability_handle BIGINT NOT NULL, schema_handle BIGINT NOT NULL, \
             generation BIGINT NOT NULL, nonce BIGINT NOT NULL, \
             PRIMARY KEY (profile, session_handle, capability_handle, schema_handle, generation));\
             TRUNCATE ndabi_v34_items, ndabi_v34_replay;\
             INSERT INTO ndabi_v34_items \
             SELECT value, (value % 1024)::INTEGER, decode(repeat(lpad(to_hex(value % 256), 2, '0'), 64), 'hex') \
             FROM generate_series(0, 99999) AS value;\
             ANALYZE ndabi_v34_items;\
             CHECKPOINT;",
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn create_database(connection: &str) -> Result<DatabaseState, String> {
    let mut client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    let row_count: i64 = client
        .query_one("SELECT COUNT(*) FROM ndabi_v34_items", &[])
        .map_err(|error| format!("prepare the v3.4 dataset before measurement: {error}"))?
        .get(0);
    if row_count != ROWS {
        return Err(format!(
            "the prepared dataset has {row_count} rows instead of {ROWS}"
        ));
    }
    let set = client
        .prepare(
            "SELECT item.id, item.bucket, item.payload \
             FROM unnest($1::bigint[]) WITH ORDINALITY AS request(id, ordinal) \
             JOIN ndabi_v34_items AS item ON item.id = request.id \
             ORDER BY request.ordinal",
        )
        .map_err(|error| error.to_string())?;
    let advance = client
        .prepare(
            "INSERT INTO ndabi_v34_replay \
             (profile, session_handle, capability_handle, schema_handle, generation, nonce) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (profile, session_handle, capability_handle, schema_handle, generation) \
             DO UPDATE SET nonce = EXCLUDED.nonce \
             WHERE ndabi_v34_replay.nonce < EXCLUDED.nonce \
             RETURNING nonce",
        )
        .map_err(|error| error.to_string())?;
    Ok(DatabaseState {
        client,
        set,
        advance,
    })
}

fn run_latency_case(
    database: &mut DatabaseState,
    batch_size: usize,
    generation: u64,
) -> Result<LatencyCase, String> {
    let mut case = create_case(batch_size, generation, WARMUP + SAMPLES)?;
    let expected = execute_set(database, &case.ids)?;
    let mut samples: [Vec<Sample>; 4] = std::array::from_fn(|_| Vec::with_capacity(SAMPLES));

    for cycle in 0..WARMUP {
        for offset in 0..Arm::ALL.len() {
            let arm = Arm::ALL[(cycle + offset) % Arm::ALL.len()];
            let outcome = execute_arm(database, &mut case, arm)?;
            require_equal(&expected, &outcome, arm)?;
        }
    }
    for cycle in 0..SAMPLES {
        for offset in 0..Arm::ALL.len() {
            let arm = Arm::ALL[(cycle + offset) % Arm::ALL.len()];
            let allocation_start = begin_measurement();
            let started = Instant::now();
            let outcome = execute_arm(database, &mut case, arm)?;
            let elapsed_ns = elapsed_ns(started);
            let allocation = end_measurement(allocation_start);
            require_equal(&expected, &outcome, arm)?;
            black_box(outcome);
            samples[arm.index()].push(Sample {
                elapsed_ns,
                allocations: allocation.allocations,
                allocated_bytes: allocation.allocated_bytes,
                peak_additional_live_bytes: allocation.peak_additional_live_bytes,
            });
        }
    }

    let measurements = Arm::ALL
        .iter()
        .map(|arm| finish(*arm, batch_size, &samples[arm.index()]))
        .collect::<Vec<_>>();
    let native_ephemeral = measurement(&measurements, Arm::NativeEphemeral.id())?;
    let ndabi_ephemeral = measurement(&measurements, Arm::NdabiEphemeral.id())?;
    let native_durable = measurement(&measurements, Arm::NativeDurable.id())?;
    let ndabi_durable = measurement(&measurements, Arm::NdabiDurable.id())?;
    let ephemeral_distance = ratio(ndabi_ephemeral.p95_batch_ns, native_ephemeral.p95_batch_ns);
    let resumable_distance = ratio(ndabi_durable.p95_batch_ns, native_durable.p95_batch_ns);
    let gates = vec![
        Gate {
            id: "ephemeral-native-distance".into(),
            passed: ephemeral_distance <= 1.05,
            observed: format!("{ephemeral_distance:.4}x"),
            target: "no more than 1.05x",
        },
        Gate {
            id: "resumable-native-distance".into(),
            passed: resumable_distance <= 1.10,
            observed: format!("{resumable_distance:.4}x"),
            target: "no more than 1.10x",
        },
        Gate {
            id: "literal-result-and-receipt-equality".into(),
            passed: true,
            observed: hex(&Sha256::digest(&expected.bytes)),
            target: "one byte-identical payload and receipt",
        },
    ];
    let frame_bytes = case
        .ndabi_ephemeral
        .frames
        .first()
        .ok_or_else(|| "the ephemeral frame is missing".to_string())?
        .len();
    Ok(LatencyCase {
        batch_size,
        frame_bytes,
        canonical_sha256: hex(&Sha256::digest(&expected.bytes)),
        receipt_sha256: hex(&expected.receipt),
        measurements,
        ephemeral_distance,
        resumable_distance,
        gates,
    })
}

fn create_case(
    batch_size: usize,
    generation: u64,
    frame_count: usize,
) -> Result<CaseState, String> {
    let start = ROWS - i64::try_from(batch_size).map_err(|error| error.to_string())?;
    let ids = (start..ROWS).collect::<Vec<_>>();
    let expires_unix_us = now_unix_us()?.saturating_add(600_000_000);
    let epoch = EphemeralEpoch::new(generation, EPOCH_KEY).map_err(|error| error.to_string())?;
    let ephemeral_handle = session_handle(batch_size, 1)?;
    let durable_handle = session_handle(batch_size, 2)?;
    let budget = u32::try_from(batch_size * 76).map_err(|error| error.to_string())?;
    let ephemeral = protocol_session(
        &epoch,
        ephemeral_handle,
        budget,
        expires_unix_us,
        &ids,
        frame_count,
    )?;
    let durable = protocol_session(
        &epoch,
        durable_handle,
        budget,
        expires_unix_us,
        &ids,
        frame_count,
    )?;
    Ok(CaseState {
        ids,
        native_ephemeral: NativeSession {
            identity: ReplayIdentity {
                profile: NATIVE_EPHEMERAL_PROFILE,
                session_handle: session_handle(batch_size, 3)?,
                capability_handle: CAPABILITY_HANDLE,
                schema_handle: SCHEMA_HANDLE,
                generation,
            },
            next_nonce: 1,
            last_nonce: 0,
            expires_unix_us,
        },
        ndabi_ephemeral: ephemeral,
        native_durable: NativeSession {
            identity: ReplayIdentity {
                profile: NATIVE_DURABLE_PROFILE,
                session_handle: session_handle(batch_size, 4)?,
                capability_handle: CAPABILITY_HANDLE,
                schema_handle: SCHEMA_HANDLE,
                generation,
            },
            next_nonce: 1,
            last_nonce: 0,
            expires_unix_us,
        },
        ndabi_durable: durable,
        decoded_ids: Vec::with_capacity(batch_size),
    })
}

fn protocol_session(
    epoch: &EphemeralEpoch,
    session_handle: u32,
    result_budget: u32,
    expires_unix_us: u64,
    ids: &[i64],
    frame_count: usize,
) -> Result<ProtocolSession, String> {
    let encode_binding = epoch
        .column_binding(
            session_handle,
            CAPABILITY_HANDLE,
            SCHEMA_HANDLE,
            result_budget,
            expires_unix_us,
        )
        .map_err(|error| error.to_string())?;
    let verifier_binding = epoch
        .column_binding(
            session_handle,
            CAPABILITY_HANDLE,
            SCHEMA_HANDLE,
            result_budget,
            expires_unix_us,
        )
        .map_err(|error| error.to_string())?;
    let parameters = ids
        .iter()
        .flat_map(|id| id.to_le_bytes())
        .collect::<Vec<_>>();
    let mut frames = Vec::with_capacity(frame_count);
    for index in 0..frame_count {
        frames.push(
            ColumnBatchFrame {
                flags: 0,
                session_handle,
                capability_handle: CAPABILITY_HANDLE,
                schema_handle: SCHEMA_HANDLE,
                generation: epoch.generation(),
                nonce: u64::try_from(index + 1).expect("bounded frame count"),
                deadline_unix_us: expires_unix_us,
                result_budget,
                plan_handle: PLAN_HANDLE,
                result_shape: RESULT_SHAPE,
                transaction_group: 0,
                operation_flags: OPERATION_READ | OPERATION_IDEMPOTENT,
                rows: u16::try_from(ids.len()).map_err(|error| error.to_string())?,
                columns: 1,
                row_bytes: 8,
                parameters: parameters.clone(),
            }
            .encode(&encode_binding)
            .map_err(|error| error.to_string())?,
        );
    }
    Ok(ProtocolSession {
        frames,
        next_frame: 0,
        verifier: ColumnVerifier::new(verifier_binding, 0),
    })
}

fn execute_arm(
    database: &mut DatabaseState,
    case: &mut CaseState,
    arm: Arm,
) -> Result<Outcome, String> {
    match arm {
        Arm::NativeEphemeral => {
            advance_native(&mut case.native_ephemeral)?;
            execute_set(database, &case.ids)
        }
        Arm::NdabiEphemeral => {
            let ProtocolSession {
                frames,
                next_frame,
                verifier,
            } = &mut case.ndabi_ephemeral;
            let frame = frames
                .get(*next_frame)
                .ok_or_else(|| "the ephemeral frame supply ended".to_string())?;
            *next_frame += 1;
            let view = verifier.verify(frame).map_err(|error| error.to_string())?;
            decode_ids(view, &mut case.decoded_ids)?;
            execute_set(database, &case.decoded_ids)
        }
        Arm::NativeDurable => {
            let nonce = advance_native_candidate(&case.native_durable)?;
            let outcome =
                execute_durable(database, case.native_durable.identity, nonce, &case.ids)?;
            case.native_durable.last_nonce = nonce;
            case.native_durable.next_nonce = nonce.saturating_add(1);
            Ok(outcome)
        }
        Arm::NdabiDurable => {
            let ProtocolSession {
                frames,
                next_frame,
                verifier,
            } = &mut case.ndabi_durable;
            let frame = frames
                .get(*next_frame)
                .ok_or_else(|| "the resumable frame supply ended".to_string())?;
            *next_frame += 1;
            let pending = verifier
                .verify_pending_at(frame, now_unix_us()?)
                .map_err(|error| error.to_string())?;
            decode_ids(pending.view(), &mut case.decoded_ids)?;
            let outcome = execute_durable(
                database,
                pending.identity(),
                pending.nonce(),
                &case.decoded_ids,
            )?;
            verifier
                .commit_pending(pending)
                .map_err(|error| error.to_string())?;
            Ok(outcome)
        }
    }
}

fn advance_native(session: &mut NativeSession) -> Result<(), String> {
    let nonce = advance_native_candidate(session)?;
    session.last_nonce = nonce;
    session.next_nonce = nonce.saturating_add(1);
    Ok(())
}

fn advance_native_candidate(session: &NativeSession) -> Result<u64, String> {
    if session.expires_unix_us <= now_unix_us()? {
        return Err("the native session expired".into());
    }
    if session.next_nonce == 0 || session.next_nonce <= session.last_nonce {
        return Err("the native session replayed a nonce".into());
    }
    Ok(session.next_nonce)
}

fn decode_ids(view: ColumnBatchView<'_>, output: &mut Vec<i64>) -> Result<(), String> {
    if view.plan_handle() != PLAN_HANDLE
        || view.result_shape() != RESULT_SHAPE
        || view.columns() != 1
        || view.row_bytes() != 8
    {
        return Err("the column batch profile changed".into());
    }
    output.clear();
    for index in 0..view.rows() {
        let bytes = view
            .row(index)
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "an NDABI identifier has the wrong size".to_string())?;
        output.push(i64::from_le_bytes(bytes));
    }
    Ok(())
}

fn execute_set(database: &mut DatabaseState, ids: &[i64]) -> Result<Outcome, String> {
    let rows = database
        .client
        .query(&database.set, &[&ids])
        .map_err(|error| error.to_string())?;
    canonical(&rows)
}

fn execute_durable(
    database: &mut DatabaseState,
    identity: ReplayIdentity,
    nonce: u64,
    ids: &[i64],
) -> Result<Outcome, String> {
    let DatabaseState {
        client,
        set,
        advance,
    } = database;
    let mut transaction = client.transaction().map_err(|error| error.to_string())?;
    advance_transaction(&mut transaction, advance, identity, nonce)?;
    let rows = transaction
        .query(set, &[&ids])
        .map_err(|error| error.to_string())?;
    let outcome = canonical(&rows)?;
    transaction.commit().map_err(|error| error.to_string())?;
    Ok(outcome)
}

fn advance_transaction(
    transaction: &mut Transaction<'_>,
    statement: &Statement,
    identity: ReplayIdentity,
    nonce: u64,
) -> Result<(), String> {
    let values = replay_values(identity, nonce)?;
    let row = transaction
        .query_opt(
            statement,
            &[
                &values[0], &values[1], &values[2], &values[3], &values[4], &values[5],
            ],
        )
        .map_err(|error| error.to_string())?;
    if row.is_none() {
        return Err("PostgreSQL refused a replayed nonce".into());
    }
    Ok(())
}

fn replay_values(identity: ReplayIdentity, nonce: u64) -> Result<[i64; 6], String> {
    Ok([
        i64::from(identity.profile),
        i64::from(identity.session_handle),
        i64::from(identity.capability_handle),
        i64::from(identity.schema_handle),
        i64::try_from(identity.generation).map_err(|error| error.to_string())?,
        i64::try_from(nonce).map_err(|error| error.to_string())?,
    ])
}

fn canonical(rows: &[Row]) -> Result<Outcome, String> {
    let mut bytes = Vec::with_capacity(rows.len() * 76);
    for row in rows {
        let id: i64 = row.get(0);
        let bucket: i32 = row.get(1);
        let payload: Vec<u8> = row.get(2);
        if payload.len() != 64 {
            return Err("the PostgreSQL payload length changed".into());
        }
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.extend_from_slice(&bucket.to_le_bytes());
        bytes.extend_from_slice(&payload);
    }
    let mut receipt = Sha256::new();
    receipt.update(b"ndabi/postgresql/replay-receipt/v1");
    receipt.update(RECEIPT_AUTHORITY);
    receipt.update(Sha256::digest(&bytes));
    Ok(Outcome {
        bytes,
        receipt: receipt.finalize().into(),
    })
}

fn run_concurrency_case(
    connection: &str,
    concurrency: usize,
    generation: u64,
) -> Result<ConcurrencyCase, String> {
    let mut measurements = Vec::with_capacity(Arm::ALL.len());
    for arm in Arm::ALL {
        measurements.push(run_concurrent_arm(
            connection,
            arm,
            concurrency,
            generation.saturating_add(u64::try_from(arm.index()).expect("bounded arm") * 100),
        )?);
    }
    let native_ephemeral = concurrency_measurement(&measurements, Arm::NativeEphemeral.id())?;
    let ndabi_ephemeral = concurrency_measurement(&measurements, Arm::NdabiEphemeral.id())?;
    let native_durable = concurrency_measurement(&measurements, Arm::NativeDurable.id())?;
    let ndabi_durable = concurrency_measurement(&measurements, Arm::NdabiDurable.id())?;
    let ephemeral_throughput_ratio =
        ndabi_ephemeral.operations_per_second / native_ephemeral.operations_per_second;
    let resumable_throughput_ratio =
        ndabi_durable.operations_per_second / native_durable.operations_per_second;
    let ephemeral_p95_distance = ratio(
        ndabi_ephemeral.p95_request_ns,
        native_ephemeral.p95_request_ns,
    );
    let resumable_p95_distance = ratio(ndabi_durable.p95_request_ns, native_durable.p95_request_ns);
    let expected = concurrency * CONCURRENT_SAMPLES;
    let gates = vec![
        Gate {
            id: "complete-workers".into(),
            passed: measurements
                .iter()
                .all(|measurement| measurement.completed_requests == expected),
            observed: format!("{expected} requests per arm"),
            target: "every registered request",
        },
        Gate {
            id: "ephemeral-throughput-distance".into(),
            passed: ephemeral_throughput_ratio >= 0.90,
            observed: format!("{ephemeral_throughput_ratio:.4}x"),
            target: "at least 0.90x",
        },
        Gate {
            id: "resumable-throughput-distance".into(),
            passed: resumable_throughput_ratio >= 0.90,
            observed: format!("{resumable_throughput_ratio:.4}x"),
            target: "at least 0.90x",
        },
        Gate {
            id: "ephemeral-p95-distance".into(),
            passed: ephemeral_p95_distance <= 1.15,
            observed: format!("{ephemeral_p95_distance:.4}x"),
            target: "no more than 1.15x",
        },
        Gate {
            id: "resumable-p95-distance".into(),
            passed: resumable_p95_distance <= 1.15,
            observed: format!("{resumable_p95_distance:.4}x"),
            target: "no more than 1.15x",
        },
    ];
    Ok(ConcurrencyCase {
        concurrency,
        measurements,
        ephemeral_throughput_ratio,
        resumable_throughput_ratio,
        ephemeral_p95_distance,
        resumable_p95_distance,
        gates,
    })
}

fn run_paired_concurrency_case(
    connection: &str,
    concurrency: usize,
    generation: u64,
) -> Result<ConcurrencyCase, String> {
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut handles = Vec::with_capacity(concurrency);
    for worker in 0..concurrency {
        let connection = connection.to_string();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            run_paired_worker(&connection, worker, generation, barrier)
        }));
    }
    barrier.wait();
    let mut workers = Vec::with_capacity(concurrency);
    for handle in handles {
        workers.push(
            handle
                .join()
                .map_err(|_| "a paired concurrency worker panicked".to_string())??,
        );
    }

    let expected_per_worker = concurrency_expected_requests();
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
            concurrency,
            completed_requests,
            p95_request_ns: percentile(&raw, 0.95),
            operations_per_second: operations as f64
                / (critical_ns.max(1) as f64 / 1_000_000_000.0),
            raw_request_ns: raw,
        });
    }
    let native_ephemeral = concurrency_measurement(&measurements, Arm::NativeEphemeral.id())?;
    let ndabi_ephemeral = concurrency_measurement(&measurements, Arm::NdabiEphemeral.id())?;
    let native_durable = concurrency_measurement(&measurements, Arm::NativeDurable.id())?;
    let ndabi_durable = concurrency_measurement(&measurements, Arm::NdabiDurable.id())?;
    let ephemeral_throughput_ratio =
        ndabi_ephemeral.operations_per_second / native_ephemeral.operations_per_second;
    let resumable_throughput_ratio =
        ndabi_durable.operations_per_second / native_durable.operations_per_second;
    let ephemeral_p95_distance = ratio(
        ndabi_ephemeral.p95_request_ns,
        native_ephemeral.p95_request_ns,
    );
    let resumable_p95_distance = ratio(ndabi_durable.p95_request_ns, native_durable.p95_request_ns);
    let expected = concurrency * expected_per_worker;
    let gates = vec![
        Gate {
            id: "complete-workers".into(),
            passed: measurements
                .iter()
                .all(|measurement| measurement.completed_requests == expected),
            observed: format!("{expected} requests per arm"),
            target: "every registered request",
        },
        Gate {
            id: "ephemeral-throughput-distance".into(),
            passed: ephemeral_throughput_ratio >= 0.90,
            observed: format!("{ephemeral_throughput_ratio:.4}x"),
            target: "at least 0.90x",
        },
        Gate {
            id: "resumable-throughput-distance".into(),
            passed: resumable_throughput_ratio >= 0.90,
            observed: format!("{resumable_throughput_ratio:.4}x"),
            target: "at least 0.90x",
        },
        Gate {
            id: "ephemeral-p95-distance".into(),
            passed: ephemeral_p95_distance <= 1.15,
            observed: format!("{ephemeral_p95_distance:.4}x"),
            target: "no more than 1.15x",
        },
        Gate {
            id: "resumable-p95-distance".into(),
            passed: resumable_p95_distance <= 1.15,
            observed: format!("{resumable_p95_distance:.4}x"),
            target: "no more than 1.15x",
        },
    ];
    Ok(ConcurrencyCase {
        concurrency,
        measurements,
        ephemeral_throughput_ratio,
        resumable_throughput_ratio,
        ephemeral_p95_distance,
        resumable_p95_distance,
        gates,
    })
}

fn run_paired_worker(
    connection: &str,
    worker: usize,
    generation: u64,
    barrier: Arc<Barrier>,
) -> Result<PairedWorkerResult, String> {
    let prepared = (|| {
        let worker_generation =
            generation.saturating_add(u64::try_from(worker).expect("bounded worker"));
        let mut database = create_database(connection)?;
        let frame_count = CONCURRENT_WARMUP + concurrency_expected_requests();
        let mut case = create_case(32, worker_generation, frame_count)?;
        offset_paired_worker_identities(&mut case, worker)?;
        let expected = execute_set(&mut database, &case.ids)?;
        for cycle in 0..CONCURRENT_WARMUP {
            for offset in 0..Arm::ALL.len() {
                let arm = Arm::ALL[(cycle + offset) % Arm::ALL.len()];
                let outcome = execute_arm(&mut database, &mut case, arm)?;
                require_equal(&expected, &outcome, arm)?;
            }
        }
        Ok::<_, String>((database, case, expected))
    })();
    barrier.wait();
    let (mut database, mut case, expected) = prepared?;
    let mut raw: [Vec<u64>; 4] =
        std::array::from_fn(|_| Vec::with_capacity(concurrency_expected_requests()));
    let mut arm_elapsed_ns = [0u64; 4];
    for block in 0..PAIRED_BLOCKS {
        for offset in 0..Arm::ALL.len() {
            let arm = Arm::ALL[(block + offset) % Arm::ALL.len()];
            let block_started = Instant::now();
            for _ in 0..PAIRED_REQUESTS_PER_BLOCK {
                let started = Instant::now();
                let outcome = execute_arm(&mut database, &mut case, arm)?;
                raw[arm.index()].push(elapsed_ns(started));
                require_equal(&expected, &outcome, arm)?;
            }
            arm_elapsed_ns[arm.index()] =
                arm_elapsed_ns[arm.index()].saturating_add(elapsed_ns(block_started));
        }
    }
    Ok(PairedWorkerResult {
        raw,
        arm_elapsed_ns,
    })
}

fn offset_paired_worker_identities(case: &mut CaseState, worker: usize) -> Result<(), String> {
    let offset = u32::try_from(worker)
        .map_err(|error| error.to_string())?
        .checked_mul(16)
        .ok_or_else(|| "the paired worker offset overflowed".to_string())?;
    case.native_ephemeral.identity.session_handle = case
        .native_ephemeral
        .identity
        .session_handle
        .checked_add(offset)
        .ok_or_else(|| "the ephemeral session handle overflowed".to_string())?;
    case.native_durable.identity.session_handle = case
        .native_durable
        .identity
        .session_handle
        .checked_add(offset)
        .ok_or_else(|| "the resumable session handle overflowed".to_string())?;
    Ok(())
}

fn concurrency_expected_requests() -> usize {
    PAIRED_BLOCKS * PAIRED_REQUESTS_PER_BLOCK
}

fn run_concurrent_arm(
    connection: &str,
    arm: Arm,
    concurrency: usize,
    generation: u64,
) -> Result<ConcurrencyMeasurement, String> {
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut handles = Vec::with_capacity(concurrency);
    for worker in 0..concurrency {
        let connection = connection.to_string();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            run_worker(&connection, arm, worker, generation, barrier)
        }));
    }
    barrier.wait();
    let started = Instant::now();
    let mut raw = Vec::with_capacity(concurrency * CONCURRENT_SAMPLES);
    for handle in handles {
        let worker = handle
            .join()
            .map_err(|_| "a concurrency worker panicked".to_string())??;
        raw.extend(worker);
    }
    let wall_seconds = started.elapsed().as_secs_f64();
    raw.sort_unstable();
    let completed_requests = raw.len();
    Ok(ConcurrencyMeasurement {
        id: arm.id(),
        concurrency,
        completed_requests,
        p95_request_ns: percentile(&raw, 0.95),
        operations_per_second: (completed_requests * 32) as f64 / wall_seconds,
        raw_request_ns: raw,
    })
}

fn run_worker(
    connection: &str,
    arm: Arm,
    worker: usize,
    generation: u64,
    barrier: Arc<Barrier>,
) -> Result<Vec<u64>, String> {
    let prepared = (|| {
        let worker_generation =
            generation.saturating_add(u64::try_from(worker).expect("bounded worker"));
        let mut database = create_database(connection)?;
        let mut case = create_case(
            32,
            worker_generation,
            CONCURRENT_WARMUP + CONCURRENT_SAMPLES,
        )?;
        offset_worker_identities(&mut case, worker, arm)?;
        let expected = execute_set(&mut database, &case.ids)?;
        for _ in 0..CONCURRENT_WARMUP {
            let outcome = execute_arm(&mut database, &mut case, arm)?;
            require_equal(&expected, &outcome, arm)?;
        }
        Ok::<_, String>((database, case, expected))
    })();
    barrier.wait();
    let (mut database, mut case, expected) = prepared?;
    let mut elapsed = Vec::with_capacity(CONCURRENT_SAMPLES);
    for _ in 0..CONCURRENT_SAMPLES {
        let started = Instant::now();
        let outcome = execute_arm(&mut database, &mut case, arm)?;
        elapsed.push(elapsed_ns(started));
        require_equal(&expected, &outcome, arm)?;
    }
    Ok(elapsed)
}

fn offset_worker_identities(case: &mut CaseState, worker: usize, arm: Arm) -> Result<(), String> {
    let offset = u32::try_from(worker)
        .map_err(|error| error.to_string())?
        .checked_mul(16)
        .and_then(|value| value.checked_add(u32::try_from(arm.index()).ok()?))
        .ok_or_else(|| "the worker session offset overflowed".to_string())?;
    match arm {
        Arm::NativeEphemeral => {
            case.native_ephemeral.identity.session_handle = case
                .native_ephemeral
                .identity
                .session_handle
                .checked_add(offset)
                .ok_or_else(|| "the native session handle overflowed".to_string())?;
        }
        Arm::NativeDurable => {
            case.native_durable.identity.session_handle = case
                .native_durable
                .identity
                .session_handle
                .checked_add(offset)
                .ok_or_else(|| "the durable session handle overflowed".to_string())?;
        }
        Arm::NdabiEphemeral | Arm::NdabiDurable => {}
    }
    Ok(())
}

fn prove_restart_invalidation(generation: u64) -> Result<bool, String> {
    let old_epoch =
        EphemeralEpoch::new(generation, EPOCH_KEY).map_err(|error| error.to_string())?;
    let old_binding = old_epoch
        .column_binding(
            SESSION_BASE + 1,
            CAPABILITY_HANDLE,
            SCHEMA_HANDLE,
            152,
            u64::MAX,
        )
        .map_err(|error| error.to_string())?;
    let frame = ColumnBatchFrame {
        flags: 0,
        session_handle: SESSION_BASE + 1,
        capability_handle: CAPABILITY_HANDLE,
        schema_handle: SCHEMA_HANDLE,
        generation,
        nonce: 1,
        deadline_unix_us: u64::MAX,
        result_budget: 152,
        plan_handle: PLAN_HANDLE,
        result_shape: RESULT_SHAPE,
        transaction_group: 0,
        operation_flags: OPERATION_READ | OPERATION_IDEMPOTENT,
        rows: 2,
        columns: 1,
        row_bytes: 8,
        parameters: [1i64.to_le_bytes(), 2i64.to_le_bytes()].concat(),
    }
    .encode(&old_binding)
    .map_err(|error| error.to_string())?;
    let restarted = EphemeralEpoch::new(generation.saturating_add(1), RESTARTED_KEY)
        .map_err(|error| error.to_string())?;
    let restarted_binding = restarted
        .column_binding(
            SESSION_BASE + 1,
            CAPABILITY_HANDLE,
            SCHEMA_HANDLE,
            152,
            u64::MAX,
        )
        .map_err(|error| error.to_string())?;
    Ok(ColumnVerifier::new(restarted_binding, 0)
        .verify(&frame)
        .is_err())
}

fn prove_killed_transaction(connection: &str, generation: u64) -> Result<bool, String> {
    let identity = proof_identity(generation, 0x51);
    clear_identity(connection, identity)?;
    let mut victim = create_database(connection)?;
    let mut killer = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    let backend_pid: i32 = victim
        .client
        .query_one("SELECT pg_backend_pid()", &[])
        .map_err(|error| error.to_string())?
        .get(0);
    let DatabaseState {
        client, advance, ..
    } = &mut victim;
    let mut transaction = client.transaction().map_err(|error| error.to_string())?;
    advance_transaction(&mut transaction, advance, identity, 1)?;
    let terminated: bool = killer
        .query_one("SELECT pg_terminate_backend($1)", &[&backend_pid])
        .map_err(|error| error.to_string())?
        .get(0);
    drop(transaction);
    drop(victim);
    let count = replay_count(&mut killer, identity)?;
    Ok(terminated && count == 0)
}

fn prove_committed_replay(database: &mut DatabaseState, generation: u64) -> Result<bool, String> {
    let identity = proof_identity(generation, 0x52);
    let ids = [ROWS - 2, ROWS - 1];
    let first = execute_durable(database, identity, 1, &ids)?;
    black_box(first);
    Ok(execute_durable(database, identity, 1, &ids).is_err())
}

fn clear_identity(connection: &str, identity: ReplayIdentity) -> Result<(), String> {
    let mut client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    let values = replay_values(identity, 1)?;
    client
        .execute(
            "DELETE FROM ndabi_v34_replay WHERE profile=$1 AND session_handle=$2 \
             AND capability_handle=$3 AND schema_handle=$4 AND generation=$5",
            &[&values[0], &values[1], &values[2], &values[3], &values[4]],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn replay_count(client: &mut Client, identity: ReplayIdentity) -> Result<i64, String> {
    let values = replay_values(identity, 1)?;
    Ok(client
        .query_one(
            "SELECT COUNT(*) FROM ndabi_v34_replay WHERE profile=$1 AND session_handle=$2 \
             AND capability_handle=$3 AND schema_handle=$4 AND generation=$5",
            &[&values[0], &values[1], &values[2], &values[3], &values[4]],
        )
        .map_err(|error| error.to_string())?
        .get(0))
}

fn proof_identity(generation: u64, suffix: u32) -> ReplayIdentity {
    ReplayIdentity {
        profile: NATIVE_DURABLE_PROFILE,
        session_handle: SESSION_BASE + suffix,
        capability_handle: CAPABILITY_HANDLE,
        schema_handle: SCHEMA_HANDLE,
        generation,
    }
}

fn prove_borrowed_decode(generation: u64) -> Result<AllocationDelta, String> {
    let mut case = create_case(128, generation, 1)?;
    let frame = case
        .ndabi_ephemeral
        .frames
        .first()
        .ok_or_else(|| "the allocation frame is missing".to_string())?;
    let allocation_start = begin_measurement();
    let view = case
        .ndabi_ephemeral
        .verifier
        .verify(frame)
        .map_err(|error| error.to_string())?;
    let mut checksum = 0u64;
    for index in 0..view.rows() {
        checksum ^= u64::try_from(view.row(index).map_err(|error| error.to_string())?.len())
            .unwrap_or(u64::MAX);
    }
    black_box(checksum);
    Ok(end_measurement(allocation_start))
}

fn finish(arm: Arm, operations: usize, samples: &[Sample]) -> Measurement {
    let mut elapsed = samples
        .iter()
        .map(|sample| sample.elapsed_ns)
        .collect::<Vec<_>>();
    elapsed.sort_unstable();
    let total_ns = elapsed.iter().map(|value| u128::from(*value)).sum::<u128>();
    let total_operations = (samples.len() * operations) as f64;
    Measurement {
        id: arm.id(),
        samples: samples.len(),
        operations_per_batch: operations,
        median_batch_ns: percentile(&elapsed, 0.50),
        p95_batch_ns: percentile(&elapsed, 0.95),
        p99_batch_ns: percentile(&elapsed, 0.99),
        operations_per_second: total_operations / (total_ns as f64 / 1_000_000_000.0),
        allocations_per_batch: samples.iter().map(|sample| sample.allocations).sum::<u64>() as f64
            / samples.len() as f64,
        allocated_bytes_per_batch: samples
            .iter()
            .map(|sample| sample.allocated_bytes)
            .sum::<u64>() as f64
            / samples.len() as f64,
        peak_additional_live_bytes: samples
            .iter()
            .map(|sample| sample.peak_additional_live_bytes)
            .max()
            .unwrap_or(0),
        raw_batch_ns: elapsed,
    }
}

fn measurement<'a>(values: &'a [Measurement], id: &str) -> Result<&'a Measurement, String> {
    values
        .iter()
        .find(|value| value.id == id)
        .ok_or_else(|| format!("missing measurement {id}"))
}

fn concurrency_measurement<'a>(
    values: &'a [ConcurrencyMeasurement],
    id: &str,
) -> Result<&'a ConcurrencyMeasurement, String> {
    values
        .iter()
        .find(|value| value.id == id)
        .ok_or_else(|| format!("missing concurrency measurement {id}"))
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

fn session_handle(batch_size: usize, suffix: u32) -> Result<u32, String> {
    SESSION_BASE
        .checked_add(u32::try_from(batch_size).map_err(|error| error.to_string())? * 16)
        .and_then(|value| value.checked_add(suffix))
        .ok_or_else(|| "the session handle overflowed".to_string())
}

fn campaign_generation() -> Result<u64, String> {
    now_unix_us()?
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(u64::from(std::process::id())))
        .ok_or_else(|| "the campaign generation overflowed".to_string())
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

fn percentile(sorted: &[u64], quantile: f64) -> u64 {
    sorted[((sorted.len() - 1) as f64 * quantile).ceil() as usize]
}

fn ratio(left: u64, right: u64) -> f64 {
    left as f64 / right.max(1) as f64
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
    fn every_latency_case_has_independent_replay_identities() {
        let case = create_case(32, 17, WARMUP + SAMPLES).expect("create case");
        assert_ne!(case.native_ephemeral.identity, case.native_durable.identity);
        assert_ne!(case.ndabi_ephemeral.verifier.last_nonce(), u64::MAX);
        assert_eq!(case.ndabi_ephemeral.frames.len(), WARMUP + SAMPLES);
        assert_eq!(case.ndabi_durable.frames.len(), WARMUP + SAMPLES);
    }

    #[test]
    fn restart_proof_refuses_the_old_frame() {
        assert!(prove_restart_invalidation(17).expect("restart proof"));
    }
}
