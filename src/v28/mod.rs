//! Measure operation fusion against a real PostgreSQL engine.
//!
//! Every arm returns the same canonical bytes and receipt.
//! Native set and pipeline arms retain the optimisations available to NDABI.

use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use ndabi_showdown::alloc::{begin_measurement, end_measurement};
use ndabi_showdown::core_v01::{
    plan_execution_view, BackendCapabilities, ExecutionStrategy, Frame, FrameKind, Operation,
    SessionBinding, SessionVerifier, OPERATION_IDEMPOTENT, OPERATION_READ,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, NoTls, Row, Statement};

const ROWS: i64 = 100_000;
const BATCH_SIZES: [usize; 3] = [8, 32, 128];
const SAMPLES: usize = 63;
const WARMUP: usize = 5;
const SESSION_BASE: u32 = 0x2700_0000;
const CAPABILITY_HANDLE: u32 = 0x2700_1001;
const SCHEMA_HANDLE: u32 = 0x2700_2001;
const PLAN_HANDLE: u32 = 0x2700_3001;
const RESULT_SHAPE: u32 = 0x2700_4001;
const FRAME_KEY: [u8; 32] = [0x27; 32];
const RECEIPT_AUTHORITY: [u8; 32] = [0x72; 32];

#[derive(Clone, Copy, Debug)]
enum Arm {
    SequentialPrepared,
    NativeSet,
    NativePipeline,
    NdabiSet,
}

impl Arm {
    const ALL: [Self; 4] = [
        Self::SequentialPrepared,
        Self::NativeSet,
        Self::NativePipeline,
        Self::NdabiSet,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::SequentialPrepared => "sequential-prepared",
            Self::NativeSet => "native-set",
            Self::NativePipeline => "native-pipeline",
            Self::NdabiSet => "ndabi-set",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::SequentialPrepared => 0,
            Self::NativeSet => 1,
            Self::NativePipeline => 2,
            Self::NdabiSet => 3,
        }
    }
}

#[derive(Debug)]
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
    p95_ns_per_operation: f64,
    operations_per_second: f64,
    allocations_per_batch: f64,
    allocated_bytes_per_batch: f64,
    peak_additional_live_bytes: u64,
    raw_batch_ns: Vec<u64>,
}

#[derive(Serialize)]
struct Ratios {
    sequential_over_ndabi_p95: f64,
    ndabi_over_native_set_p95: f64,
    pipeline_over_native_set_p95: f64,
}

#[derive(Serialize)]
struct Gate {
    id: String,
    passed: bool,
    observed: String,
    target: &'static str,
}

#[derive(Serialize)]
struct CaseReport {
    batch_size: usize,
    canonical_sha256: String,
    receipt_sha256: String,
    measurements: Vec<Measurement>,
    ratios: Ratios,
    gates: Vec<Gate>,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    status: &'static str,
    generated_at_unix_seconds: u64,
    postgresql_version: String,
    rows: i64,
    cases: Vec<CaseReport>,
    borrowed_decode_allocations: u64,
    borrowed_decode_allocated_bytes: u64,
    hard_gate_passed: bool,
    limitations: [&'static str; 5],
}

struct DatabaseState {
    client: Client,
    point: Statement,
    set: Statement,
}

struct CaseState {
    ids: Vec<i64>,
    frames: Vec<Vec<u8>>,
    next_frame: usize,
    verifier: SessionVerifier,
    decoded_ids: Vec<i64>,
}

pub fn run() -> Result<(), String> {
    let connection = std::env::args()
        .nth(1)
        .ok_or_else(|| "supply the PostgreSQL connection string".to_string())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let decode_allocation = prove_borrowed_decode()?;
    runtime.block_on(run_async(&connection, decode_allocation))
}

async fn run_async(
    connection: &str,
    decode_allocation: ndabi_showdown::alloc::AllocationDelta,
) -> Result<(), String> {
    let mut database = create_database(connection).await?;
    prove_frame_refusals()?;
    let mut cases = Vec::with_capacity(BATCH_SIZES.len());
    for batch_size in BATCH_SIZES {
        cases.push(run_case(&mut database, batch_size).await?);
    }
    let hard_gate_passed = decode_allocation.allocations == 0
        && decode_allocation.allocated_bytes == 0
        && cases
            .iter()
            .flat_map(|case| case.gates.iter())
            .all(|gate| gate.passed);
    let postgresql_version = database
        .client
        .query_one("SHOW server_version", &[])
        .await
        .map_err(|error| error.to_string())?
        .get::<_, String>(0);
    let report = Report {
        schema: "ndabi-postgresql-borrowed-batch-v2.8",
        status: "local-docker-relative-diagnostic",
        generated_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs(),
        postgresql_version,
        rows: ROWS,
        cases,
        borrowed_decode_allocations: decode_allocation.allocations,
        borrowed_decode_allocated_bytes: decode_allocation.allocated_bytes,
        hard_gate_passed,
        limitations: [
            "Docker Desktop does not prove native Linux absolute latency.",
            "The campaign uses loopback TCP without TLS.",
            "The campaign excludes concurrency and controlled WAN delay.",
            "The allocation counter excludes PostgreSQL server allocations.",
            "The speed-up measures round-trip removal, not binary syntax alone.",
        ],
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)
        .map_err(|error| error.to_string())?;
    println!();
    if hard_gate_passed {
        Ok(())
    } else {
        Err("the v2.8 hard gate failed".into())
    }
}

async fn create_database(connection: &str) -> Result<DatabaseState, String> {
    let (client, connection_task) = tokio_postgres::connect(connection, NoTls)
        .await
        .map_err(|error| error.to_string())?;
    tokio::spawn(async move {
        if let Err(error) = connection_task.await {
            eprintln!("PostgreSQL connection failed: {error}");
        }
    });
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS ndabi_v27_items (\
             id BIGINT PRIMARY KEY, bucket INTEGER NOT NULL, payload BYTEA NOT NULL);\
             TRUNCATE ndabi_v27_items;\
             INSERT INTO ndabi_v27_items \
             SELECT value, (value % 1024)::INTEGER, decode(repeat(lpad(to_hex(value % 256), 2, '0'), 64), 'hex') \
             FROM generate_series(0, 99999) AS value;\
             ANALYZE ndabi_v27_items;",
        )
        .await
        .map_err(|error| error.to_string())?;
    let point = client
        .prepare("SELECT id, bucket, payload FROM ndabi_v27_items WHERE id = $1")
        .await
        .map_err(|error| error.to_string())?;
    let set = client
        .prepare(
            "SELECT item.id, item.bucket, item.payload \
             FROM unnest($1::bigint[]) WITH ORDINALITY AS request(id, ordinal) \
             JOIN ndabi_v27_items AS item ON item.id = request.id \
             ORDER BY request.ordinal",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(DatabaseState { client, point, set })
}

async fn run_case(database: &mut DatabaseState, batch_size: usize) -> Result<CaseReport, String> {
    let mut case = create_case(batch_size)?;
    let expected = execute_set(database, &case.ids).await?;
    let mut samples: [Vec<Sample>; 4] = std::array::from_fn(|_| Vec::with_capacity(SAMPLES));

    for cycle in 0..WARMUP {
        for offset in 0..Arm::ALL.len() {
            let arm = Arm::ALL[(cycle + offset) % Arm::ALL.len()];
            let outcome = execute_arm(database, &mut case, arm).await?;
            require_equal(&expected, &outcome, arm)?;
            black_box(outcome);
        }
    }

    for cycle in 0..SAMPLES {
        for offset in 0..Arm::ALL.len() {
            let arm = Arm::ALL[(cycle + offset) % Arm::ALL.len()];
            let allocation_start = begin_measurement();
            let started = Instant::now();
            let outcome = execute_arm(database, &mut case, arm).await?;
            let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
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
    let sequential = measurement(&measurements, "sequential-prepared")?;
    let native_set = measurement(&measurements, "native-set")?;
    let pipeline = measurement(&measurements, "native-pipeline")?;
    let ndabi = measurement(&measurements, "ndabi-set")?;
    let ratios = Ratios {
        sequential_over_ndabi_p95: ratio(sequential.p95_batch_ns, ndabi.p95_batch_ns),
        ndabi_over_native_set_p95: ratio(ndabi.p95_batch_ns, native_set.p95_batch_ns),
        pipeline_over_native_set_p95: ratio(pipeline.p95_batch_ns, native_set.p95_batch_ns),
    };
    let mut gates = Vec::new();
    if batch_size >= 32 {
        gates.push(Gate {
            id: "ndabi-native-set-distance".into(),
            passed: ratios.ndabi_over_native_set_p95 <= 1.10,
            observed: format!("{:.4}x", ratios.ndabi_over_native_set_p95),
            target: "no more than 1.10x",
        });
        gates.push(Gate {
            id: "sequential-round-trip-removal".into(),
            passed: ratios.sequential_over_ndabi_p95 >= 4.0,
            observed: format!("{:.4}x", ratios.sequential_over_ndabi_p95),
            target: "at least 4.00x",
        });
    }
    gates.push(Gate {
        id: "literal-result-and-receipt-equality".into(),
        passed: true,
        observed: hex(&Sha256::digest(&expected.bytes)),
        target: "one byte-identical payload and receipt",
    });
    Ok(CaseReport {
        batch_size,
        canonical_sha256: hex(&Sha256::digest(&expected.bytes)),
        receipt_sha256: hex(&expected.receipt),
        measurements,
        ratios,
        gates,
    })
}

fn create_case(batch_size: usize) -> Result<CaseState, String> {
    let session_handle = SESSION_BASE
        .checked_add(u32::try_from(batch_size).map_err(|error| error.to_string())?)
        .ok_or_else(|| "the session handle overflowed".to_string())?;
    let generation = u64::try_from(batch_size).map_err(|error| error.to_string())?;
    let binding = SessionBinding::new(
        session_handle,
        CAPABILITY_HANDLE,
        SCHEMA_HANDLE,
        generation,
        u32::try_from(batch_size * 76).map_err(|error| error.to_string())?,
        u64::MAX,
        FRAME_KEY,
    )
    .map_err(|error| error.to_string())?;
    let start = ROWS - i64::try_from(batch_size).map_err(|error| error.to_string())?;
    let ids = (start..ROWS).collect::<Vec<_>>();
    let frame_count = WARMUP + SAMPLES;
    let mut frames = Vec::with_capacity(frame_count);
    for index in 0..frame_count {
        let operations = ids
            .iter()
            .enumerate()
            .map(|(operation_index, id)| Operation {
                id: u32::try_from(operation_index + 1).expect("bounded batch size"),
                plan_handle: PLAN_HANDLE,
                transaction_group: 0,
                result_shape: RESULT_SHAPE,
                flags: OPERATION_READ | OPERATION_IDEMPOTENT,
                dependencies: Vec::new(),
                parameters: id.to_le_bytes().to_vec(),
            })
            .collect();
        let frame = Frame {
            kind: FrameKind::ExecuteBatch,
            flags: 0,
            session_handle,
            capability_handle: CAPABILITY_HANDLE,
            schema_handle: SCHEMA_HANDLE,
            generation,
            nonce: u64::try_from(index + 1).expect("bounded frame count"),
            deadline_unix_us: u64::MAX,
            result_budget: u32::try_from(batch_size * 76).expect("bounded result size"),
            operations,
        };
        frames.push(frame.encode(&binding).map_err(|error| error.to_string())?);
    }
    Ok(CaseState {
        ids,
        frames,
        next_frame: 0,
        verifier: SessionVerifier::new(binding, 0),
        decoded_ids: Vec::with_capacity(batch_size),
    })
}

async fn execute_arm(
    database: &DatabaseState,
    case: &mut CaseState,
    arm: Arm,
) -> Result<Outcome, String> {
    match arm {
        Arm::SequentialPrepared => execute_sequential(database, &case.ids).await,
        Arm::NativeSet => execute_set(database, &case.ids).await,
        Arm::NativePipeline => execute_pipeline(database, &case.ids).await,
        Arm::NdabiSet => {
            let bytes = case
                .frames
                .get(case.next_frame)
                .ok_or_else(|| "the NDABI frame supply ended".to_string())?;
            case.next_frame += 1;
            let frame = case
                .verifier
                .verify_view(bytes)
                .map_err(|error| error.to_string())?;
            let strategy = plan_execution_view(
                frame,
                BackendCapabilities {
                    set_queries: true,
                    prepared_pipeline: true,
                    server_graph: false,
                },
            )
            .map_err(|error| error.to_string())?;
            if strategy != ExecutionStrategy::SetQuery {
                return Err("the homogeneous batch did not select one set query".into());
            }
            case.decoded_ids.clear();
            for index in 0..frame.operation_count() {
                let operation = frame.operation(index).map_err(|error| error.to_string())?;
                let bytes = operation
                    .parameters
                    .try_into()
                    .map_err(|_| "an NDABI identifier has the wrong size".to_string())?;
                case.decoded_ids.push(i64::from_le_bytes(bytes));
            }
            execute_set(database, &case.decoded_ids).await
        }
    }
}

async fn execute_sequential(database: &DatabaseState, ids: &[i64]) -> Result<Outcome, String> {
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        rows.push(
            database
                .client
                .query_one(&database.point, &[id])
                .await
                .map_err(|error| error.to_string())?,
        );
    }
    canonical(&rows)
}

async fn execute_set(database: &DatabaseState, ids: &[i64]) -> Result<Outcome, String> {
    let rows = database
        .client
        .query(&database.set, &[&ids])
        .await
        .map_err(|error| error.to_string())?;
    canonical(&rows)
}

async fn execute_pipeline(database: &DatabaseState, ids: &[i64]) -> Result<Outcome, String> {
    let futures = ids.iter().map(|id| async {
        database
            .client
            .query_one(&database.point, &[id])
            .await
            .map_err(|error| error.to_string())
    });
    let rows = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    canonical(&rows)
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
    receipt.update(b"ndabi/postgresql/batch-receipt/v1");
    receipt.update(RECEIPT_AUTHORITY);
    receipt.update(Sha256::digest(&bytes));
    Ok(Outcome {
        bytes,
        receipt: receipt.finalize().into(),
    })
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

fn finish(arm: Arm, operations: usize, samples: &[Sample]) -> Measurement {
    let mut elapsed = samples
        .iter()
        .map(|sample| sample.elapsed_ns)
        .collect::<Vec<_>>();
    elapsed.sort_unstable();
    let total_ns = elapsed.iter().map(|value| u128::from(*value)).sum::<u128>();
    let total_operations = (samples.len() * operations) as f64;
    let p95 = percentile(&elapsed, 0.95);
    Measurement {
        id: arm.id(),
        samples: samples.len(),
        operations_per_batch: operations,
        median_batch_ns: percentile(&elapsed, 0.50),
        p95_batch_ns: p95,
        p99_batch_ns: percentile(&elapsed, 0.99),
        p95_ns_per_operation: p95 as f64 / operations as f64,
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

fn percentile(sorted: &[u64], quantile: f64) -> u64 {
    sorted[((sorted.len() - 1) as f64 * quantile).ceil() as usize]
}

fn ratio(left: u64, right: u64) -> f64 {
    left as f64 / right.max(1) as f64
}

fn prove_frame_refusals() -> Result<(), String> {
    let mut case = create_case(8)?;
    let frame = case
        .frames
        .first()
        .ok_or_else(|| "the refusal frame is missing".to_string())?;
    for index in 0..frame.len() {
        let mut changed = frame.clone();
        changed[index] ^= 1;
        let binding = SessionBinding::new(
            SESSION_BASE + 8,
            CAPABILITY_HANDLE,
            SCHEMA_HANDLE,
            8,
            8 * 76,
            u64::MAX,
            FRAME_KEY,
        )
        .map_err(|error| error.to_string())?;
        if SessionVerifier::new(binding, 0).verify(&changed).is_ok() {
            return Err(format!("modified frame byte {index} was accepted"));
        }
    }
    let first = case
        .verifier
        .verify(frame)
        .map_err(|error| error.to_string())?;
    black_box(first);
    if case.verifier.verify(frame).is_ok() {
        return Err("a replayed frame was accepted".into());
    }
    Ok(())
}

fn prove_borrowed_decode() -> Result<ndabi_showdown::alloc::AllocationDelta, String> {
    let mut case = create_case(128)?;
    let frame = case
        .frames
        .first()
        .ok_or_else(|| "the allocation frame is missing".to_string())?;
    let allocation_start = begin_measurement();
    let view = case
        .verifier
        .verify_view(frame)
        .map_err(|error| error.to_string())?;
    let mut checksum = 0u64;
    for index in 0..view.operation_count() {
        let operation = view.operation(index).map_err(|error| error.to_string())?;
        checksum ^= u64::from(operation.id);
        checksum ^= u64::try_from(operation.parameters.len()).unwrap_or(u64::MAX);
    }
    black_box(checksum);
    Ok(end_measurement(allocation_start))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_case_has_enough_unique_frames() {
        for batch_size in BATCH_SIZES {
            let case = create_case(batch_size).expect("create case");
            assert_eq!(case.frames.len(), WARMUP + SAMPLES);
            let mut verifier = case.verifier;
            for frame in case.frames {
                assert!(verifier.verify(&frame).is_ok());
            }
        }
    }

    #[test]
    fn percentile_uses_the_registered_nearest_rank() {
        let values = (1..=100).collect::<Vec<_>>();
        assert_eq!(percentile(&values, 0.50), 51);
        assert_eq!(percentile(&values, 0.95), 96);
        assert_eq!(percentile(&values, 0.99), 100);
    }
}
