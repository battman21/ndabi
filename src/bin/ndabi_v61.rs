use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ndabi_postgres_v1::{
    digest_label, memory_replay_store, AuthorityContext, OperationBinding, RangeBackend,
    RangeProfile, ServerSession as RangeServerSession, WireClientSession,
};
use ndabi_protocol::{
    batch_frame_bytes, Authority, BatchItem, MemoryReplayStore, ProtocolError, ServerSession,
    SystemClock, FRAME_BYTES,
};
use ndabi_showdown::alloc::{begin_measurement, end_measurement, AllocationDelta};
use postgres::{Client, NoTls, Row, Statement};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[global_allocator]
static GLOBAL: ndabi_showdown::alloc::CountingAllocator = ndabi_showdown::alloc::CountingAllocator;

const SQL: &str =
    "SELECT id,bucket,owner,score,payload FROM ndabi_v61_items WHERE id = ANY($1) ORDER BY id";
const SAMPLES: usize = 31;
const WARMUPS: usize = 5;
const EXPIRY_UNIX_US: u64 = 4_102_444_800_000_000;
const COUNTS: [u32; 2] = [32, 128];
const ARMS: [Arm; 3] = [Arm::Sequential, Arm::Batch, Arm::Native];

#[derive(Clone, Copy)]
enum Arm {
    Sequential = 0,
    Batch = 1,
    Native = 2,
}

impl Arm {
    fn id(self) -> &'static str {
        match self {
            Self::Sequential => "sequential-canonical",
            Self::Batch => "batch-canonical",
            Self::Native => "native-fused",
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
    operation_count: u32,
    sequential_frame_bytes: usize,
    batch_frame_bytes: usize,
    request_compression: f64,
    response_bytes: usize,
    result_sha256: String,
    measurements: Vec<Measurement>,
    sequential_data_queries: u64,
    batch_data_queries: u64,
    expected_sequential_data_queries: u64,
    expected_batch_data_queries: u64,
    p95_speedup: f64,
    cpu_p50_speedup: f64,
    batch_native_p95_distance: f64,
    batch_native_cpu_distance: f64,
    allocation_reduction: f64,
    allocated_bytes_reduction: f64,
    receipts_valid: bool,
    speed_target: f64,
    cpu_target: f64,
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
    replay_refused: bool,
    mutation_refused: bool,
    inadequate_budget_refused_before_query: bool,
    noncanonical_order_refused_before_query: bool,
    successful_data_queries: u64,
    passed: bool,
}

struct Outcome {
    bytes: Vec<u8>,
    receipt_nonzero: bool,
}

struct Sample {
    wall_ns: u64,
    cpu_ns: u64,
    allocation: AllocationDelta,
}

struct SequentialState {
    profile: RangeProfile,
    client: WireClientSession,
    server: RangeServerSession,
    backend: RangeBackend,
    replay: MemoryReplayStore,
}

struct BatchState {
    profile: RangeProfile,
    items: Vec<BatchItem>,
    frame: Vec<u8>,
    client: WireClientSession,
    server: ServerSession,
    backend: RangeBackend,
    replay: MemoryReplayStore,
}

struct NativeState {
    client: Client,
    deadline_statement: Statement,
    statement: Statement,
    ids: Vec<i64>,
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
    let mut reports = Vec::new();
    for (case_index, count) in COUNTS.into_iter().enumerate() {
        reports.push(measure_case(&connection, count, case_index)?);
    }
    let security = security_suite(&connection)?;
    let passed = reports.iter().all(|report| report.passed) && security.passed;
    let report = Report {
        campaign: "NDABI canonical PostgreSQL batch v6.1",
        samples: SAMPLES,
        warmups: WARMUPS,
        cases: reports,
        security,
        passed,
    };
    serde_json::to_writer(std::io::stdout(), &report).map_err(|error| error.to_string())?;
    println!();
    if passed {
        Ok(())
    } else {
        Err("the canonical PostgreSQL batch gate failed".to_string())
    }
}

fn measure_case(connection: &str, count: u32, case_index: usize) -> Result<CaseReport, String> {
    let profile = profile()?;
    let identity = identity(profile)?;
    let ids = case_ids(count);
    let expected = expected_rows(&ids);
    let result_budget = u32::try_from(expected.len()).map_err(|error| error.to_string())?;
    let mut sequential = SequentialState::new(connection, profile, identity, count, case_index)?;
    let mut batch = BatchState::new(
        connection,
        profile,
        identity,
        &ids,
        result_budget,
        case_index,
    )?;
    let mut native = NativeState::new(connection, ids.clone())?;
    let sequential_before = sequential.backend.data_queries();
    let batch_before = batch.backend.data_queries();
    let mut samples: [Vec<Sample>; 3] = std::array::from_fn(|_| Vec::with_capacity(SAMPLES));
    let mut receipts_valid = true;
    for sample_index in 0..WARMUPS + SAMPLES {
        for arm_offset in 0..ARMS.len() {
            let arm = ARMS[(case_index + sample_index + arm_offset) % ARMS.len()];
            let deadline = deadline()?;
            let before_cpu = thread_cpu_ns()?;
            let allocation_start = begin_measurement();
            let started = Instant::now();
            let outcome = match arm {
                Arm::Sequential => sequential.execute(&ids, result_budget, deadline)?,
                Arm::Batch => batch.execute(result_budget, count, deadline)?,
                Arm::Native => native.execute()?,
            };
            let wall_ns = elapsed_ns(started)?;
            let allocation = end_measurement(allocation_start);
            let cpu_ns = thread_cpu_ns()?.saturating_sub(before_cpu);
            black_box(&outcome.bytes);
            if outcome.bytes != expected {
                return Err(format!("the {count}-operand {} result changed", arm.id()));
            }
            if !matches!(arm, Arm::Native) {
                receipts_valid &= outcome.receipt_nonzero;
            }
            if sample_index >= WARMUPS {
                samples[arm as usize].push(Sample {
                    wall_ns,
                    cpu_ns,
                    allocation,
                });
            }
        }
    }
    let sequential_data_queries = sequential.backend.data_queries() - sequential_before;
    let batch_data_queries = batch.backend.data_queries() - batch_before;
    let measurements: Vec<Measurement> = ARMS
        .into_iter()
        .map(|arm| summarise(arm, std::mem::take(&mut samples[arm as usize])))
        .collect();
    let sequential_measurement = &measurements[Arm::Sequential as usize];
    let batch_measurement = &measurements[Arm::Batch as usize];
    let native_measurement = &measurements[Arm::Native as usize];
    let total_runs = u64::try_from(WARMUPS + SAMPLES).map_err(|error| error.to_string())?;
    let expected_sequential_data_queries = total_runs * u64::from(count);
    let expected_batch_data_queries = total_runs;
    let sequential_frame_bytes = FRAME_BYTES * count as usize;
    let batch_request_bytes =
        batch_frame_bytes(count as usize).map_err(|error| error.to_string())?;
    let request_compression = 1.0 - batch_request_bytes as f64 / sequential_frame_bytes as f64;
    let p95_speedup = sequential_measurement.p95_ns as f64 / batch_measurement.p95_ns as f64;
    let cpu_p50_speedup =
        sequential_measurement.p50_cpu_ns as f64 / batch_measurement.p50_cpu_ns as f64;
    let batch_native_p95_distance =
        batch_measurement.p95_ns as f64 / native_measurement.p95_ns as f64;
    let batch_native_cpu_distance =
        batch_measurement.p50_cpu_ns as f64 / native_measurement.p50_cpu_ns as f64;
    let allocation_reduction =
        1.0 - batch_measurement.mean_allocations / sequential_measurement.mean_allocations;
    let allocated_bytes_reduction =
        1.0 - batch_measurement.mean_allocated_bytes / sequential_measurement.mean_allocated_bytes;
    let speed_target = if count == 32 { 10.0 } else { 25.0 };
    let cpu_target = if count == 32 { 8.0 } else { 20.0 };
    let passed = receipts_valid
        && sequential_data_queries == expected_sequential_data_queries
        && batch_data_queries == expected_batch_data_queries
        && request_compression >= 0.80
        && p95_speedup >= speed_target
        && cpu_p50_speedup >= cpu_target
        && batch_native_p95_distance <= 1.25
        && batch_native_cpu_distance <= 1.35
        && allocation_reduction >= 0.75
        && allocated_bytes_reduction >= 0.40;
    Ok(CaseReport {
        operation_count: count,
        sequential_frame_bytes,
        batch_frame_bytes: batch_request_bytes,
        request_compression,
        response_bytes: expected.len(),
        result_sha256: hex(&Sha256::digest(&expected)),
        measurements,
        sequential_data_queries,
        batch_data_queries,
        expected_sequential_data_queries,
        expected_batch_data_queries,
        p95_speedup,
        cpu_p50_speedup,
        batch_native_p95_distance,
        batch_native_cpu_distance,
        allocation_reduction,
        allocated_bytes_reduction,
        receipts_valid,
        speed_target,
        cpu_target,
        passed,
    })
}

impl SequentialState {
    fn new(
        connection: &str,
        profile: RangeProfile,
        identity: ndabi_protocol::BackendIdentity,
        count: u32,
        case_index: usize,
    ) -> Result<Self, String> {
        let authority = authority(identity, 610 + case_index as u64)?;
        let backend = connect_backend(connection, profile)?;
        let server =
            RangeServerSession::new(authority.clone(), 90, 1).map_err(|error| error.to_string())?;
        let _ = count;
        Ok(Self {
            profile,
            client: WireClientSession::new(authority),
            server,
            backend,
            replay: memory_replay_store(),
        })
    }

    fn execute(
        &mut self,
        ids: &[i64],
        _result_budget: u32,
        deadline: u64,
    ) -> Result<Outcome, String> {
        let mut combined = Vec::with_capacity(6 + ids.len() * 84);
        combined.extend_from_slice(&1_u16.to_le_bytes());
        combined.extend_from_slice(&(ids.len() as u32).to_le_bytes());
        let mut receipt_nonzero = true;
        for id in ids {
            let frame = self
                .client
                .encode(
                    self.profile
                        .operation(*id, 1)
                        .map_err(|error| error.to_string())?,
                    90,
                    1,
                    deadline,
                )
                .map_err(|error| error.to_string())?;
            let execution = self
                .server
                .execute(&frame, &mut self.backend, &mut self.replay, &SystemClock)
                .map_err(|error| error.to_string())?;
            combined.extend_from_slice(&execution.bytes[6..]);
            receipt_nonzero &= execution.receipt.iter().any(|byte| *byte != 0);
        }
        Ok(Outcome {
            bytes: combined,
            receipt_nonzero,
        })
    }
}

impl BatchState {
    fn new(
        connection: &str,
        profile: RangeProfile,
        identity: ndabi_protocol::BackendIdentity,
        ids: &[i64],
        result_budget: u32,
        case_index: usize,
    ) -> Result<Self, String> {
        let authority = authority(identity, 620 + case_index as u64)?;
        let items: Vec<BatchItem> = ids.iter().map(|id| BatchItem::new(*id, 0, 1)).collect();
        let frame = vec![0; batch_frame_bytes(items.len()).map_err(|error| error.to_string())?];
        Ok(Self {
            profile,
            items,
            frame,
            client: WireClientSession::new(authority.clone()),
            server: ServerSession::new(authority, result_budget, ids.len() as u32)
                .map_err(|error| error.to_string())?,
            backend: connect_backend(connection, profile)?,
            replay: memory_replay_store(),
        })
    }

    fn execute(
        &mut self,
        result_budget: u32,
        row_budget: u32,
        deadline: u64,
    ) -> Result<Outcome, String> {
        self.client
            .encode_batch_into(
                self.profile
                    .batch_operation()
                    .map_err(|error| error.to_string())?,
                &self.items,
                result_budget,
                row_budget,
                deadline,
                &mut self.frame,
            )
            .map_err(|error| error.to_string())?;
        let execution = self
            .server
            .execute_batch(
                &self.frame,
                &mut self.backend,
                &mut self.replay,
                &SystemClock,
            )
            .map_err(|error| error.to_string())?;
        Ok(Outcome {
            receipt_nonzero: execution.receipt.iter().any(|byte| *byte != 0),
            bytes: execution.bytes,
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
        if rows.len() != self.ids.len() {
            return Err("the native fused query returned an incomplete result".to_string());
        }
        Ok(Outcome {
            bytes: encode_rows(&rows, &self.ids)?,
            receipt_nonzero: false,
        })
    }
}

fn security_suite(connection: &str) -> Result<SecurityReport, String> {
    let profile = profile()?;
    let identity = identity(profile)?;
    let ids = [101_i64, 102_i64];
    let items = [BatchItem::new(101, 0, 1), BatchItem::new(102, 0, 1)];
    let result_budget = 6 + 2 * 84;
    let authority = authority(identity, 699)?;
    let mut client = WireClientSession::new(authority.clone());
    let mut frame = vec![0; batch_frame_bytes(2).map_err(|error| error.to_string())?];
    client
        .encode_batch_into(
            profile
                .batch_operation()
                .map_err(|error| error.to_string())?,
            &items,
            result_budget,
            2,
            deadline()?,
            &mut frame,
        )
        .map_err(|error| error.to_string())?;
    let server =
        ServerSession::new(authority, result_budget, 2).map_err(|error| error.to_string())?;
    let mut backend = connect_backend(connection, profile)?;
    let mut replay = memory_replay_store();
    let execution = server
        .execute_batch(&frame, &mut backend, &mut replay, &SystemClock)
        .map_err(|error| error.to_string())?;
    if execution.bytes != expected_rows(&ids) {
        return Err("the security control returned changed bytes".to_string());
    }
    let queries_after_success = backend.data_queries();
    let replay_refused = matches!(
        server.execute_batch(&frame, &mut backend, &mut replay, &SystemClock),
        Err(ProtocolError::Replay)
    );
    let mut changed = frame.clone();
    changed[128] ^= 1;
    let mutation_refused = matches!(
        server.execute_batch(&changed, &mut backend, &mut replay, &SystemClock),
        Err(ProtocolError::AuthenticationFailed)
    );
    let inadequate_budget_refused_before_query = refusal_before_query(
        connection,
        profile,
        identity,
        700,
        &items,
        result_budget - 1,
        result_budget,
    )?;
    let reversed = [BatchItem::new(102, 0, 1), BatchItem::new(101, 0, 1)];
    let noncanonical_order_refused_before_query = refusal_before_query(
        connection,
        profile,
        identity,
        701,
        &reversed,
        result_budget,
        result_budget,
    )?;
    let successful_data_queries = backend.data_queries();
    let passed = replay_refused
        && mutation_refused
        && inadequate_budget_refused_before_query
        && noncanonical_order_refused_before_query
        && queries_after_success == 1
        && successful_data_queries == 1;
    Ok(SecurityReport {
        replay_refused,
        mutation_refused,
        inadequate_budget_refused_before_query,
        noncanonical_order_refused_before_query,
        successful_data_queries,
        passed,
    })
}

fn refusal_before_query(
    connection: &str,
    profile: RangeProfile,
    identity: ndabi_protocol::BackendIdentity,
    session: u64,
    items: &[BatchItem],
    frame_budget: u32,
    server_budget: u32,
) -> Result<bool, String> {
    let authority = authority(identity, session)?;
    let mut client = WireClientSession::new(authority.clone());
    let mut frame = vec![0; batch_frame_bytes(items.len()).map_err(|error| error.to_string())?];
    client
        .encode_batch_into(
            profile
                .batch_operation()
                .map_err(|error| error.to_string())?,
            items,
            frame_budget,
            items.len() as u32,
            deadline()?,
            &mut frame,
        )
        .map_err(|error| error.to_string())?;
    let server = ServerSession::new(authority, server_budget, items.len() as u32)
        .map_err(|error| error.to_string())?;
    let mut backend = connect_backend(connection, profile)?;
    let before = backend.data_queries();
    let refused = server
        .execute_batch(
            &frame,
            &mut backend,
            &mut memory_replay_store(),
            &SystemClock,
        )
        .is_err();
    Ok(refused && backend.data_queries() == before)
}

fn profile() -> Result<RangeProfile, String> {
    RangeProfile::new(
        SQL,
        OperationBinding::new(61, 610).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn identity(profile: RangeProfile) -> Result<ndabi_protocol::BackendIdentity, String> {
    profile
        .identity(
            digest_label(
                b"ndabi/postgresql/batch/schema/v1",
                b"ndabi_v61_items(id:i64,bucket:i32,owner:i32,score:i32,payload:bytes64)",
            ),
            digest_label(
                b"ndabi/postgresql/batch/policy/v1",
                b"select-only;fixed-table;fixed-projection;ascending-ids",
            ),
        )
        .map_err(|error| error.to_string())
}

fn authority(identity: ndabi_protocol::BackendIdentity, session: u64) -> Result<Authority, String> {
    let context = AuthorityContext::new(
        *b"pgbatch-tenant01",
        *b"pgbatch-reader01",
        1,
        digest_label(
            b"ndabi/postgresql/batch/capability/v1",
            b"read:ndabi_v61_items:identifier-batch",
        ),
        identity,
    )
    .map_err(|error| error.to_string())?;
    Authority::new_read([61; 32], 1, session, EXPIRY_UNIX_US, context)
        .map_err(|error| error.to_string())
}

fn connect_backend(connection: &str, profile: RangeProfile) -> Result<RangeBackend, String> {
    let client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    RangeBackend::new(
        client,
        profile,
        digest_label(
            b"ndabi/postgresql/batch/schema/v1",
            b"ndabi_v61_items(id:i64,bucket:i32,owner:i32,score:i32,payload:bytes64)",
        ),
        digest_label(
            b"ndabi/postgresql/batch/policy/v1",
            b"select-only;fixed-table;fixed-projection;ascending-ids",
        ),
    )
    .map_err(|error| error.to_string())
}

fn case_ids(count: u32) -> Vec<i64> {
    let start = if count == 32 { 1_000 } else { 5_000 };
    (0..i64::from(count)).map(|offset| start + offset).collect()
}

fn expected_rows(ids: &[i64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(6 + ids.len() * 84);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for id in ids {
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.extend_from_slice(&((*id % 1_000) as i32).to_le_bytes());
        bytes.extend_from_slice(&((*id % 100) as i32).to_le_bytes());
        bytes.extend_from_slice(&((*id % 10_000) as i32).to_le_bytes());
        bytes.extend_from_slice(&[(*id % 256) as u8; 64]);
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
            return Err("the native fused row changed".to_string());
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
    let wall: Vec<u64> = samples.iter().map(|sample| sample.wall_ns).collect();
    let cpu: Vec<u64> = samples.iter().map(|sample| sample.cpu_ns).collect();
    Measurement {
        arm: arm.id(),
        p50_ns: percentile(&wall, 0.50),
        p95_ns: percentile(&wall, 0.95),
        p99_ns: percentile(&wall, 0.99),
        p50_cpu_ns: percentile(&cpu, 0.50),
        mean_allocations: samples
            .iter()
            .map(|sample| sample.allocation.allocations as f64)
            .sum::<f64>()
            / samples.len() as f64,
        mean_allocated_bytes: samples
            .iter()
            .map(|sample| sample.allocation.allocated_bytes as f64)
            .sum::<f64>()
            / samples.len() as f64,
        peak_additional_live_bytes: samples
            .iter()
            .map(|sample| sample.allocation.peak_additional_live_bytes)
            .max()
            .unwrap_or(0),
        raw_ns: wall,
        raw_cpu_ns: cpu,
    }
}

fn percentile(values: &[u64], quantile: f64) -> u64 {
    let mut ordered = values.to_vec();
    ordered.sort_unstable();
    let index = ((ordered.len() - 1) as f64 * quantile).ceil() as usize;
    ordered[index]
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
        write!(output, "{byte:02x}").expect("string writes cannot fail");
    }
    output
}
