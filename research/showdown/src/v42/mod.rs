//! Measure the reusable embedded PostgreSQL adapter across varied query shapes.
//!
//! This campaign keeps the accepted v4.1 source and evidence immutable.

use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ndabi_postgres::{
    AdapterError, Authority, Backend, ClientSession, PostgresBackend, ProfileSql, ReadOperation,
    ServerSession, FRAME_BYTES,
};
use ndabi_showdown::alloc::{begin_measurement, end_measurement, AllocationDelta};
use postgres::{Client, NoTls};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ROWS: i64 = 1_000_000;
const WARMUP: usize = 7;
const SAMPLES: usize = 63;
const MAXIMUM_RESULT_BYTES: u32 = 2 * 1024 * 1024;
const GENERATION: u64 = 0x4200_0000_0000_0001;
const EXPIRY_UNIX_US: u64 = 4_102_444_800_000_000;
const DEADLINE_UNIX_US: u64 = EXPIRY_UNIX_US - 1;
const ROOT_KEY: [u8; 32] = [0x42; 32];
const CAPABILITY: u32 = 0x4200_1001;
const SCHEMA: u32 = 0x4200_2001;
const PLAN: u32 = 0x4200_3001;

const RANGE_SQL: &str = "SELECT item.id, item.bucket, item.owner, item.score, item.payload \
    FROM unnest($1::bigint[]) WITH ORDINALITY AS request(id, ordinal) \
    JOIN ndabi_v42_items AS item ON item.id = request.id \
    ORDER BY request.ordinal";
const PREDICATE_SQL: &str = "SELECT id, bucket, owner, score, payload \
    FROM ndabi_v42_items WHERE bucket = $1 AND score >= $2 \
    ORDER BY score DESC, id ASC LIMIT $3";
const AGGREGATE_SQL: &str = "SELECT bucket, COUNT(*)::bigint, COALESCE(SUM(score), 0)::bigint \
    FROM ndabi_v42_items WHERE score >= $1 GROUP BY bucket ORDER BY bucket";
const JOIN_SQL: &str = "SELECT item.id, item.owner, owner.name, item.score, item.payload \
    FROM ndabi_v42_items AS item JOIN ndabi_v42_owners AS owner ON owner.id = item.owner \
    WHERE item.owner = $1 ORDER BY item.id LIMIT $2";

const ARMS: [Arm; 3] = [Arm::Native, Arm::Json, Arm::Ndabi];
const CASES: [Case; 5] = [
    Case {
        id: "range-128",
        operation: ReadOperation::Range {
            start: 400_000,
            count: 128,
        },
        result_budget: 16 * 1024,
    },
    Case {
        id: "predicate-64",
        operation: ReadOperation::Predicate {
            bucket: 731,
            minimum_score: 4_000,
            limit: 64,
        },
        result_budget: 8 * 1024,
    },
    Case {
        id: "aggregate",
        operation: ReadOperation::Aggregate {
            minimum_score: 9_900,
        },
        result_budget: 32 * 1024,
    },
    Case {
        id: "join-64",
        operation: ReadOperation::Join {
            owner: 2_103,
            limit: 64,
        },
        result_budget: 8 * 1024,
    },
    Case {
        id: "large-range-4096",
        operation: ReadOperation::Range {
            start: 700_000,
            count: 4_096,
        },
        result_budget: 512 * 1024,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
enum Arm {
    #[serde(rename = "native-prepared")]
    Native,
    #[serde(rename = "compact-json")]
    Json,
    #[serde(rename = "ndabi-embedded")]
    Ndabi,
}

impl Arm {
    fn id(self) -> &'static str {
        match self {
            Self::Native => "native-prepared",
            Self::Json => "compact-json",
            Self::Ndabi => "ndabi-embedded",
        }
    }
}

#[derive(Clone, Copy)]
struct Case {
    id: &'static str,
    operation: ReadOperation,
    result_budget: u32,
}

#[derive(Deserialize, Serialize)]
struct JsonRequest {
    protocol: String,
    generation: u64,
    session: u32,
    capability: u32,
    schema: u32,
    plan: u32,
    deadline_unix_us: u64,
    result_budget: u32,
    operation: ReadOperation,
}

#[derive(Serialize)]
struct Measurement {
    id: &'static str,
    samples: usize,
    median_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    median_client_cpu_ns: u64,
    mean_allocations: f64,
    mean_allocated_bytes: f64,
    peak_additional_live_bytes: u64,
    request_bytes: Option<usize>,
    response_bytes: usize,
    raw_ns: Vec<u64>,
    raw_client_cpu_ns: Vec<u64>,
}

#[derive(Serialize)]
struct CaseReport {
    id: &'static str,
    result_sha256: String,
    ndabi_receipt_sha256: String,
    measurements: Vec<Measurement>,
    ndabi_native_p95_distance: f64,
    ndabi_native_cpu_distance: f64,
    request_compression: f64,
}

#[derive(Serialize)]
struct SecurityReport {
    changed_frame_refused: bool,
    replay_refused: bool,
    cross_session_refused: bool,
    expired_frame_refused: bool,
    excessive_budget_refused: bool,
    backend_failure_preserved_nonce: bool,
    arbitrary_sql_refused: bool,
    write_operation_refused: bool,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    status: &'static str,
    client_operating_system: &'static str,
    client_architecture: &'static str,
    rows: i64,
    client_max_rss_kib: u64,
    cases: Vec<CaseReport>,
    security: SecurityReport,
    correctness_gate_passed: bool,
    limitations: [&'static str; 4],
}

struct Outcome {
    bytes: Vec<u8>,
    receipt: Option<[u8; 32]>,
    request_bytes: Option<usize>,
}

struct ArmState {
    native: PostgresBackend,
    json: PostgresBackend,
    ndabi: PostgresBackend,
    ndabi_client: ClientSession,
    ndabi_server: ServerSession,
}

pub fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments
        .next()
        .ok_or_else(|| "supply prepare or client".to_string())?;
    let connection = arguments
        .next()
        .ok_or_else(|| "supply the PostgreSQL connection".to_string())?;
    if arguments.next().is_some() {
        return Err("too many v4.2 arguments".into());
    }
    match mode.as_str() {
        "prepare" => prepare(&connection),
        "client" => client(&connection),
        _ => Err("use ndabi_v42 prepare|client with a PostgreSQL connection".into()),
    }
}

fn profile_sql() -> ProfileSql {
    ProfileSql {
        range: RANGE_SQL,
        predicate: PREDICATE_SQL,
        aggregate: AGGREGATE_SQL,
        join: JOIN_SQL,
    }
}

fn prepare(connection: &str) -> Result<(), String> {
    let mut client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS ndabi_v42_owners (\
             id INTEGER PRIMARY KEY, name TEXT NOT NULL);\
             CREATE TABLE IF NOT EXISTS ndabi_v42_items (\
             id BIGINT PRIMARY KEY, bucket INTEGER NOT NULL, owner INTEGER NOT NULL,\
             score INTEGER NOT NULL, payload BYTEA NOT NULL,\
             FOREIGN KEY (owner) REFERENCES ndabi_v42_owners(id));\
             TRUNCATE ndabi_v42_items, ndabi_v42_owners;\
             INSERT INTO ndabi_v42_owners \
             SELECT value, 'owner-' || lpad(value::text, 4, '0') \
             FROM generate_series(0, 4095) AS value;\
             INSERT INTO ndabi_v42_items \
             SELECT value, (value % 1024)::INTEGER, (value % 4096)::INTEGER,\
             ((value * 37) % 10000)::INTEGER,\
             decode(repeat(lpad(to_hex(value % 256), 2, '0'), 64), 'hex') \
             FROM generate_series(0, 999999) AS value;\
             CREATE INDEX IF NOT EXISTS ndabi_v42_bucket_score \
             ON ndabi_v42_items(bucket, score DESC, id);\
             CREATE INDEX IF NOT EXISTS ndabi_v42_score_bucket \
             ON ndabi_v42_items(score, bucket);\
             CREATE INDEX IF NOT EXISTS ndabi_v42_owner_id \
             ON ndabi_v42_items(owner, id);\
             ANALYZE ndabi_v42_items;\
             ANALYZE ndabi_v42_owners;\
             CHECKPOINT;",
        )
        .map_err(|error| error.to_string())?;
    let count: i64 = client
        .query_one("SELECT COUNT(*) FROM ndabi_v42_items", &[])
        .map_err(|error| error.to_string())?
        .get(0);
    if count != ROWS {
        return Err("the v4.2 dataset row count is invalid".into());
    }
    println!("{{\"schema\":\"ndabi-postgresql-v4.2-prepare\",\"rows\":{ROWS}}}");
    Ok(())
}

fn connect_backend(connection: &str) -> Result<PostgresBackend, String> {
    let mut client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    let count: i64 = client
        .query_one("SELECT COUNT(*) FROM ndabi_v42_items", &[])
        .map_err(|_| "prepare the v4.2 dataset before measurement".to_string())?
        .get(0);
    if count != ROWS {
        return Err("the v4.2 dataset row count is invalid".into());
    }
    PostgresBackend::new(client, profile_sql()).map_err(|error| error.to_string())
}

fn authority(session: u32) -> Result<Authority, String> {
    Authority::new(
        ROOT_KEY,
        GENERATION,
        session,
        EXPIRY_UNIX_US,
        CAPABILITY,
        SCHEMA,
        PLAN,
    )
    .map_err(|error| error.to_string())
}

fn client(connection: &str) -> Result<(), String> {
    let ndabi_authority = authority(0x4200_0001)?;
    let mut state = ArmState {
        native: connect_backend(connection)?,
        json: connect_backend(connection)?,
        ndabi: connect_backend(connection)?,
        ndabi_client: ClientSession::new(ndabi_authority.clone()),
        ndabi_server: ServerSession::new(ndabi_authority, MAXIMUM_RESULT_BYTES)
            .map_err(|error| error.to_string())?,
    };
    let mut reports = Vec::new();
    for (case_index, case) in CASES.into_iter().enumerate() {
        reports.push(measure_case(&mut state, case, case_index)?);
    }
    let security = security_suite(connection)?;
    let correctness_gate_passed = reports.len() == CASES.len();
    let report = Report {
        schema: "ndabi-postgresql-scale-shapes-v4.2",
        status: "local-docker-process-diagnostic",
        client_operating_system: std::env::consts::OS,
        client_architecture: std::env::consts::ARCH,
        rows: ROWS,
        client_max_rss_kib: maximum_rss_kib(),
        cases: reports,
        security,
        correctness_gate_passed,
        limitations: [
            "The Docker host is Apple silicon, not physical Linux.",
            "The campaign uses local cleartext PostgreSQL, not TLS or WAN.",
            "The campaign does not test MongoDB or hosted Supabase.",
            "The campaign does not measure provider tokens or energy.",
        ],
    };
    serde_json::to_writer(std::io::stdout(), &report).map_err(|error| error.to_string())?;
    println!();
    Ok(())
}

fn measure_case(state: &mut ArmState, case: Case, case_index: usize) -> Result<CaseReport, String> {
    let mut expected: Option<Vec<u8>> = None;
    let mut receipt_identity = None;
    let mut samples: [Vec<Sample>; 3] = std::array::from_fn(|_| Vec::with_capacity(SAMPLES));
    let mut request_sizes: [Option<usize>; 3] = [None, None, None];
    let mut response_bytes = 0;
    for sample_index in 0..WARMUP + SAMPLES {
        for arm_offset in 0..ARMS.len() {
            let arm = ARMS[(case_index + sample_index + arm_offset) % ARMS.len()];
            let before_cpu = thread_cpu_ns()?;
            let before_allocations = begin_measurement();
            let started = Instant::now();
            let outcome = execute_arm(state, arm, case)?;
            let elapsed = elapsed_ns(started)?;
            let allocation = end_measurement(before_allocations);
            let cpu = thread_cpu_ns()?.saturating_sub(before_cpu);
            black_box(&outcome.bytes);
            if let Some(canonical) = &expected {
                if canonical != &outcome.bytes {
                    return Err(format!("{} returned changed bytes", case.id));
                }
            } else {
                expected = Some(outcome.bytes.clone());
                response_bytes = outcome.bytes.len();
            }
            if arm == Arm::Ndabi && receipt_identity.is_none() {
                receipt_identity = outcome.receipt;
            }
            request_sizes[arm as usize] = outcome.request_bytes;
            if sample_index >= WARMUP {
                samples[arm as usize].push(Sample {
                    wall_ns: elapsed,
                    cpu_ns: cpu,
                    allocation,
                });
            }
        }
    }
    let canonical = expected.ok_or_else(|| "the case produced no result".to_string())?;
    let mut measurements = Vec::new();
    for arm in ARMS {
        measurements.push(summarise(
            arm,
            std::mem::take(&mut samples[arm as usize]),
            request_sizes[arm as usize],
            response_bytes,
        )?);
    }
    let native = measurement(&measurements, Arm::Native)?;
    let json = measurement(&measurements, Arm::Json)?;
    let ndabi = measurement(&measurements, Arm::Ndabi)?;
    Ok(CaseReport {
        id: case.id,
        result_sha256: hexadecimal(&Sha256::digest(&canonical)),
        ndabi_receipt_sha256: hexadecimal(
            &receipt_identity.ok_or_else(|| "the NDABI receipt is missing".to_string())?,
        ),
        ndabi_native_p95_distance: ndabi.p95_ns as f64 / native.p95_ns as f64,
        ndabi_native_cpu_distance: ndabi.median_client_cpu_ns as f64
            / native.median_client_cpu_ns as f64,
        request_compression: 1.0
            - ndabi
                .request_bytes
                .ok_or_else(|| "the NDABI request size is missing".to_string())?
                as f64
                / json
                    .request_bytes
                    .ok_or_else(|| "the JSON request size is missing".to_string())?
                    as f64,
        measurements,
    })
}

fn execute_arm(state: &mut ArmState, arm: Arm, case: Case) -> Result<Outcome, String> {
    match arm {
        Arm::Native => Ok(Outcome {
            bytes: state
                .native
                .execute(case.operation)
                .map_err(|error| error.to_string())?,
            receipt: None,
            request_bytes: None,
        }),
        Arm::Json => {
            let request = JsonRequest {
                protocol: "ndabi-json-bridge-v1".to_string(),
                generation: GENERATION,
                session: 0x4200_0002,
                capability: CAPABILITY,
                schema: SCHEMA,
                plan: PLAN,
                deadline_unix_us: DEADLINE_UNIX_US,
                result_budget: case.result_budget,
                operation: case.operation,
            };
            let encoded = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
            let decoded: JsonRequest =
                serde_json::from_slice(&encoded).map_err(|error| error.to_string())?;
            validate_json(&decoded, case.result_budget)?;
            Ok(Outcome {
                bytes: state
                    .json
                    .execute(decoded.operation)
                    .map_err(|error| error.to_string())?,
                receipt: None,
                request_bytes: Some(encoded.len()),
            })
        }
        Arm::Ndabi => {
            let frame = state
                .ndabi_client
                .encode(case.operation, case.result_budget, DEADLINE_UNIX_US)
                .map_err(|error| error.to_string())?;
            let result = state
                .ndabi_server
                .execute(&frame, now_unix_us()?, &mut state.ndabi)
                .map_err(|error| error.to_string())?;
            Ok(Outcome {
                bytes: result.bytes,
                receipt: Some(result.receipt),
                request_bytes: Some(FRAME_BYTES),
            })
        }
    }
}

fn validate_json(request: &JsonRequest, result_budget: u32) -> Result<(), String> {
    if request.protocol != "ndabi-json-bridge-v1"
        || request.generation != GENERATION
        || request.session != 0x4200_0002
        || request.capability != CAPABILITY
        || request.schema != SCHEMA
        || request.plan != PLAN
        || request.deadline_unix_us != DEADLINE_UNIX_US
        || request.result_budget != result_budget
    {
        return Err("the JSON bridge authority changed".into());
    }
    Ok(())
}

struct Sample {
    wall_ns: u64,
    cpu_ns: u64,
    allocation: AllocationDelta,
}

fn summarise(
    arm: Arm,
    samples: Vec<Sample>,
    request_bytes: Option<usize>,
    response_bytes: usize,
) -> Result<Measurement, String> {
    if samples.len() != SAMPLES {
        return Err("the sample count is invalid".into());
    }
    let raw_ns: Vec<u64> = samples.iter().map(|sample| sample.wall_ns).collect();
    let raw_client_cpu_ns: Vec<u64> = samples.iter().map(|sample| sample.cpu_ns).collect();
    let mean_allocations = samples
        .iter()
        .map(|sample| sample.allocation.allocations as f64)
        .sum::<f64>()
        / samples.len() as f64;
    let mean_allocated_bytes = samples
        .iter()
        .map(|sample| sample.allocation.allocated_bytes as f64)
        .sum::<f64>()
        / samples.len() as f64;
    let peak_additional_live_bytes = samples
        .iter()
        .map(|sample| sample.allocation.peak_additional_live_bytes)
        .max()
        .unwrap_or(0);
    Ok(Measurement {
        id: arm.id(),
        samples: SAMPLES,
        median_ns: percentile(&raw_ns, 0.50),
        p95_ns: percentile(&raw_ns, 0.95),
        p99_ns: percentile(&raw_ns, 0.99),
        median_client_cpu_ns: percentile(&raw_client_cpu_ns, 0.50),
        mean_allocations,
        mean_allocated_bytes,
        peak_additional_live_bytes,
        request_bytes,
        response_bytes,
        raw_ns,
        raw_client_cpu_ns,
    })
}

fn measurement(measurements: &[Measurement], arm: Arm) -> Result<&Measurement, String> {
    measurements
        .iter()
        .find(|measurement| measurement.id == arm.id())
        .ok_or_else(|| format!("the {} measurement is missing", arm.id()))
}

fn security_suite(connection: &str) -> Result<SecurityReport, String> {
    let operation = ReadOperation::Range { start: 1, count: 1 };
    let changed_frame_refused = {
        let binding = authority(0x4200_0101)?;
        let mut client = ClientSession::new(binding.clone());
        let mut server =
            ServerSession::new(binding, MAXIMUM_RESULT_BYTES).map_err(|error| error.to_string())?;
        let mut frame = client
            .encode(operation, 256, DEADLINE_UNIX_US)
            .map_err(|error| error.to_string())?;
        frame[40] ^= 1;
        server
            .execute(&frame, now_unix_us()?, &mut connect_backend(connection)?)
            .is_err()
    };
    let replay_refused = {
        let binding = authority(0x4200_0102)?;
        let mut client = ClientSession::new(binding.clone());
        let mut server =
            ServerSession::new(binding, MAXIMUM_RESULT_BYTES).map_err(|error| error.to_string())?;
        let frame = client
            .encode(operation, 256, DEADLINE_UNIX_US)
            .map_err(|error| error.to_string())?;
        let mut backend = connect_backend(connection)?;
        server
            .execute(&frame, now_unix_us()?, &mut backend)
            .map_err(|error| error.to_string())?;
        server
            .execute(&frame, now_unix_us()?, &mut backend)
            .is_err()
    };
    let cross_session_refused = {
        let source = authority(0x4200_0103)?;
        let target = authority(0x4200_0104)?;
        let mut client = ClientSession::new(source);
        let mut server =
            ServerSession::new(target, MAXIMUM_RESULT_BYTES).map_err(|error| error.to_string())?;
        let frame = client
            .encode(operation, 256, DEADLINE_UNIX_US)
            .map_err(|error| error.to_string())?;
        server
            .execute(&frame, now_unix_us()?, &mut connect_backend(connection)?)
            .is_err()
    };
    let expired_frame_refused = {
        let binding = authority(0x4200_0105)?;
        let mut client = ClientSession::new(binding.clone());
        let mut server =
            ServerSession::new(binding, MAXIMUM_RESULT_BYTES).map_err(|error| error.to_string())?;
        let deadline = now_unix_us()?.saturating_sub(1);
        let frame = client
            .encode(operation, 256, deadline)
            .map_err(|error| error.to_string())?;
        server
            .execute(&frame, now_unix_us()?, &mut connect_backend(connection)?)
            .is_err()
    };
    let excessive_budget_refused = {
        let binding = authority(0x4200_0106)?;
        let mut client = ClientSession::new(binding.clone());
        let mut server = ServerSession::new(binding, 128).map_err(|error| error.to_string())?;
        let frame = client
            .encode(operation, 256, DEADLINE_UNIX_US)
            .map_err(|error| error.to_string())?;
        server
            .execute(&frame, now_unix_us()?, &mut connect_backend(connection)?)
            .is_err()
    };
    let backend_failure_preserved_nonce = {
        struct Refusal;
        impl Backend for Refusal {
            fn execute(&mut self, _operation: ReadOperation) -> Result<Vec<u8>, AdapterError> {
                Err(AdapterError::backend_refused())
            }
        }
        let binding = authority(0x4200_0107)?;
        let mut client = ClientSession::new(binding.clone());
        let mut server =
            ServerSession::new(binding, MAXIMUM_RESULT_BYTES).map_err(|error| error.to_string())?;
        let frame = client
            .encode(operation, 256, DEADLINE_UNIX_US)
            .map_err(|error| error.to_string())?;
        let refused = server
            .execute(&frame, now_unix_us()?, &mut Refusal)
            .is_err();
        let retried = server
            .execute(&frame, now_unix_us()?, &mut connect_backend(connection)?)
            .is_ok();
        refused && retried
    };
    let arbitrary_sql_refused = serde_json::from_str::<ReadOperation>(
        r#"{"operation":"sql","statement":"DROP TABLE ndabi_v42_items"}"#,
    )
    .is_err();
    let write_operation_refused =
        serde_json::from_str::<ReadOperation>(r#"{"operation":"write","id":1,"score":2}"#).is_err();
    Ok(SecurityReport {
        changed_frame_refused,
        replay_refused,
        cross_session_refused,
        expired_frame_refused,
        excessive_budget_refused,
        backend_failure_preserved_nonce,
        arbitrary_sql_refused,
        write_operation_refused,
    })
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

fn now_unix_us() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?;
    u64::try_from(duration.as_micros()).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn thread_cpu_ns() -> Result<u64, String> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let status = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) };
    if status != 0 || time.tv_sec < 0 || time.tv_nsec < 0 {
        return Err("the thread CPU clock failed".into());
    }
    let seconds = u64::try_from(time.tv_sec).map_err(|error| error.to_string())?;
    let nanoseconds = u64::try_from(time.tv_nsec).map_err(|error| error.to_string())?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| "the thread CPU clock overflowed".into())
}

#[cfg(not(unix))]
fn thread_cpu_ns() -> Result<u64, String> {
    Err("the v4.2 campaign requires a Unix thread CPU clock".into())
}

#[cfg(target_os = "linux")]
fn maximum_rss_kib() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if status != 0 {
        return 0;
    }
    let usage = unsafe { usage.assume_init() };
    u64::try_from(usage.ru_maxrss).unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn maximum_rss_kib() -> u64 {
    0
}

fn hexadecimal(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registered_cases_cover_every_shape_and_scale_boundary() {
        assert_eq!(CASES.len(), 5);
        assert_eq!(CASES[4].operation.result_limit(), 4_096);
        assert_eq!(ROWS, 1_000_000);
    }

    #[test]
    fn the_percentile_uses_the_registered_upper_observation() {
        assert_eq!(percentile(&[1, 2, 3, 4, 5], 0.95), 5);
    }

    #[test]
    fn unsafe_json_operations_refuse() {
        assert!(serde_json::from_str::<ReadOperation>(
            r#"{"operation":"sql","statement":"SELECT 1"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ReadOperation>(r#"{"operation":"write","id":1}"#).is_err());
    }
}
