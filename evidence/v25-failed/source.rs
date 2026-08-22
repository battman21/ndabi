use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use postgres::{Client, NoTls, SimpleQueryMessage, Statement};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::alloc::{begin_measurement, end_measurement};

const TARGET: i64 = 99_999;
const ROWS: i64 = 100_000;
const SAMPLES: usize = 63;
const WARMUP: usize = 5;
const OPERATIONS_PER_SAMPLE: usize = 8;
const FULL_FRAME_BYTES: usize = 72;
const SESSION_FRAME_BYTES: usize = 24;
const SESSION_HANDLE: u32 = 0x2500_0001;
const GENERATION: u32 = 1;
const AUTHORITY: [u8; 32] = [37; 32];
const FRAME_KEY: [u8; 32] = [41; 32];

#[derive(Clone, Copy)]
enum Arm {
    Simple,
    Native,
    Full,
    Session,
    DirectRepeat,
}

impl Arm {
    fn id(self) -> &'static str {
        match self {
            Self::Simple => "simple-sql",
            Self::Native => "native-prepared",
            Self::Full => "full-ndabi",
            Self::Session => "session-ndabi",
            Self::DirectRepeat => "direct-repeat",
        }
    }
}

#[derive(Serialize)]
struct Measurement {
    id: &'static str,
    samples: usize,
    operations_per_sample: usize,
    median_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    operations_per_second: f64,
    allocations_per_operation: f64,
    allocated_bytes_per_operation: f64,
    peak_additional_live_bytes: u64,
    request_bytes: usize,
    response_bytes: usize,
    raw_ns_per_operation: Vec<u64>,
}

#[derive(Serialize)]
struct Ratios {
    simple_over_session_p95: f64,
    full_over_session_p95: f64,
    session_over_native_p95: f64,
    native_over_direct_repeat_p95: f64,
}

#[derive(Serialize)]
struct Gate {
    id: &'static str,
    passed: bool,
    observed: String,
    target: &'static str,
}

#[derive(Serialize)]
struct HardGate {
    passed: bool,
    checks: Vec<Gate>,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    status: &'static str,
    generated_at_unix_seconds: u64,
    postgresql_version: String,
    rows: i64,
    target: i64,
    canonical_response_sha256: String,
    receipt_core_sha256: String,
    measurements: Vec<Measurement>,
    ratios: Ratios,
    hard_gate: HardGate,
    limitations: [&'static str; 4],
}

struct Sample {
    elapsed_ns: u64,
    allocations: u64,
    allocated_bytes: u64,
    peak_additional_live_bytes: u64,
}

struct State {
    client: Client,
    statement: Statement,
    simple_sql: String,
    full_frame: [u8; FULL_FRAME_BYTES],
    session_frame: [u8; SESSION_FRAME_BYTES],
    next_nonce: u64,
    last_session_nonce: u64,
    canonical: Vec<u8>,
    receipt_core: [u8; 32],
}

pub fn run() -> Result<(), String> {
    let connection = std::env::args()
        .nth(1)
        .ok_or_else(|| "supply the PostgreSQL connection string".to_string())?;
    let mut state = create_state(&connection)?;
    prove_refusals(&mut state)?;
    let arms = [
        Arm::Simple,
        Arm::Native,
        Arm::Full,
        Arm::Session,
        Arm::DirectRepeat,
    ];
    for index in 0..WARMUP {
        for offset in 0..arms.len() {
            let arm = arms[(index + offset) % arms.len()];
            for _ in 0..OPERATIONS_PER_SAMPLE {
                black_box(execute_arm(&mut state, arm)?);
            }
        }
    }
    let mut samples: Vec<Vec<Sample>> = arms.iter().map(|_| Vec::with_capacity(SAMPLES)).collect();
    for index in 0..SAMPLES {
        for offset in 0..arms.len() {
            let arm_index = (index + offset) % arms.len();
            let arm = arms[arm_index];
            let allocation_start = begin_measurement();
            let started = Instant::now();
            for _ in 0..OPERATIONS_PER_SAMPLE {
                let (payload, receipt) = execute_arm(&mut state, arm)?;
                if payload != state.canonical || receipt != state.receipt_core {
                    return Err(format!("{} changed the result or receipt core", arm.id()));
                }
                black_box((payload, receipt));
            }
            let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let allocation = end_measurement(allocation_start);
            samples[arm_index].push(Sample {
                elapsed_ns,
                allocations: allocation.allocations,
                allocated_bytes: allocation.allocated_bytes,
                peak_additional_live_bytes: allocation.peak_additional_live_bytes,
            });
        }
    }
    let measurements = arms
        .iter()
        .zip(samples.iter())
        .map(|(arm, values)| finish(*arm, values, state.canonical.len()))
        .collect::<Vec<_>>();
    let simple = measurement(&measurements, "simple-sql")?;
    let native = measurement(&measurements, "native-prepared")?;
    let full = measurement(&measurements, "full-ndabi")?;
    let session = measurement(&measurements, "session-ndabi")?;
    let repeat = measurement(&measurements, "direct-repeat")?;
    let ratios = Ratios {
        simple_over_session_p95: ratio(simple.p95_ns, session.p95_ns),
        full_over_session_p95: ratio(full.p95_ns, session.p95_ns),
        session_over_native_p95: ratio(session.p95_ns, native.p95_ns),
        native_over_direct_repeat_p95: ratio(native.p95_ns, repeat.p95_ns),
    };
    let checks = vec![
        Gate {
            id: "simple-stack-removal",
            passed: ratios.simple_over_session_p95 >= 1.10,
            observed: format!("{:.4}x", ratios.simple_over_session_p95),
            target: "at least 1.10x",
        },
        Gate {
            id: "session-native-distance",
            passed: ratios.session_over_native_p95 <= 1.10,
            observed: format!("{:.4}x", ratios.session_over_native_p95),
            target: "no more than 1.10x",
        },
        Gate {
            id: "full-session-distance",
            passed: ratios.full_over_session_p95 <= 1.50,
            observed: format!("{:.4}x", ratios.full_over_session_p95),
            target: "no more than 1.50x",
        },
        Gate {
            id: "direct-repeat-distance",
            passed: (0.90..=1.10).contains(&ratios.native_over_direct_repeat_p95),
            observed: format!("{:.4}x", ratios.native_over_direct_repeat_p95),
            target: "between 0.90x and 1.10x",
        },
        Gate {
            id: "literal-result-and-receipt-equality",
            passed: true,
            observed: hex(&Sha256::digest(&state.canonical)),
            target: "one canonical payload and receipt core",
        },
        Gate {
            id: "frame-refusals",
            passed: true,
            observed: "tamper, handle, generation, and replay refused".into(),
            target: "all fail closed",
        },
    ];
    let hard_gate = HardGate {
        passed: checks.iter().all(|check| check.passed),
        checks,
    };
    let version = state
        .client
        .query_one("SHOW server_version", &[])
        .map_err(|error| error.to_string())?
        .get::<_, String>(0);
    let report = Report {
        schema: "ndabi-postgresql-real-engine-v2.5",
        status: "loopback-postgresql-measurement",
        generated_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs(),
        postgresql_version: version,
        rows: ROWS,
        target: TARGET,
        canonical_response_sha256: hex(&Sha256::digest(&state.canonical)),
        receipt_core_sha256: hex(&state.receipt_core),
        measurements,
        ratios,
        hard_gate,
        limitations: [
            "Request sizes are application payload sizes, not captured network bytes.",
            "Rust allocation counts exclude PostgreSQL server allocations.",
            "The campaign excludes TLS, pipelines, concurrency, and physical networks.",
            "The native prepared arm identifies the existing PostgreSQL protocol ceiling.",
        ],
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)
        .map_err(|error| error.to_string())?;
    println!();
    if report.hard_gate.passed {
        Ok(())
    } else {
        Err("the v2.5 hard gate failed".into())
    }
}

fn create_state(connection: &str) -> Result<State, String> {
    let mut client = Client::connect(connection, NoTls).map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS ndabi_items (\
             id BIGINT PRIMARY KEY, bucket INTEGER NOT NULL, payload BYTEA NOT NULL);\
             TRUNCATE ndabi_items;\
             INSERT INTO ndabi_items \
             SELECT value, (value % 1024)::INTEGER, decode(repeat(lpad(to_hex(value % 256), 2, '0'), 64), 'hex') \
             FROM generate_series(0, 99999) AS value;\
             ANALYZE ndabi_items;",
        )
        .map_err(|error| error.to_string())?;
    let statement = client
        .prepare("SELECT id, bucket, payload FROM ndabi_items WHERE id = $1")
        .map_err(|error| error.to_string())?;
    let simple_sql =
        format!("SELECT id, bucket, encode(payload, 'hex') FROM ndabi_items WHERE id = {TARGET}");
    let full_frame = encode_full_frame(TARGET as u64, 1);
    let session_frame = encode_session_frame(TARGET as u64, 1);
    let mut state = State {
        client,
        statement,
        simple_sql,
        full_frame,
        session_frame,
        next_nonce: 1,
        last_session_nonce: 0,
        canonical: Vec::new(),
        receipt_core: [0; 32],
    };
    let (payload, receipt) = execute_prepared(&mut state, TARGET)?;
    state.canonical = payload;
    state.receipt_core = receipt;
    Ok(state)
}

fn execute_arm(state: &mut State, arm: Arm) -> Result<(Vec<u8>, [u8; 32]), String> {
    state.next_nonce = state.next_nonce.wrapping_add(1);
    match arm {
        Arm::Simple => execute_simple(state),
        Arm::Native | Arm::DirectRepeat => execute_prepared(state, TARGET),
        Arm::Full => {
            state.full_frame[40..48].copy_from_slice(&state.next_nonce.to_le_bytes());
            authenticate_full_frame(&mut state.full_frame);
            let id = decode_full_frame(&state.full_frame)? as i64;
            execute_prepared(state, id)
        }
        Arm::Session => {
            state.session_frame[16..24].copy_from_slice(&state.next_nonce.to_le_bytes());
            let id =
                decode_session_frame(&state.session_frame, &mut state.last_session_nonce)? as i64;
            execute_prepared(state, id)
        }
    }
}

fn execute_simple(state: &mut State) -> Result<(Vec<u8>, [u8; 32]), String> {
    let messages = state
        .client
        .simple_query(&state.simple_sql)
        .map_err(|error| error.to_string())?;
    let row = messages
        .iter()
        .find_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(row),
            _ => None,
        })
        .ok_or_else(|| "the simple query returned no row".to_string())?;
    let id = row
        .get(0)
        .ok_or_else(|| "missing id".to_string())?
        .parse::<i64>()
        .map_err(|error| error.to_string())?;
    let bucket = row
        .get(1)
        .ok_or_else(|| "missing bucket".to_string())?
        .parse::<i32>()
        .map_err(|error| error.to_string())?;
    let payload = decode_hex(row.get(2).ok_or_else(|| "missing payload".to_string())?)?;
    canonical(id, bucket, &payload)
}

fn execute_prepared(state: &mut State, id: i64) -> Result<(Vec<u8>, [u8; 32]), String> {
    let row = state
        .client
        .query_one(&state.statement, &[&id])
        .map_err(|error| error.to_string())?;
    let returned_id: i64 = row.get(0);
    let bucket: i32 = row.get(1);
    let payload: Vec<u8> = row.get(2);
    canonical(returned_id, bucket, &payload)
}

fn canonical(id: i64, bucket: i32, payload: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    if payload.len() != 64 {
        return Err("the PostgreSQL payload length changed".into());
    }
    let mut bytes = Vec::with_capacity(76);
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(&bucket.to_le_bytes());
    bytes.extend_from_slice(payload);
    let mut receipt = Sha256::new();
    receipt.update(b"ndabi/postgresql/receipt-core/v1");
    receipt.update(AUTHORITY);
    receipt.update(SESSION_HANDLE.to_le_bytes());
    receipt.update(Sha256::digest(&bytes));
    Ok((bytes, receipt.finalize().into()))
}

fn encode_full_frame(id: u64, nonce: u64) -> [u8; FULL_FRAME_BYTES] {
    let mut frame = [0u8; FULL_FRAME_BYTES];
    frame[0..4].copy_from_slice(b"NDBI");
    frame[4] = 1;
    frame[5] = 1;
    frame[8..16].copy_from_slice(&id.to_le_bytes());
    frame[16..24].copy_from_slice(&1u64.to_le_bytes());
    frame[24..32].copy_from_slice(&76u64.to_le_bytes());
    frame[32..40].copy_from_slice(&u64::from(GENERATION).to_le_bytes());
    frame[40..48].copy_from_slice(&nonce.to_le_bytes());
    frame[48..56].copy_from_slice(&AUTHORITY[..8]);
    authenticate_full_frame(&mut frame);
    frame
}

fn authenticate_full_frame(frame: &mut [u8; FULL_FRAME_BYTES]) {
    let tag = blake3::keyed_hash(&FRAME_KEY, &frame[..56]);
    frame[56..72].copy_from_slice(&tag.as_bytes()[..16]);
}

fn decode_full_frame(frame: &[u8; FULL_FRAME_BYTES]) -> Result<u64, String> {
    let tag = blake3::keyed_hash(&FRAME_KEY, &frame[..56]);
    if frame[0..4] != *b"NDBI"
        || frame[4] != 1
        || frame[5] != 1
        || frame[6..8] != [0, 0]
        || frame[32..40] != u64::from(GENERATION).to_le_bytes()
        || frame[48..56] != AUTHORITY[..8]
        || frame[56..72] != tag.as_bytes()[..16]
    {
        return Err("the full NDABI frame is invalid".into());
    }
    Ok(u64::from_le_bytes(frame[8..16].try_into().unwrap()))
}

fn encode_session_frame(id: u64, nonce: u64) -> [u8; SESSION_FRAME_BYTES] {
    let mut frame = [0u8; SESSION_FRAME_BYTES];
    frame[0..4].copy_from_slice(&SESSION_HANDLE.to_le_bytes());
    frame[4..8].copy_from_slice(&GENERATION.to_le_bytes());
    frame[8..16].copy_from_slice(&id.to_le_bytes());
    frame[16..24].copy_from_slice(&nonce.to_le_bytes());
    frame
}

fn decode_session_frame(
    frame: &[u8; SESSION_FRAME_BYTES],
    last_nonce: &mut u64,
) -> Result<u64, String> {
    let handle = u32::from_le_bytes(frame[0..4].try_into().unwrap());
    let generation = u32::from_le_bytes(frame[4..8].try_into().unwrap());
    let nonce = u64::from_le_bytes(frame[16..24].try_into().unwrap());
    if handle != SESSION_HANDLE || generation != GENERATION || nonce <= *last_nonce {
        return Err("the session NDABI frame is invalid or replayed".into());
    }
    *last_nonce = nonce;
    Ok(u64::from_le_bytes(frame[8..16].try_into().unwrap()))
}

fn prove_refusals(state: &mut State) -> Result<(), String> {
    let mut tampered = state.full_frame;
    tampered[8] ^= 1;
    if decode_full_frame(&tampered).is_ok() {
        return Err("a modified full frame was accepted".into());
    }
    let mut wrong_handle = encode_session_frame(TARGET as u64, 1);
    wrong_handle[0] ^= 1;
    let mut nonce = 0;
    if decode_session_frame(&wrong_handle, &mut nonce).is_ok() {
        return Err("a wrong session handle was accepted".into());
    }
    let mut wrong_generation = encode_session_frame(TARGET as u64, 1);
    wrong_generation[4..8].copy_from_slice(&(GENERATION + 1).to_le_bytes());
    if decode_session_frame(&wrong_generation, &mut nonce).is_ok() {
        return Err("a wrong generation was accepted".into());
    }
    let replay = encode_session_frame(TARGET as u64, 2);
    decode_session_frame(&replay, &mut nonce)?;
    if decode_session_frame(&replay, &mut nonce).is_ok() {
        return Err("a replayed nonce was accepted".into());
    }
    Ok(())
}

fn finish(arm: Arm, samples: &[Sample], response_bytes: usize) -> Measurement {
    let mut elapsed = samples
        .iter()
        .map(|sample| sample.elapsed_ns / OPERATIONS_PER_SAMPLE as u64)
        .collect::<Vec<_>>();
    elapsed.sort_unstable();
    let total = samples
        .iter()
        .map(|sample| u128::from(sample.elapsed_ns))
        .sum::<u128>();
    let operations = (samples.len() * OPERATIONS_PER_SAMPLE) as f64;
    Measurement {
        id: arm.id(),
        samples: samples.len(),
        operations_per_sample: OPERATIONS_PER_SAMPLE,
        median_ns: percentile(&elapsed, 0.50),
        p95_ns: percentile(&elapsed, 0.95),
        p99_ns: percentile(&elapsed, 0.99),
        operations_per_second: operations / (total as f64 / 1_000_000_000.0),
        allocations_per_operation: samples.iter().map(|sample| sample.allocations).sum::<u64>()
            as f64
            / operations,
        allocated_bytes_per_operation: samples
            .iter()
            .map(|sample| sample.allocated_bytes)
            .sum::<u64>() as f64
            / operations,
        peak_additional_live_bytes: samples
            .iter()
            .map(|sample| sample.peak_additional_live_bytes)
            .max()
            .unwrap_or(0),
        request_bytes: match arm {
            Arm::Simple => 82,
            Arm::Native | Arm::DirectRepeat => 8,
            Arm::Full => FULL_FRAME_BYTES,
            Arm::Session => SESSION_FRAME_BYTES,
        },
        response_bytes,
        raw_ns_per_operation: elapsed,
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

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("the hexadecimal payload has an odd length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_payload_round_trips() {
        assert_eq!(decode_hex("00ff10").unwrap(), [0, 255, 16]);
    }

    #[test]
    fn session_replay_fails() {
        let frame = encode_session_frame(7, 1);
        let mut last = 0;
        assert_eq!(decode_session_frame(&frame, &mut last).unwrap(), 7);
        assert!(decode_session_frame(&frame, &mut last).is_err());
    }
}
