use std::collections::BTreeSet;
use std::fs;
use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use arrow_array::{Array, Int64Array, RecordBatch, UInt32Array, UInt64Array};
use olx_core::auth::{CapabilityClaims, CapabilityIssuer, CapabilityVerificationKeyring};
use olx_core::database::{database_governed_read_resource, Database, ACTION_DATABASE_READ};
use olx_core::fixtures::software_ops_corpus;
use olx_core::governance::{ClassificationState, GovernanceLabel, GovernedExecutionReceipt};
use olx_core::model::{
    EntityId, EventId, EvidenceRef, ExportProfile, PartitionId, ScanPredicate, SensitivityClass,
    TrajectoryId, TrajectoryVersion,
};
use olx_core::scan::EgressMode;
use olx_core::signature::SigningIdentity;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::alloc::{begin_measurement, end_measurement};

const DATABASE_ID: &str = "db:ndabi-v22";
const TENANT_ID: &str = "tenant:ndabi-v22";
const PRINCIPAL: &str = "agent:ndabi-v22";
const PURPOSE: &str = "benchmark:governed-read";
const TRAJECTORIES: u64 = 10_000;
const PARTITIONS: u64 = 100;
const TARGET: u64 = TRAJECTORIES - 1;
const SAMPLES: usize = 63;
const WARMUP: usize = 5;
const FULL_FRAME_BYTES: usize = 72;
const SESSION_FRAME_BYTES: usize = 24;
const SESSION_HANDLE: u32 = 0x2200_0001;

#[derive(Clone, Copy)]
enum Arm {
    Sql,
    Full,
    Session,
    Native,
    DirectRepeat,
}

impl Arm {
    fn id(self) -> &'static str {
        match self {
            Self::Sql => "governed-sql",
            Self::Full => "full-ndabi",
            Self::Session => "session-ndabi",
            Self::Native => "native-typed",
            Self::DirectRepeat => "direct-repeat",
        }
    }
}

#[derive(Serialize)]
struct Measurement {
    id: &'static str,
    samples: usize,
    median_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    operations_per_second: f64,
    allocations_per_operation: f64,
    allocated_bytes_per_operation: f64,
    peak_additional_live_bytes: u64,
    request_bytes: usize,
    response_bytes: usize,
    raw_ns: Vec<u64>,
}

#[derive(Serialize)]
struct Gate {
    id: &'static str,
    passed: bool,
    observed: String,
    target: &'static str,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    status: &'static str,
    generated_at_unix_seconds: u64,
    source_fingerprint_sha256: String,
    database_id: &'static str,
    tenant_id: &'static str,
    trajectories: u64,
    partitions: u64,
    target_trajectory: u64,
    database_data_root_sha256: String,
    canonical_response_sha256: String,
    canonical_response_bytes: usize,
    measurements: Vec<Measurement>,
    ratios: Ratios,
    hard_gate: HardGate,
    limitations: [&'static str; 5],
}

#[derive(Serialize)]
struct Ratios {
    sql_over_session_p95: f64,
    full_over_session_p95: f64,
    session_over_native_p95: f64,
    native_over_direct_repeat_p95: f64,
}

#[derive(Serialize)]
struct HardGate {
    passed: bool,
    checks: Vec<Gate>,
}

struct Sample {
    elapsed_ns: u64,
    allocations: u64,
    allocated_bytes: u64,
    peak_additional_live_bytes: u64,
}

struct State {
    runtime: tokio::runtime::Runtime,
    snapshot: olx_core::database::GovernedSnapshot,
    sql: String,
    full_frame: [u8; FULL_FRAME_BYTES],
    session_frame: [u8; SESSION_FRAME_BYTES],
    frame_key: [u8; 32],
    next_nonce: u64,
    last_session_nonce: u64,
    canonical: Vec<u8>,
}

pub fn run() -> Result<(), String> {
    let (directory, mut state) = create_state()?;
    let result = execute(&mut state);
    drop(state);
    fs::remove_dir_all(directory.path()).map_err(|error| error.to_string())?;
    result
}

fn execute(state: &mut State) -> Result<(), String> {
    prove_refusals(state)?;
    let arms = [
        Arm::Sql,
        Arm::Full,
        Arm::Session,
        Arm::Native,
        Arm::DirectRepeat,
    ];
    for index in 0..WARMUP {
        for offset in 0..arms.len() {
            let arm = arms[(index + offset) % arms.len()];
            black_box(execute_arm(state, arm)?);
        }
    }

    let mut samples: Vec<Vec<Sample>> = arms.iter().map(|_| Vec::with_capacity(SAMPLES)).collect();
    for index in 0..SAMPLES {
        for offset in 0..arms.len() {
            let arm_index = (index + offset) % arms.len();
            let arm = arms[arm_index];
            let allocation_start = begin_measurement();
            let started = Instant::now();
            let payload = execute_arm(state, arm)?;
            let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let allocation = end_measurement(allocation_start);
            if payload != state.canonical {
                return Err(format!(
                    "{} returned a different canonical payload",
                    arm.id()
                ));
            }
            black_box(payload);
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
    let sql = measurement(&measurements, "governed-sql")?;
    let full = measurement(&measurements, "full-ndabi")?;
    let session = measurement(&measurements, "session-ndabi")?;
    let native = measurement(&measurements, "native-typed")?;
    let repeat = measurement(&measurements, "direct-repeat")?;
    let ratios = Ratios {
        sql_over_session_p95: ratio(sql.p95_ns, session.p95_ns),
        full_over_session_p95: ratio(full.p95_ns, session.p95_ns),
        session_over_native_p95: ratio(session.p95_ns, native.p95_ns),
        native_over_direct_repeat_p95: ratio(native.p95_ns, repeat.p95_ns),
    };
    let checks = vec![
        Gate {
            id: "sql-stack-removal",
            passed: ratios.sql_over_session_p95 >= 2.5,
            observed: format!("{:.4}x", ratios.sql_over_session_p95),
            target: "at least 2.5x",
        },
        Gate {
            id: "session-native-distance",
            passed: (0.90..=1.10).contains(&ratios.session_over_native_p95),
            observed: format!("{:.4}x", ratios.session_over_native_p95),
            target: "between 0.90x and 1.10x",
        },
        Gate {
            id: "direct-repeat-distance",
            passed: (0.90..=1.10).contains(&ratios.native_over_direct_repeat_p95),
            observed: format!("{:.4}x", ratios.native_over_direct_repeat_p95),
            target: "between 0.90x and 1.10x",
        },
        Gate {
            id: "literal-semantic-equality",
            passed: true,
            observed: hex(&Sha256::digest(&state.canonical)),
            target: "one byte-identical canonical payload",
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
    let report = Report {
        schema: "ndabi-white-tree-real-engine-v2.2",
        status: "signed-white-tree-governed-read-measurement",
        generated_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs(),
        source_fingerprint_sha256: source_fingerprint(),
        database_id: DATABASE_ID,
        tenant_id: TENANT_ID,
        trajectories: TRAJECTORIES,
        partitions: PARTITIONS,
        target_trajectory: TARGET,
        database_data_root_sha256: hex(&state.snapshot.data_root_sha256()),
        canonical_response_sha256: hex(&Sha256::digest(&state.canonical)),
        canonical_response_bytes: state.canonical.len(),
        measurements,
        ratios,
        hard_gate,
        limitations: [
            "This result covers one White Tree point-query shape.",
            "The build uses development software signing for an isolated benchmark fixture.",
            "The campaign excludes sockets, TLS, concurrency, energy, and provider tokens.",
            "The SQL arm uses DataFusion while NDABI selects the native governed Arrow surface.",
            "The native typed arm identifies the gain caused by layer removal, not binary syntax.",
        ],
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)
        .map_err(|error| error.to_string())?;
    println!();
    if report.hard_gate.passed {
        Ok(())
    } else {
        Err("the v2.2 hard gate failed".into())
    }
}

fn create_state() -> Result<(tempfile::TempDir, State), String> {
    let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    let signer = SigningIdentity::from_seed("ndabi-v22-database", [22; 32], 0, 1_000_000)
        .map_err(|error| format!("database signer: {error:?}"))?;
    let parts = dataset();
    Database::create_tenant(directory.path(), DATABASE_ID, TENANT_ID, parts, 10, &signer)
        .map_err(|error| format!("create database: {error:?}"))?;
    let mut database_keys = olx_core::signature::VerificationKeyring::default();
    database_keys
        .add(signer.public_key_record())
        .map_err(|error| format!("database key: {error:?}"))?;
    let database = Database::open(directory.path(), database_keys)
        .map_err(|error| format!("open database: {error:?}"))?;
    let profile = profile();
    let label = label();
    let resource = database_governed_read_resource(DATABASE_ID, &profile, &label);
    let issuer = CapabilityIssuer::new(
        SigningIdentity::from_seed("ndabi-v22-authority", [23; 32], 0, 1_000_000)
            .map_err(|error| format!("authority signer: {error:?}"))?,
    );
    let token = issuer
        .mint(
            CapabilityClaims {
                schema_version: 2,
                issuer: String::new(),
                key_id: String::new(),
                tenant: TENANT_ID.into(),
                principal: PRINCIPAL.into(),
                actions: [ACTION_DATABASE_READ.into()].into_iter().collect(),
                resources: [resource].into_iter().collect(),
                purposes: [PURPOSE.into()].into_iter().collect(),
                not_before: 0,
                expires_at: 1_000_000,
                nonce: "ndabi-v22-capability".into(),
            },
            0,
        )
        .map_err(|error| format!("mint capability: {error:?}"))?;
    let mut capability_keys = CapabilityVerificationKeyring::new("ndabi-v22-authority")
        .map_err(|error| format!("capability keyring: {error:?}"))?;
    capability_keys
        .add_key(issuer.public_key_record())
        .map_err(|error| format!("capability key: {error:?}"))?;
    let session = database
        .authenticate(&capability_keys, &token, 15, PURPOSE)
        .map_err(|error| format!("authenticate: {error:?}"))?;
    let snapshot = session
        .governed_snapshot(profile, label)
        .map_err(|error| format!("governed snapshot: {error:?}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .map_err(|error| error.to_string())?;
    let sql = format!(
        "SELECT trajectory_id, event_id, role, valid_time_us, system_time_us, withheld_count \
         FROM trajectories WHERE trajectory_id = {TARGET} ORDER BY member_ordinal"
    );
    let frame_key = [29; 32];
    let full_frame = encode_full_frame(&snapshot, TARGET, 1, &frame_key);
    let session_frame = encode_session_frame(snapshot.generation(), TARGET, 1);
    let mut state = State {
        runtime,
        snapshot,
        sql,
        full_frame,
        session_frame,
        frame_key,
        next_nonce: 1,
        last_session_nonce: 0,
        canonical: Vec::new(),
    };
    state.canonical = execute_native(&state)?;
    Ok((directory, state))
}

fn dataset() -> Vec<(PartitionId, Vec<TrajectoryVersion>)> {
    let template = software_ops_corpus().remove(0);
    let per_partition = TRAJECTORIES / PARTITIONS;
    (0..PARTITIONS)
        .map(|partition| {
            let versions = (0..per_partition)
                .map(|offset| {
                    let id = partition * per_partition + offset;
                    let mut version = template.clone();
                    version.trajectory_id = TrajectoryId(id);
                    version.subject = EntityId(id + 1);
                    for member in &mut version.members {
                        let ordinal = u64::from(member.ordinal);
                        member.event_id = EventId(id * 10 + ordinal + 1);
                        member.evidence = vec![EvidenceRef(id * 10 + ordinal + 1)];
                    }
                    version
                })
                .collect();
            (PartitionId(partition + 1), versions)
        })
        .collect()
}

fn profile() -> ExportProfile {
    ExportProfile {
        profile_bit: u32::MAX,
        allowed_max_sensitivity: SensitivityClass::LegalPrivilege,
        allowed_jurisdictions: u32::MAX,
        permitted_rights: u32::MAX,
    }
}

fn label() -> GovernanceLabel {
    GovernanceLabel {
        classification: ClassificationState::Classified,
        data_categories: BTreeSet::from(["benchmark:trajectory".into()]),
        permitted_purposes: BTreeSet::from([PURPOSE.into()]),
        legal_bases: BTreeSet::from(["benchmark:authorised".into()]),
        policy_id: Some("ndabi-v22".into()),
        policy_version: Some("1".into()),
        ..GovernanceLabel::default()
    }
}

fn execute_arm(state: &mut State, arm: Arm) -> Result<Vec<u8>, String> {
    state.next_nonce = state.next_nonce.wrapping_add(1);
    match arm {
        Arm::Sql => execute_sql(state),
        Arm::Full => {
            state.full_frame[40..48].copy_from_slice(&state.next_nonce.to_le_bytes());
            authenticate_full_frame(&mut state.full_frame, &state.frame_key);
            let trajectory = decode_full_frame(
                &state.full_frame,
                state.snapshot.authority().binding_sha256,
                &state.frame_key,
            )?;
            execute_typed(state, trajectory)
        }
        Arm::Session => {
            state.session_frame[16..24].copy_from_slice(&state.next_nonce.to_le_bytes());
            let trajectory = decode_session_frame(
                &state.session_frame,
                state.snapshot.generation(),
                &mut state.last_session_nonce,
            )?;
            execute_typed(state, trajectory)
        }
        Arm::Native | Arm::DirectRepeat => execute_native(state),
    }
}

fn execute_sql(state: &mut State) -> Result<Vec<u8>, String> {
    let result = state
        .runtime
        .block_on(state.snapshot.query_sql(
            &state.sql,
            ScanPredicate::default(),
            None,
            None,
            EgressMode::MixedMasked,
            u64::MAX,
            10,
            1,
        ))
        .map_err(|error| format!("SQL query: {error:?}"))?;
    verify_receipt(&result.receipt, &state.snapshot)?;
    canonical_sql(&result.batches)
}

fn execute_native(state: &State) -> Result<Vec<u8>, String> {
    execute_typed(state, TARGET)
}

fn execute_typed(state: &State, trajectory: u64) -> Result<Vec<u8>, String> {
    let result = state
        .snapshot
        .query_arrow(
            ScanPredicate {
                entity: None,
                trajectory: Some(TrajectoryId(trajectory)),
            },
            None,
            None,
            EgressMode::MixedMasked,
        )
        .map_err(|error| format!("Arrow query: {error:?}"))?;
    verify_receipt(&result.receipt, &state.snapshot)?;
    canonical_arrow(&result.batch)
}

fn verify_receipt(
    receipt: &GovernedExecutionReceipt,
    snapshot: &olx_core::database::GovernedSnapshot,
) -> Result<(), String> {
    receipt
        .verify()
        .map_err(|error| format!("receipt verification: {error:?}"))?;
    if receipt.database_id != DATABASE_ID
        || receipt.tenant_id != TENANT_ID
        || receipt.generation != snapshot.generation()
        || receipt.data_root_sha256 != snapshot.data_root_sha256()
        || receipt.authorization.decision.principal != PRINCIPAL
        || receipt.authorization.decision.purpose != PURPOSE
        || receipt.authorization.binding_sha256 != snapshot.authority().binding_sha256
    {
        return Err("the governed receipt lost an authority or snapshot binding".into());
    }
    Ok(())
}

fn canonical_sql(batches: &[RecordBatch]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for batch in batches {
        append_columns(batch, [0, 1, 2, 3, 4, 5], &mut bytes)?;
    }
    Ok(bytes)
}

fn canonical_arrow(batch: &RecordBatch) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    append_columns(batch, [0, 3, 4, 5, 6, 8], &mut bytes)?;
    Ok(bytes)
}

fn append_columns(
    batch: &RecordBatch,
    columns: [usize; 6],
    bytes: &mut Vec<u8>,
) -> Result<(), String> {
    let trajectory = batch
        .column(columns[0])
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or_else(|| "trajectory column type changed".to_string())?;
    let event = batch
        .column(columns[1])
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or_else(|| "event column type changed".to_string())?;
    let role = batch
        .column(columns[2])
        .as_any()
        .downcast_ref::<UInt32Array>()
        .ok_or_else(|| "role column type changed".to_string())?;
    let valid = batch
        .column(columns[3])
        .as_any()
        .downcast_ref::<Int64Array>()
        .ok_or_else(|| "valid-time column type changed".to_string())?;
    let system = batch
        .column(columns[4])
        .as_any()
        .downcast_ref::<Int64Array>()
        .ok_or_else(|| "system-time column type changed".to_string())?;
    let withheld = batch
        .column(columns[5])
        .as_any()
        .downcast_ref::<UInt32Array>()
        .ok_or_else(|| "withheld column type changed".to_string())?;
    for row in 0..batch.num_rows() {
        if trajectory.is_null(row)
            || event.is_null(row)
            || role.is_null(row)
            || valid.is_null(row)
            || system.is_null(row)
            || withheld.is_null(row)
        {
            return Err("the scalar benchmark result contains a null".into());
        }
        bytes.extend_from_slice(&trajectory.value(row).to_le_bytes());
        bytes.extend_from_slice(&event.value(row).to_le_bytes());
        bytes.extend_from_slice(&role.value(row).to_le_bytes());
        bytes.extend_from_slice(&valid.value(row).to_le_bytes());
        bytes.extend_from_slice(&system.value(row).to_le_bytes());
        bytes.extend_from_slice(&withheld.value(row).to_le_bytes());
    }
    Ok(())
}

fn encode_full_frame(
    snapshot: &olx_core::database::GovernedSnapshot,
    trajectory: u64,
    nonce: u64,
    key: &[u8; 32],
) -> [u8; FULL_FRAME_BYTES] {
    let mut frame = [0u8; FULL_FRAME_BYTES];
    frame[0..4].copy_from_slice(b"NDBI");
    frame[4] = 1;
    frame[5] = 1;
    frame[8..16].copy_from_slice(&trajectory.to_le_bytes());
    frame[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    frame[24..32].copy_from_slice(&10u64.to_le_bytes());
    frame[32..40].copy_from_slice(&snapshot.generation().to_le_bytes());
    frame[40..48].copy_from_slice(&nonce.to_le_bytes());
    frame[48..56].copy_from_slice(&snapshot.authority().binding_sha256[..8]);
    authenticate_full_frame(&mut frame, key);
    frame
}

fn authenticate_full_frame(frame: &mut [u8; FULL_FRAME_BYTES], key: &[u8; 32]) {
    let tag = blake3::keyed_hash(key, &frame[..56]);
    frame[56..72].copy_from_slice(&tag.as_bytes()[..16]);
}

fn decode_full_frame(
    frame: &[u8; FULL_FRAME_BYTES],
    authority: [u8; 32],
    key: &[u8; 32],
) -> Result<u64, String> {
    let tag = blake3::keyed_hash(key, &frame[..56]);
    if frame[0..4] != *b"NDBI"
        || frame[4] != 1
        || frame[5] != 1
        || frame[6..8] != [0, 0]
        || frame[16..24] != u64::MAX.to_le_bytes()
        || frame[24..32] != 10u64.to_le_bytes()
        || frame[48..56] != authority[..8]
        || frame[56..72] != tag.as_bytes()[..16]
    {
        return Err("the full NDABI frame is invalid".into());
    }
    Ok(u64::from_le_bytes(frame[8..16].try_into().unwrap()))
}

fn encode_session_frame(generation: u64, trajectory: u64, nonce: u64) -> [u8; 24] {
    let mut frame = [0u8; 24];
    frame[0..4].copy_from_slice(&SESSION_HANDLE.to_le_bytes());
    frame[4..8].copy_from_slice(&(generation as u32).to_le_bytes());
    frame[8..16].copy_from_slice(&trajectory.to_le_bytes());
    frame[16..24].copy_from_slice(&nonce.to_le_bytes());
    frame
}

fn decode_session_frame(
    frame: &[u8; 24],
    generation: u64,
    last_nonce: &mut u64,
) -> Result<u64, String> {
    let handle = u32::from_le_bytes(frame[0..4].try_into().unwrap());
    let frame_generation = u32::from_le_bytes(frame[4..8].try_into().unwrap());
    let nonce = u64::from_le_bytes(frame[16..24].try_into().unwrap());
    if handle != SESSION_HANDLE || u64::from(frame_generation) != generation || nonce <= *last_nonce
    {
        return Err("the session NDABI frame is invalid or replayed".into());
    }
    *last_nonce = nonce;
    Ok(u64::from_le_bytes(frame[8..16].try_into().unwrap()))
}

fn prove_refusals(state: &mut State) -> Result<(), String> {
    let mut tampered = state.full_frame;
    tampered[8] ^= 1;
    if decode_full_frame(
        &tampered,
        state.snapshot.authority().binding_sha256,
        &state.frame_key,
    )
    .is_ok()
    {
        return Err("a modified full frame was accepted".into());
    }
    let mut wrong_handle = encode_session_frame(state.snapshot.generation(), TARGET, 1);
    wrong_handle[0] ^= 1;
    let mut nonce = 0;
    if decode_session_frame(&wrong_handle, state.snapshot.generation(), &mut nonce).is_ok() {
        return Err("a wrong session handle was accepted".into());
    }
    let wrong_generation = encode_session_frame(state.snapshot.generation() + 1, TARGET, 1);
    if decode_session_frame(&wrong_generation, state.snapshot.generation(), &mut nonce).is_ok() {
        return Err("a wrong database generation was accepted".into());
    }
    let replay = encode_session_frame(state.snapshot.generation(), TARGET, 2);
    decode_session_frame(&replay, state.snapshot.generation(), &mut nonce)?;
    if decode_session_frame(&replay, state.snapshot.generation(), &mut nonce).is_ok() {
        return Err("a replayed session nonce was accepted".into());
    }
    Ok(())
}

fn finish(arm: Arm, samples: &[Sample], response_bytes: usize) -> Measurement {
    let mut elapsed = samples
        .iter()
        .map(|sample| sample.elapsed_ns)
        .collect::<Vec<_>>();
    elapsed.sort_unstable();
    let total = elapsed.iter().map(|value| u128::from(*value)).sum::<u128>();
    let operations = samples.len() as f64;
    Measurement {
        id: arm.id(),
        samples: samples.len(),
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
            Arm::Sql => 149,
            Arm::Full => FULL_FRAME_BYTES,
            Arm::Session => SESSION_FRAME_BYTES,
            Arm::Native | Arm::DirectRepeat => 0,
        },
        response_bytes,
        raw_ns: elapsed,
    }
}

fn measurement<'a>(values: &'a [Measurement], id: &str) -> Result<&'a Measurement, String> {
    values
        .iter()
        .find(|value| value.id == id)
        .ok_or_else(|| format!("missing measurement {id}"))
}

fn percentile(sorted: &[u64], quantile: f64) -> u64 {
    let index = ((sorted.len() - 1) as f64 * quantile).ceil() as usize;
    sorted[index]
}

fn ratio(left: u64, right: u64) -> f64 {
    left as f64 / right.max(1) as f64
}

fn source_fingerprint() -> String {
    let mut hash = Sha256::new();
    hash.update(include_bytes!("mod.rs"));
    hash.update(include_bytes!("../../Cargo.toml"));
    hex(&hash.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_frame_tampering_fails() {
        let key = [7; 32];
        let mut frame = [0u8; FULL_FRAME_BYTES];
        frame[0..4].copy_from_slice(b"NDBI");
        frame[4] = 1;
        frame[5] = 1;
        frame[8..16].copy_from_slice(&9u64.to_le_bytes());
        frame[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        frame[24..32].copy_from_slice(&10u64.to_le_bytes());
        frame[48..56].copy_from_slice(&[3; 8]);
        authenticate_full_frame(&mut frame, &key);
        assert_eq!(decode_full_frame(&frame, [3; 32], &key).unwrap(), 9);
        frame[8] ^= 1;
        assert!(decode_full_frame(&frame, [3; 32], &key).is_err());
    }

    #[test]
    fn session_frame_replay_fails() {
        let frame = encode_session_frame(4, 9, 1);
        let mut last = 0;
        assert_eq!(decode_session_frame(&frame, 4, &mut last).unwrap(), 9);
        assert!(decode_session_frame(&frame, 4, &mut last).is_err());
    }
}
