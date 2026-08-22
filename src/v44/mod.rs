use ndabi_session::{Authority, Backend, ClientSession, RawOperation, ServerSession, FRAME_BYTES};
use serde::{Deserialize, Serialize};

use crate::measure::{finish_arm, measure_batch, ArmBatch, ArmMeasurement, Observation};
use crate::white_tree::WhiteTreePreparedBackend;
use crate::wire::Digest64;

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;
const MAXIMUM_RESULT_BYTES: u32 = 8_192;
const BLOCKS: usize = 20;
const SCHEDULE: [[Arm; 3]; 3] = [
    [Arm::Direct, Arm::Json, Arm::Ndabi],
    [Arm::Json, Arm::Ndabi, Arm::Direct],
    [Arm::Ndabi, Arm::Direct, Arm::Json],
];

#[derive(Clone, Copy)]
enum Arm {
    Direct,
    Json,
    Ndabi,
}

impl Arm {
    fn index(self) -> usize {
        match self {
            Self::Direct => 0,
            Self::Json => 1,
            Self::Ndabi => 2,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct NamedRequest {
    operation: String,
    trajectory_id: i64,
    snapshot_handle: i64,
    seed_member_ordinal: u32,
    maximum_causal_hops: u32,
}

impl NamedRequest {
    fn fixed() -> Self {
        Self {
            operation: "assemble_governed_context".to_string(),
            trajectory_id: 100,
            snapshot_handle: 1,
            seed_member_ordinal: 3,
            maximum_causal_hops: 3,
        }
    }

    fn operation(self) -> Result<RawOperation, String> {
        if self != Self::fixed() {
            return Err("the named request is not authorised".to_string());
        }
        Ok(WhiteTreePreparedBackend::operation())
    }
}

impl PartialEq for NamedRequest {
    fn eq(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.trajectory_id == other.trajectory_id
            && self.snapshot_handle == other.snapshot_handle
            && self.seed_member_ordinal == other.seed_member_ordinal
            && self.maximum_causal_hops == other.maximum_causal_hops
    }
}

struct DirectState {
    backend: WhiteTreePreparedBackend,
}

impl DirectState {
    fn observe(&mut self) -> Result<Observation, String> {
        let bytes = self
            .backend
            .execute(WhiteTreePreparedBackend::operation())
            .map_err(|error| error.to_string())?;
        observation(&bytes)
    }
}

struct JsonState {
    backend: WhiteTreePreparedBackend,
    request: Vec<u8>,
}

struct EqualJsonState {
    backend: WhiteTreePreparedBackend,
    request: Vec<u8>,
    client: ClientSession,
    server: ServerSession,
}

impl EqualJsonState {
    fn observe(&mut self) -> Result<Observation, String> {
        self.request.clear();
        serde_json::to_writer(&mut self.request, &NamedRequest::fixed())
            .map_err(|error| error.to_string())?;
        let request: NamedRequest =
            serde_json::from_slice(&self.request).map_err(|error| error.to_string())?;
        let frame = self
            .client
            .encode(request.operation()?, MAXIMUM_RESULT_BYTES, DEADLINE)
            .map_err(|error| error.to_string())?;
        let result = self
            .server
            .execute(&frame, NOW, &mut self.backend)
            .map_err(|error| error.to_string())?;
        observation(&result.bytes)
    }
}

impl JsonState {
    fn observe(&mut self) -> Result<Observation, String> {
        self.request.clear();
        serde_json::to_writer(&mut self.request, &NamedRequest::fixed())
            .map_err(|error| error.to_string())?;
        let request: NamedRequest =
            serde_json::from_slice(&self.request).map_err(|error| error.to_string())?;
        let bytes = self
            .backend
            .execute(request.operation()?)
            .map_err(|error| error.to_string())?;
        observation(&bytes)
    }
}

struct NdabiState {
    backend: WhiteTreePreparedBackend,
    client: ClientSession,
    server: ServerSession,
}

impl NdabiState {
    fn observe(&mut self) -> Result<Observation, String> {
        let frame = self
            .client
            .encode(
                WhiteTreePreparedBackend::operation(),
                MAXIMUM_RESULT_BYTES,
                DEADLINE,
            )
            .map_err(|error| error.to_string())?;
        let result = self
            .server
            .execute(&frame, NOW, &mut self.backend)
            .map_err(|error| error.to_string())?;
        observation(&result.bytes)
    }
}

fn observation(bytes: &[u8]) -> Result<Observation, String> {
    let mut digest = Digest64::new();
    digest.update(bytes);
    let digest = digest.finish();
    Ok(Observation {
        response_bytes: bytes.len(),
        semantic_digest: digest,
        view_digest: digest,
        rendered_bytes: 0,
    })
}

#[derive(Serialize)]
struct Gates {
    exact_results: bool,
    refusals: String,
    request_compression_passed: bool,
    per_process_latency_passed: bool,
    passed: bool,
}

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    iterations: usize,
    warmup: usize,
    measurement_blocks: usize,
    arms: Vec<ArmMeasurement>,
    request_compression: f64,
    ndabi_json_p95_ratio: f64,
    ndabi_direct_p95_ratio: f64,
    gates: Gates,
}

pub fn run() -> Result<(), String> {
    let (iterations, warmup) = arguments()?;
    if iterations < BLOCKS || warmup < BLOCKS {
        return Err("iterations and warm-up must each be at least 20".to_string());
    }
    let authority = authority(44)?;
    let mut direct = DirectState {
        backend: WhiteTreePreparedBackend::new()?,
    };
    let mut json = JsonState {
        backend: WhiteTreePreparedBackend::new()?,
        request: Vec::with_capacity(256),
    };
    let mut ndabi = NdabiState {
        backend: WhiteTreePreparedBackend::new()?,
        client: ClientSession::new(authority.clone()),
        server: ServerSession::new(authority, MAXIMUM_RESULT_BYTES)
            .map_err(|error| error.to_string())?,
    };
    let direct_identity = direct.observe()?;
    let json_identity = json.observe()?;
    let ndabi_identity = ndabi.observe()?;
    let exact_results = direct_identity.semantic_digest == json_identity.semantic_digest
        && json_identity.semantic_digest == ndabi_identity.semantic_digest
        && direct_identity.response_bytes == json_identity.response_bytes
        && json_identity.response_bytes == ndabi_identity.response_bytes;
    let json_request_bytes = serde_json::to_vec(&NamedRequest::fixed())
        .map_err(|error| error.to_string())?
        .len();
    let request_compression = 1.0 - FRAME_BYTES as f64 / json_request_bytes as f64;
    let refusal_count = refusal_suite()?;

    let samples_per_block = iterations / BLOCKS;
    let warmup_per_block = warmup / BLOCKS;
    let mut batches: [Vec<ArmBatch>; 3] = std::array::from_fn(|_| Vec::new());
    for block in 0..BLOCKS {
        let round = SCHEDULE[block % SCHEDULE.len()];
        for arm in round {
            let batch = match arm {
                Arm::Direct => {
                    measure_batch(samples_per_block, warmup_per_block, || direct.observe())
                }
                Arm::Json => measure_batch(samples_per_block, warmup_per_block, || json.observe()),
                Arm::Ndabi => {
                    measure_batch(samples_per_block, warmup_per_block, || ndabi.observe())
                }
            }?;
            batches[arm.index()].push(batch);
        }
    }
    let arms = vec![
        finish_arm(
            "direct",
            "direct prepared White Tree",
            0,
            0,
            true,
            std::mem::take(&mut batches[0]),
        )?,
        finish_arm(
            "json",
            "named JSON prepared White Tree",
            json_request_bytes,
            json.request.capacity(),
            true,
            std::mem::take(&mut batches[1]),
        )?,
        finish_arm(
            "ndabi",
            "shared-session NDABI White Tree",
            FRAME_BYTES,
            FRAME_BYTES,
            true,
            std::mem::take(&mut batches[2]),
        )?,
    ];
    let direct_p95 = arms[0].p95_ns as f64;
    let json_p95 = arms[1].p95_ns as f64;
    let ndabi_p95 = arms[2].p95_ns as f64;
    let per_process_latency_passed = ndabi_p95 <= json_p95 * 1.10;
    let gates = Gates {
        exact_results,
        refusals: format!("{refusal_count}/6"),
        request_compression_passed: request_compression >= 0.35,
        per_process_latency_passed,
        passed: exact_results
            && refusal_count == 6
            && request_compression >= 0.35
            && per_process_latency_passed,
    };
    let report = Report {
        campaign: "NDABI shared-session White Tree v4.4",
        iterations: samples_per_block * BLOCKS,
        warmup: warmup_per_block * BLOCKS,
        measurement_blocks: BLOCKS,
        arms,
        request_compression,
        ndabi_json_p95_ratio: ndabi_p95 / json_p95,
        ndabi_direct_p95_ratio: ndabi_p95 / direct_p95,
        gates,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
    );
    Ok(())
}

pub fn run_v45() -> Result<(), String> {
    let (iterations, warmup) = arguments()?;
    if iterations < BLOCKS || warmup < BLOCKS {
        return Err("iterations and warm-up must each be at least 20".to_string());
    }
    let json_authority = authority(45)?;
    let ndabi_authority = authority(46)?;
    let mut direct = DirectState {
        backend: WhiteTreePreparedBackend::new()?,
    };
    let mut json = EqualJsonState {
        backend: WhiteTreePreparedBackend::new()?,
        request: Vec::with_capacity(256),
        client: ClientSession::new(json_authority.clone()),
        server: ServerSession::new(json_authority, MAXIMUM_RESULT_BYTES)
            .map_err(|error| error.to_string())?,
    };
    let mut ndabi = NdabiState {
        backend: WhiteTreePreparedBackend::new()?,
        client: ClientSession::new(ndabi_authority.clone()),
        server: ServerSession::new(ndabi_authority, MAXIMUM_RESULT_BYTES)
            .map_err(|error| error.to_string())?,
    };
    let direct_identity = direct.observe()?;
    let json_identity = json.observe()?;
    let ndabi_identity = ndabi.observe()?;
    let exact_results = direct_identity.semantic_digest == json_identity.semantic_digest
        && json_identity.semantic_digest == ndabi_identity.semantic_digest
        && direct_identity.response_bytes == json_identity.response_bytes
        && json_identity.response_bytes == ndabi_identity.response_bytes;
    let json_request_bytes = serde_json::to_vec(&NamedRequest::fixed())
        .map_err(|error| error.to_string())?
        .len();
    let request_compression = 1.0 - FRAME_BYTES as f64 / json_request_bytes as f64;
    let refusal_count = refusal_suite()?;
    let samples_per_block = iterations / BLOCKS;
    let warmup_per_block = warmup / BLOCKS;
    let mut batches: [Vec<ArmBatch>; 3] = std::array::from_fn(|_| Vec::new());
    for block in 0..BLOCKS {
        for arm in SCHEDULE[block % SCHEDULE.len()] {
            let batch = match arm {
                Arm::Direct => {
                    measure_batch(samples_per_block, warmup_per_block, || direct.observe())
                }
                Arm::Json => measure_batch(samples_per_block, warmup_per_block, || json.observe()),
                Arm::Ndabi => {
                    measure_batch(samples_per_block, warmup_per_block, || ndabi.observe())
                }
            }?;
            batches[arm.index()].push(batch);
        }
    }
    let arms = vec![
        finish_arm(
            "direct",
            "direct prepared White Tree",
            0,
            0,
            true,
            std::mem::take(&mut batches[0]),
        )?,
        finish_arm(
            "json",
            "equal-security JSON White Tree gateway",
            json_request_bytes,
            json.request.capacity(),
            true,
            std::mem::take(&mut batches[1]),
        )?,
        finish_arm(
            "ndabi",
            "shared-session NDABI White Tree",
            FRAME_BYTES,
            FRAME_BYTES,
            true,
            std::mem::take(&mut batches[2]),
        )?,
    ];
    let direct_p95 = arms[0].p95_ns as f64;
    let json_p95 = arms[1].p95_ns as f64;
    let ndabi_p95 = arms[2].p95_ns as f64;
    let per_process_latency_passed = ndabi_p95 <= json_p95;
    let gates = Gates {
        exact_results,
        refusals: format!("{refusal_count}/6"),
        request_compression_passed: request_compression >= 0.35,
        per_process_latency_passed,
        passed: exact_results
            && refusal_count == 6
            && request_compression >= 0.35
            && per_process_latency_passed,
    };
    let report = Report {
        campaign: "NDABI equal-security White Tree v4.5",
        iterations: samples_per_block * BLOCKS,
        warmup: warmup_per_block * BLOCKS,
        measurement_blocks: BLOCKS,
        arms,
        request_compression,
        ndabi_json_p95_ratio: ndabi_p95 / json_p95,
        ndabi_direct_p95_ratio: ndabi_p95 / direct_p95,
        gates,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn authority(session: u32) -> Result<Authority, String> {
    Authority::new([44; 32], 1, session, DEADLINE, 10, 11, 12).map_err(|error| error.to_string())
}

fn refusal_suite() -> Result<u32, String> {
    let operation = WhiteTreePreparedBackend::operation();
    let mut passed = 0;
    let execute =
        |session, operation, budget, now, mutate: bool, replay: bool| -> Result<bool, String> {
            let binding = authority(session)?;
            let mut client = ClientSession::new(binding.clone());
            let mut server = ServerSession::new(binding, MAXIMUM_RESULT_BYTES)
                .map_err(|error| error.to_string())?;
            let mut frame = client
                .encode(operation, budget, 1_500_000)
                .map_err(|error| error.to_string())?;
            if mutate {
                frame[40] ^= 1;
            }
            let mut backend = WhiteTreePreparedBackend::new()?;
            let first = server.execute(&frame, now, &mut backend);
            if replay && first.is_ok() {
                Ok(server.execute(&frame, now, &mut backend).is_err())
            } else {
                Ok(first.is_err())
            }
        };
    passed += u32::from(execute(101, operation, 8_192, NOW, true, false)?);
    passed += u32::from(execute(102, operation, 8_192, NOW, false, true)?);
    let source = authority(103)?;
    let mut client = ClientSession::new(source);
    let frame = client
        .encode(operation, 8_192, 1_500_000)
        .map_err(|error| error.to_string())?;
    let mut wrong_server =
        ServerSession::new(authority(104)?, 8_192).map_err(|error| error.to_string())?;
    passed += u32::from(
        wrong_server
            .execute(&frame, NOW, &mut WhiteTreePreparedBackend::new()?)
            .is_err(),
    );
    passed += u32::from(execute(105, operation, 8_192, 1_500_000, false, false)?);
    passed += u32::from(execute(106, operation, 8_193, NOW, false, false)?);
    let unsupported =
        RawOperation::new(0x31, 101, 1, (3 << 16) | 3).map_err(|error| error.to_string())?;
    passed += u32::from(execute(107, unsupported, 8_192, NOW, false, false)?);
    Ok(passed)
}

fn arguments() -> Result<(usize, usize), String> {
    let mut iterations = 20_000;
    let mut warmup = 2_000;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{argument} requires a value"))?;
        match argument.as_str() {
            "--iterations" => {
                iterations = value
                    .parse()
                    .map_err(|_| "iterations are invalid".to_string())?
            }
            "--warmup" => {
                warmup = value
                    .parse()
                    .map_err(|_| "warm-up is invalid".to_string())?
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((iterations, warmup))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_registered_refusals_pass() {
        assert_eq!(refusal_suite().expect("suite"), 6);
    }

    #[test]
    fn named_request_maps_only_to_the_fixed_operation() {
        assert_eq!(
            NamedRequest::fixed().operation().expect("operation"),
            WhiteTreePreparedBackend::operation()
        );
        let mut changed = NamedRequest::fixed();
        changed.trajectory_id += 1;
        assert!(changed.operation().is_err());
    }
}
