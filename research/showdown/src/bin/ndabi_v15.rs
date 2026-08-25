#[path = "../alloc.rs"]
mod alloc;
#[path = "../v15/mod.rs"]
mod v14;

use std::hint::black_box;
use std::process::Command;
use std::time::Instant;

use alloc::{begin_measurement, end_measurement, CountingAllocator};
use serde::Serialize;
use v14::codecs::{self, Arm};
use v14::model::{
    Dataset, PreparedCapability, PreparedCommand, Query, QueryReceipt, ResultBuffer,
    SemanticResult, Session, Workload,
};

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

const NONCE_BASE: u64 = 9_000_000_000;
const BATCHES: usize = 60;
const WARMUP_BATCHES: usize = 5;

#[derive(Clone, Copy, Debug, Serialize)]
struct Config {
    records: usize,
    workload: Workload,
    result_bytes: usize,
}

#[derive(Debug, Serialize)]
struct PhaseMeasurement {
    id: &'static str,
    batches: usize,
    operations_per_batch: usize,
    median_batch_ns: u64,
    p95_batch_ns: u64,
    median_ns_per_operation: f64,
    p95_ns_per_operation: f64,
    allocations_per_operation: f64,
    allocated_bytes_per_operation: f64,
    peak_additional_live_bytes: u64,
    timer_control_ratio: f64,
    calibration_passed: bool,
}

#[derive(Debug, Serialize)]
struct Evidence {
    schema: &'static str,
    status: &'static str,
    config: Config,
    environment: Environment,
    timer_p95_ns: u64,
    exactness: Exactness,
    phases: Vec<PhaseMeasurement>,
    hard_gate: HardGate,
    limitations: [&'static str; 5],
}

#[derive(Debug, Serialize)]
struct Environment {
    os: &'static str,
    architecture: &'static str,
    rustc: String,
    source_fingerprint_blake3: String,
    dataset_retained_bytes: usize,
    profiled_arms: [&'static str; 3],
    available_arms: [&'static str; 6],
    ndabi_arm_index: usize,
}

#[derive(Debug, Serialize)]
struct Exactness {
    semantic_results_equal: bool,
    payloads_equal: bool,
    receipts_equal: bool,
}

#[derive(Debug, Serialize)]
struct HardGate {
    passed: bool,
    all_phases_calibrated: bool,
    exactness_passed: bool,
    ndabi_hot_allocations_zero: bool,
}

struct CompleteState {
    session: Session,
    request: Vec<u8>,
    response: Vec<u8>,
    result: ResultBuffer,
}

impl CompleteState {
    fn new(result_bytes: usize) -> Self {
        Self {
            session: Session {
                last_nonce: NONCE_BASE,
            },
            request: Vec::with_capacity(2_048),
            response: Vec::with_capacity(result_bytes.saturating_mul(2).saturating_add(1_024)),
            result: ResultBuffer::with_capacity(result_bytes),
        }
    }
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> Result<(), String> {
    let config = parse_args(std::env::args().skip(1))?;
    let evidence = run(config)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&evidence).map_err(|error| error.to_string())?
    );
    if !evidence.hard_gate.passed {
        return Err("the NDABI v1.5 phase-profile gate failed".to_string());
    }
    Ok(())
}

fn run(config: Config) -> Result<Evidence, String> {
    let dataset = Dataset::fixture(config.records)?;
    let query = Query::fixture(config.workload, config.records, config.result_bytes)?;
    let capability = PreparedCapability::fixture(dataset.snapshot, query.result_budget);
    let command = PreparedCommand {
        capability_handle: capability.handle,
        capability_generation: capability.generation,
        query,
    };
    let exactness = prove_exactness(&dataset, capability, command, config.result_bytes)?;
    let timer_p95_ns = timer_p95();
    let complete_operations = complete_operations(config);
    let response_operations = response_operations(config.result_bytes);
    let request_operations = 5_000;

    let mut seed_session = Session {
        last_nonce: NONCE_BASE,
    };
    let mut canonical_result = ResultBuffer::with_capacity(config.result_bytes);
    let canonical_receipt = v14::kernel::execute(
        &dataset,
        &capability,
        capability.envelope(NONCE_BASE + 1),
        command,
        &mut seed_session,
        &mut canonical_result,
    )?;

    let mut ndabi_request = Vec::with_capacity(128);
    codecs::encode_request(
        Arm::Ndabi,
        &mut ndabi_request,
        capability,
        capability.envelope(NONCE_BASE + 1),
        command,
    )?;
    let mut ndabi_response = Vec::with_capacity(config.result_bytes + 128);
    codecs::encode_response(
        Arm::Ndabi,
        &mut ndabi_response,
        &canonical_result,
        canonical_receipt,
    )?;
    let mut cbor_response = Vec::with_capacity(config.result_bytes + 128);
    codecs::encode_response(
        Arm::ProtectedCbor,
        &mut cbor_response,
        &canonical_result,
        canonical_receipt,
    )?;

    let mut phases = Vec::new();
    let mut request_output = Vec::with_capacity(128);
    phases.push(measure_phase(
        "ndabi-request-encode",
        request_operations,
        timer_p95_ns,
        || {
            codecs::encode_request(
                Arm::Ndabi,
                &mut request_output,
                capability,
                capability.envelope(NONCE_BASE + 1),
                command,
            )?;
            Ok(request_output.len() as u64)
        },
    )?);
    phases.push(measure_phase(
        "ndabi-request-decode",
        request_operations,
        timer_p95_ns,
        || {
            let decoded = codecs::decode_request(Arm::Ndabi, black_box(&ndabi_request))?;
            Ok(decoded.command.capability_handle)
        },
    )?);

    let mut kernel_session = Session {
        last_nonce: NONCE_BASE,
    };
    let mut kernel_result = ResultBuffer::with_capacity(config.result_bytes);
    phases.push(measure_phase(
        "kernel-execute",
        complete_operations,
        timer_p95_ns,
        || {
            let nonce = kernel_session.last_nonce.saturating_add(1);
            let receipt = v14::kernel::execute(
                &dataset,
                &capability,
                capability.envelope(nonce),
                command,
                &mut kernel_session,
                &mut kernel_result,
            )?;
            Ok(receipt.nonce)
        },
    )?);

    let mut response_output = Vec::with_capacity(config.result_bytes + 128);
    phases.push(measure_phase(
        "ndabi-response-encode",
        response_operations,
        timer_p95_ns,
        || {
            codecs::encode_response(
                Arm::Ndabi,
                &mut response_output,
                &canonical_result,
                canonical_receipt,
            )?;
            Ok(response_output.len() as u64)
        },
    )?);
    phases.push(measure_phase(
        "ndabi-response-verify",
        response_operations,
        timer_p95_ns,
        || {
            codecs::verify_response(
                Arm::Ndabi,
                black_box(&ndabi_response),
                black_box(&canonical_result),
                canonical_receipt,
            )?;
            Ok(canonical_receipt.nonce)
        },
    )?);

    let mut cbor_output = Vec::with_capacity(config.result_bytes + 128);
    phases.push(measure_phase(
        "protected-cbor-response-encode",
        response_operations,
        timer_p95_ns,
        || {
            codecs::encode_response(
                Arm::ProtectedCbor,
                &mut cbor_output,
                &canonical_result,
                canonical_receipt,
            )?;
            Ok(cbor_output.len() as u64)
        },
    )?);
    phases.push(measure_phase(
        "protected-cbor-response-verify",
        response_operations,
        timer_p95_ns,
        || {
            codecs::verify_response(
                Arm::ProtectedCbor,
                black_box(&cbor_response),
                black_box(&canonical_result),
                canonical_receipt,
            )?;
            Ok(canonical_receipt.nonce)
        },
    )?);

    let mut copied_payload = Vec::with_capacity(config.result_bytes);
    phases.push(measure_phase(
        "payload-copy",
        response_operations,
        timer_p95_ns,
        || {
            copied_payload.clear();
            copied_payload.extend_from_slice(black_box(&canonical_result.payload));
            Ok(copied_payload.len() as u64)
        },
    )?);
    phases.push(measure_phase(
        "payload-crc32",
        response_operations,
        timer_p95_ns,
        || {
            Ok(u64::from(crc32fast::hash(black_box(
                &canonical_result.payload,
            ))))
        },
    )?);
    phases.push(measure_phase(
        "payload-blake3",
        response_operations,
        timer_p95_ns,
        || {
            let digest = blake3::hash(black_box(&canonical_result.payload));
            Ok(u64::from_le_bytes(
                digest.as_bytes()[..8]
                    .try_into()
                    .map_err(|_| "the digest prefix length does not match".to_string())?,
            ))
        },
    )?);

    let mut stateless = CompleteState::new(config.result_bytes);
    phases.push(measure_phase(
        "stateless-json-complete",
        complete_operations,
        timer_p95_ns,
        || {
            process_complete(
                Arm::StatelessJson,
                &dataset,
                capability,
                command,
                &mut stateless,
            )
        },
    )?);
    let mut ndabi = CompleteState::new(config.result_bytes);
    phases.push(measure_phase(
        "ndabi-complete",
        complete_operations,
        timer_p95_ns,
        || process_complete(Arm::Ndabi, &dataset, capability, command, &mut ndabi),
    )?);
    let mut direct = CompleteState::new(config.result_bytes);
    phases.push(measure_phase(
        "direct-complete",
        complete_operations,
        timer_p95_ns,
        || process_complete(Arm::Direct, &dataset, capability, command, &mut direct),
    )?);

    let exactness_passed =
        exactness.semantic_results_equal && exactness.payloads_equal && exactness.receipts_equal;
    let all_phases_calibrated = phases.iter().all(|phase| phase.calibration_passed);
    let ndabi_hot_allocations_zero = phases
        .iter()
        .find(|phase| phase.id == "ndabi-complete")
        .is_some_and(|phase| phase.allocations_per_operation == 0.0);
    let hard_gate = HardGate {
        passed: exactness_passed && all_phases_calibrated && ndabi_hot_allocations_zero,
        all_phases_calibrated,
        exactness_passed,
        ndabi_hot_allocations_zero,
    };
    Ok(Evidence {
        schema: "ndabi-poc-phase-profile-v1.5",
        status: "diagnostic-linux-phase-profile",
        config,
        environment: Environment {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            rustc: command_output("rustc", &["--version"]),
            source_fingerprint_blake3: source_fingerprint(),
            dataset_retained_bytes: dataset.retained_bytes(),
            profiled_arms: [Arm::StatelessJson.id(), Arm::Ndabi.id(), Arm::Direct.id()],
            available_arms: Arm::ALL.map(Arm::id),
            ndabi_arm_index: Arm::Ndabi.index(),
        },
        timer_p95_ns,
        exactness,
        phases,
        hard_gate,
        limitations: [
            "This diagnostic uses a fixture query engine.",
            "Isolated phase timings do not sum exactly to complete-path timings.",
            "The direct arm is an in-process ceiling without transport.",
            "The profile does not test sockets, databases, concurrency, or remote models.",
            "Docker Desktop does not establish bare-metal absolute latency.",
        ],
    })
}

fn process_complete(
    arm: Arm,
    dataset: &Dataset,
    capability: PreparedCapability,
    command: PreparedCommand,
    state: &mut CompleteState,
) -> Result<u64, String> {
    let nonce = state.session.last_nonce.saturating_add(1);
    let envelope = capability.envelope(nonce);
    let (effective_capability, effective_envelope, effective_command) = if arm == Arm::Direct {
        (capability, envelope, command)
    } else {
        codecs::encode_request(arm, &mut state.request, capability, envelope, command)?;
        let decoded = codecs::decode_request(arm, &state.request)?;
        (
            decoded.capability.unwrap_or(capability),
            decoded.envelope.unwrap_or(envelope),
            decoded.command,
        )
    };
    let receipt = v14::kernel::execute(
        dataset,
        &effective_capability,
        effective_envelope,
        effective_command,
        &mut state.session,
        &mut state.result,
    )?;
    if arm != Arm::Direct {
        codecs::encode_response(arm, &mut state.response, &state.result, receipt)?;
        codecs::verify_response(arm, &state.response, &state.result, receipt)?;
    }
    Ok(u64::from_le_bytes(
        state.result.semantic.result_digest[..8]
            .try_into()
            .map_err(|_| "the result digest prefix length does not match".to_string())?,
    ))
}

fn measure_phase<F>(
    id: &'static str,
    operations_per_batch: usize,
    timer_p95_ns: u64,
    mut operation: F,
) -> Result<PhaseMeasurement, String>
where
    F: FnMut() -> Result<u64, String>,
{
    for _ in 0..WARMUP_BATCHES {
        for _ in 0..operations_per_batch {
            black_box(operation()?);
        }
    }
    let mut elapsed = Vec::with_capacity(BATCHES);
    let mut allocations = 0u64;
    let mut allocated_bytes = 0u64;
    let mut peak_additional_live_bytes = 0u64;
    for _ in 0..BATCHES {
        let allocation_start = begin_measurement();
        let started = Instant::now();
        for _ in 0..operations_per_batch {
            black_box(operation()?);
        }
        elapsed.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        let delta = end_measurement(allocation_start);
        allocations = allocations.saturating_add(delta.allocations);
        allocated_bytes = allocated_bytes.saturating_add(delta.allocated_bytes);
        peak_additional_live_bytes =
            peak_additional_live_bytes.max(delta.peak_additional_live_bytes);
    }
    elapsed.sort_unstable();
    let median_batch_ns = percentile(&elapsed, 0.50);
    let p95_batch_ns = percentile(&elapsed, 0.95);
    let operations = (BATCHES * operations_per_batch) as f64;
    let timer_control_ratio = timer_p95_ns as f64 / median_batch_ns.max(1) as f64;
    Ok(PhaseMeasurement {
        id,
        batches: BATCHES,
        operations_per_batch,
        median_batch_ns,
        p95_batch_ns,
        median_ns_per_operation: median_batch_ns as f64 / operations_per_batch as f64,
        p95_ns_per_operation: p95_batch_ns as f64 / operations_per_batch as f64,
        allocations_per_operation: allocations as f64 / operations,
        allocated_bytes_per_operation: allocated_bytes as f64 / operations,
        peak_additional_live_bytes,
        timer_control_ratio,
        calibration_passed: timer_p95_ns > 0 && timer_control_ratio <= 0.001,
    })
}

fn prove_exactness(
    dataset: &Dataset,
    capability: PreparedCapability,
    command: PreparedCommand,
    result_bytes: usize,
) -> Result<Exactness, String> {
    let mut values: Vec<(SemanticResult, Vec<u8>, QueryReceipt)> = Vec::new();
    for arm in [Arm::StatelessJson, Arm::Ndabi, Arm::Direct] {
        let mut state = CompleteState::new(result_bytes);
        process_complete(arm, dataset, capability, command, &mut state)?;
        values.push((
            state.result.semantic,
            state.result.payload.clone(),
            QueryReceipt {
                snapshot: capability.snapshot,
                nonce: state.session.last_nonce,
                capability_handle: capability.handle,
                result_digest: state.result.semantic.result_digest,
            },
        ));
    }
    Ok(Exactness {
        semantic_results_equal: values.windows(2).all(|pair| pair[0].0 == pair[1].0),
        payloads_equal: values.windows(2).all(|pair| pair[0].1 == pair[1].1),
        receipts_equal: values.windows(2).all(|pair| pair[0].2 == pair[1].2),
    })
}

fn timer_p95() -> u64 {
    let mut values = Vec::with_capacity(1_000);
    for _ in 0..1_000 {
        let started = Instant::now();
        values.push(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    values.sort_unstable();
    percentile(&values, 0.95)
}

fn percentile(sorted: &[u64], percentile: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) as f64 * percentile).ceil() as usize;
    sorted[index]
}

fn complete_operations(config: Config) -> usize {
    match (config.workload, config.result_bytes) {
        (Workload::Point | Workload::Temporal, _) => 2_000,
        (_, bytes) if bytes <= 65_536 => 4,
        _ => 1,
    }
}

fn response_operations(result_bytes: usize) -> usize {
    match result_bytes {
        0..=64 => 10_000,
        65..=65_536 => 64,
        _ => 4,
    }
}

fn parse_args(arguments: impl Iterator<Item = String>) -> Result<Config, String> {
    let mut config = Config {
        records: 100_000,
        workload: Workload::Point,
        result_bytes: 64,
    };
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{argument} requires a value"))?;
        match argument.as_str() {
            "--records" => config.records = number(&argument, &value)?,
            "--workload" => config.workload = value.parse()?,
            "--result-bytes" => config.result_bytes = number(&argument, &value)?,
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(config)
}

fn number(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|error| format!("{name} is not a positive integer: {error}"))
}

fn command_output(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn source_fingerprint() -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(include_bytes!("../v14/model.rs"));
    hasher.update(include_bytes!("../v14/kernel.rs"));
    hasher.update(include_bytes!("../v14/codecs.rs"));
    hasher.update(include_bytes!("ndabi_v15.rs"));
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactness_holds_for_the_point_profile() {
        let dataset = Dataset::fixture(512).expect("dataset");
        let query = Query::fixture(Workload::Point, 512, 64).expect("query");
        let capability = PreparedCapability::fixture(dataset.snapshot, query.result_budget);
        let command = PreparedCommand {
            capability_handle: capability.handle,
            capability_generation: capability.generation,
            query,
        };
        let exactness = prove_exactness(&dataset, capability, command, 64).expect("exactness");
        assert!(exactness.semantic_results_equal);
        assert!(exactness.payloads_equal);
        assert!(exactness.receipts_equal);
    }

    #[test]
    fn phase_operation_counts_keep_timer_cost_bounded() {
        assert_eq!(response_operations(64), 10_000);
        assert_eq!(response_operations(65_536), 64);
        assert_eq!(response_operations(1_048_576), 4);
    }
}
