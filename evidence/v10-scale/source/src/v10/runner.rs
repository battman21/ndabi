use std::array;
use std::process::Command;

use serde::Serialize;

use super::codecs::{self, Arm};
use super::kernel;
use super::measure::{self, BatchSample, Measurement, Observation};
use super::model::{
    Dataset, PreparedCapability, PreparedCommand, Query, QueryReceipt, ResultBuffer, Session,
    TrustedEnvelope, Workload, MAX_RECORDS, MAX_RESULT_BYTES, MIN_RECORDS, MIN_RESULT_BYTES,
};

const NONCE_BASE: u64 = 8_000_000_000;
const MAX_BATCHES: usize = 10_000;
const MAX_OPERATIONS_PER_BATCH: usize = 10_000;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Config {
    pub records: usize,
    pub workload: Workload,
    pub result_bytes: usize,
    pub batches: usize,
    pub operations_per_batch: usize,
    pub warmup_batches: usize,
}

#[derive(Debug, Serialize)]
struct Environment {
    os: &'static str,
    architecture: &'static str,
    rustc: String,
    git_commit: String,
    git_worktree_state: String,
    source_fingerprint_blake3: String,
}

#[derive(Debug, Serialize)]
struct Exactness {
    semantic_results_equal: bool,
    receipts_equal: bool,
    deterministic_encodings: bool,
}

#[derive(Debug, Serialize)]
struct Refusals {
    passed: u32,
    total: u32,
    ndabi_request_bits_refused: u64,
    ndabi_request_bits_tested: u64,
}

#[derive(Debug, Serialize)]
struct Calibration {
    empty_control_median_batch_ns: u64,
    fastest_arm_median_batch_ns: u64,
    timer_control_ratio: f64,
    target_ratio: f64,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct MemoryEvidence {
    dataset_retained_bytes: u64,
    prepared_arm_retained_bytes: u64,
}

#[derive(Debug, Serialize)]
struct GateCheck {
    id: &'static str,
    passed: bool,
    observed: String,
}

#[derive(Debug, Serialize)]
struct HardGate {
    passed: bool,
    checks: Vec<GateCheck>,
}

#[derive(Debug, Serialize)]
struct Evidence {
    schema: &'static str,
    status: &'static str,
    config: Config,
    environment: Environment,
    exactness: Exactness,
    refusals: Refusals,
    calibration: Calibration,
    arms: Vec<Measurement>,
    memory: MemoryEvidence,
    hard_gate: HardGate,
    limitations: [&'static str; 8],
}

struct ArmState {
    session: Session,
    request: Vec<u8>,
    response: Vec<u8>,
    result: ResultBuffer,
    receipt: QueryReceipt,
}

impl ArmState {
    fn new(arm: Arm, result_bytes: usize) -> Self {
        let response_capacity = if matches!(arm, Arm::StatelessJson | Arm::PreparedJson) {
            result_bytes.saturating_mul(2).saturating_add(1_024)
        } else {
            result_bytes.saturating_add(1_024)
        };
        Self {
            session: Session {
                last_nonce: NONCE_BASE,
            },
            request: Vec::with_capacity(2_048),
            response: Vec::with_capacity(response_capacity),
            result: ResultBuffer::with_capacity(result_bytes),
            receipt: QueryReceipt::default(),
        }
    }

    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.request.capacity()
            + self.response.capacity()
            + self.result.payload.capacity()
    }
}

pub fn main() -> Result<(), String> {
    let config = parse_args(std::env::args().skip(1))?;
    let evidence = run(config)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&evidence).map_err(|error| error.to_string())?
    );
    if !evidence.hard_gate.passed {
        return Err("the NDABI v1.0 hard gate failed".to_string());
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
    let refusals = prove_refusals(&dataset, capability, command, config.result_bytes)?;

    let mut states: [ArmState; 5] =
        array::from_fn(|index| ArmState::new(Arm::ALL[index], config.result_bytes));
    for arm in Arm::ALL {
        measure::warm(
            &mut states[arm.index()],
            config.warmup_batches,
            config.operations_per_batch,
            |state| process(arm, &dataset, capability, command, state),
        )?;
    }
    let mut samples: [Vec<BatchSample>; 5] = array::from_fn(|_| Vec::with_capacity(config.batches));
    let cycles = config.batches / Arm::ALL.len();
    for _ in 0..cycles {
        for offset in 0..Arm::ALL.len() {
            for position in 0..Arm::ALL.len() {
                let arm = Arm::ALL[(position + offset) % Arm::ALL.len()];
                let sample = measure::measure_one(
                    &mut states[arm.index()],
                    config.operations_per_batch,
                    |state| process(arm, &dataset, capability, command, state),
                )?;
                samples[arm.index()].push(sample);
            }
        }
    }
    let arms = Arm::ALL
        .iter()
        .map(|arm| measure::finish(arm.id(), config.operations_per_batch, &samples[arm.index()]))
        .collect::<Result<Vec<_>, _>>()?;
    let mut empty = measure::empty_samples(config.batches, config.operations_per_batch);
    empty.sort_unstable();
    let empty_median = measure::percentile(&empty, 0.50);
    let fastest_batch = arms
        .iter()
        .map(|arm| arm.median_batch_ns)
        .min()
        .ok_or_else(|| "the measurement has no arms".to_string())?;
    let timer_control_ratio = empty_median as f64 / fastest_batch.max(1) as f64;
    let calibration = Calibration {
        empty_control_median_batch_ns: empty_median,
        fastest_arm_median_batch_ns: fastest_batch,
        timer_control_ratio,
        target_ratio: 0.01,
        passed: timer_control_ratio <= 0.01,
    };
    let ndabi = &arms[Arm::Ndabi.index()];
    let checks = vec![
        gate(
            "semantic-equality",
            exactness.semantic_results_equal,
            exactness.semantic_results_equal.to_string(),
        ),
        gate(
            "receipt-equality",
            exactness.receipts_equal,
            exactness.receipts_equal.to_string(),
        ),
        gate(
            "deterministic-encoding",
            exactness.deterministic_encodings,
            exactness.deterministic_encodings.to_string(),
        ),
        gate(
            "authority-refusals",
            refusals.passed == refusals.total,
            format!("{}/{}", refusals.passed, refusals.total),
        ),
        gate(
            "protected-frame-corruption",
            refusals.ndabi_request_bits_refused == refusals.ndabi_request_bits_tested,
            format!(
                "{}/{}",
                refusals.ndabi_request_bits_refused, refusals.ndabi_request_bits_tested
            ),
        ),
        gate(
            "measurement-calibration",
            calibration.passed,
            format!("{:.4}%", calibration.timer_control_ratio * 100.0),
        ),
        gate(
            "ndabi-hot-allocation",
            ndabi.allocations_per_operation == 0.0,
            format!("{:.4}", ndabi.allocations_per_operation),
        ),
    ];
    let hard_gate = HardGate {
        passed: checks.iter().all(|check| check.passed),
        checks,
    };
    Ok(Evidence {
        schema: "ndabi-poc-result-v1.0",
        status: "local-bounded-scale-measurement-validation",
        config,
        environment: Environment {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            rustc: command_output("rustc", &["--version"]),
            git_commit: command_output("git", &["rev-parse", "HEAD"]),
            git_worktree_state: if command_output("git", &["status", "--porcelain"]).is_empty() {
                "clean".to_string()
            } else {
                "dirty".to_string()
            },
            source_fingerprint_blake3: source_fingerprint(),
        },
        exactness,
        refusals,
        calibration,
        memory: MemoryEvidence {
            dataset_retained_bytes: dataset.retained_bytes() as u64,
            prepared_arm_retained_bytes: states[Arm::Ndabi.index()].retained_bytes() as u64,
        },
        arms,
        hard_gate,
        limitations: [
            "This is a local read-only POC profile, not a public protocol standard.",
            "The query kernel is a deterministic fixture engine, not White Tree or PostgreSQL.",
            "The macOS result supports relative comparisons, not publishable absolute latency.",
            "The direct arm is an in-process ceiling and has no transport boundary.",
            "The profile does not prove shared-state concurrency or durable custody.",
            "The profile does not prove remote transport or TLS behaviour.",
            "The profile does not prove provider-token savings.",
            "Speed targets remain unfrozen until measurement validation passes.",
        ],
    })
}

fn process(
    arm: Arm,
    dataset: &Dataset,
    capability: PreparedCapability,
    command: PreparedCommand,
    state: &mut ArmState,
) -> Result<Observation, String> {
    let nonce = state.session.last_nonce.saturating_add(1);
    let trusted_envelope = capability.envelope(nonce);
    let (effective_capability, effective_envelope, effective_command) = if arm == Arm::Direct {
        (capability, trusted_envelope, command)
    } else {
        codecs::encode_request(
            arm,
            &mut state.request,
            capability,
            trusted_envelope,
            command,
        )?;
        let decoded = codecs::decode_request(arm, &state.request)?;
        (
            decoded.capability.unwrap_or(capability),
            decoded.envelope.unwrap_or(trusted_envelope),
            decoded.command,
        )
    };
    let receipt = kernel::execute(
        dataset,
        &effective_capability,
        effective_envelope,
        effective_command,
        &mut state.session,
        &mut state.result,
    )?;
    state.receipt = receipt;
    if arm != Arm::Direct {
        codecs::encode_response(arm, &mut state.response, &state.result, receipt)?;
        codecs::verify_response(arm, &state.response, &state.result, receipt)?;
    }
    Ok(Observation {
        request_bytes: state.request.len(),
        response_bytes: state.response.len(),
        semantic_fingerprint: u64::from_le_bytes(
            state.result.semantic.result_digest[..8]
                .try_into()
                .unwrap_or([0; std::mem::size_of::<u64>()]),
        ),
    })
}

fn prove_exactness(
    dataset: &Dataset,
    capability: PreparedCapability,
    command: PreparedCommand,
    result_bytes: usize,
) -> Result<Exactness, String> {
    let mut semantics = Vec::new();
    let mut receipts = Vec::new();
    let mut deterministic_encodings = true;
    for arm in Arm::ALL {
        let mut first = ArmState::new(arm, result_bytes);
        let mut second = ArmState::new(arm, result_bytes);
        process(arm, dataset, capability, command, &mut first)?;
        process(arm, dataset, capability, command, &mut second)?;
        deterministic_encodings &= first.request == second.request
            && first.response == second.response
            && first.result.payload == second.result.payload;
        semantics.push((
            first.result.semantic,
            *blake3::hash(&first.result.payload).as_bytes(),
        ));
        receipts.push(first.receipt);
    }
    Ok(Exactness {
        semantic_results_equal: semantics.windows(2).all(|pair| pair[0] == pair[1]),
        receipts_equal: receipts.windows(2).all(|pair| pair[0] == pair[1]),
        deterministic_encodings,
    })
}

fn prove_refusals(
    dataset: &Dataset,
    capability: PreparedCapability,
    command: PreparedCommand,
    result_bytes: usize,
) -> Result<Refusals, String> {
    let valid_envelope = capability.envelope(1);
    let mut cases = Vec::new();
    cases.push((
        PreparedCapability {
            revoked: true,
            ..capability
        },
        valid_envelope,
        command,
        Session::default(),
    ));
    cases.push((
        PreparedCapability {
            expires_at: super::model::BENCHMARK_NOW - 1,
            ..capability
        },
        valid_envelope,
        command,
        Session::default(),
    ));
    cases.push((
        capability,
        valid_envelope,
        PreparedCommand {
            capability_handle: command.capability_handle ^ 1,
            ..command
        },
        Session::default(),
    ));
    cases.push((
        capability,
        valid_envelope,
        PreparedCommand {
            capability_generation: command.capability_generation + 1,
            ..command
        },
        Session::default(),
    ));
    cases.push((
        capability,
        TrustedEnvelope {
            principal_digest: [0; 16],
            ..valid_envelope
        },
        command,
        Session::default(),
    ));
    cases.push((
        capability,
        TrustedEnvelope {
            purpose_digest: [0; 16],
            ..valid_envelope
        },
        command,
        Session::default(),
    ));
    cases.push((
        capability,
        TrustedEnvelope {
            snapshot: valid_envelope.snapshot + 1,
            ..valid_envelope
        },
        command,
        Session::default(),
    ));
    cases.push((
        capability,
        TrustedEnvelope {
            deadline: super::model::BENCHMARK_NOW - 1,
            ..valid_envelope
        },
        command,
        Session::default(),
    ));
    cases.push((
        capability,
        TrustedEnvelope {
            result_budget: 1,
            ..valid_envelope
        },
        command,
        Session::default(),
    ));
    cases.push((
        PreparedCapability {
            allowed_operations: 0,
            ..capability
        },
        valid_envelope,
        command,
        Session::default(),
    ));
    cases.push((
        capability,
        valid_envelope,
        command,
        Session { last_nonce: 1 },
    ));
    let mut passed = 0u32;
    for (case_capability, envelope, case_command, mut session) in cases {
        let original_nonce = session.last_nonce;
        let mut result = ResultBuffer::with_capacity(result_bytes);
        if kernel::execute(
            dataset,
            &case_capability,
            envelope,
            case_command,
            &mut session,
            &mut result,
        )
        .is_err()
            && session.last_nonce == original_nonce
        {
            passed += 1;
        }
    }
    let mut frame = Vec::new();
    codecs::encode_request(Arm::Ndabi, &mut frame, capability, valid_envelope, command)?;
    let mut bits_tested = 0u64;
    let mut bits_refused = 0u64;
    for index in 0..frame.len() {
        for bit in 0..8 {
            bits_tested += 1;
            let original = frame[index];
            frame[index] ^= 1 << bit;
            if codecs::decode_request(Arm::Ndabi, &frame).is_err() {
                bits_refused += 1;
            }
            frame[index] = original;
        }
    }
    Ok(Refusals {
        passed,
        total: 11,
        ndabi_request_bits_refused: bits_refused,
        ndabi_request_bits_tested: bits_tested,
    })
}

fn gate(id: &'static str, passed: bool, observed: String) -> GateCheck {
    GateCheck {
        id,
        passed,
        observed,
    }
}

fn parse_args(mut arguments: impl Iterator<Item = String>) -> Result<Config, String> {
    let mut config = Config {
        records: 10_000,
        workload: Workload::Point,
        result_bytes: 4_096,
        batches: 200,
        operations_per_batch: 100,
        warmup_batches: 20,
    };
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{argument} needs a value"))?;
        match argument.as_str() {
            "--records" => config.records = number(&argument, &value)?,
            "--workload" => config.workload = value.parse()?,
            "--result-bytes" => config.result_bytes = number(&argument, &value)?,
            "--batches" => config.batches = number(&argument, &value)?,
            "--operations-per-batch" => config.operations_per_batch = number(&argument, &value)?,
            "--warmup-batches" => config.warmup_batches = number(&argument, &value)?,
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if !(MIN_RECORDS..=MAX_RECORDS).contains(&config.records) {
        return Err(format!(
            "--records must be between {MIN_RECORDS} and {MAX_RECORDS}"
        ));
    }
    if !(MIN_RESULT_BYTES..=MAX_RESULT_BYTES).contains(&config.result_bytes) {
        return Err(format!(
            "--result-bytes must be between {MIN_RESULT_BYTES} and {MAX_RESULT_BYTES}"
        ));
    }
    if config.batches < Arm::ALL.len()
        || config.batches > MAX_BATCHES
        || !config.batches.is_multiple_of(Arm::ALL.len())
    {
        return Err(format!(
            "--batches must be divisible by five and between five and {MAX_BATCHES}"
        ));
    }
    if !(1..=MAX_OPERATIONS_PER_BATCH).contains(&config.operations_per_batch) {
        return Err(format!(
            "--operations-per-batch must be between one and {MAX_OPERATIONS_PER_BATCH}"
        ));
    }
    if config.warmup_batches > 1_000 {
        return Err("--warmup-batches must not exceed 1000".to_string());
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
    hasher.update(include_bytes!("model.rs"));
    hasher.update(include_bytes!("kernel.rs"));
    hasher.update(include_bytes!("codecs.rs"));
    hasher.update(include_bytes!("measure.rs"));
    hasher.update(include_bytes!("runner.rs"));
    hasher.update(include_bytes!("../bin/ndabi_v10.rs"));
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_enforce_profile_bounds() {
        assert!(
            parse_args(["--records".to_string(), (MAX_RECORDS + 1).to_string()].into_iter())
                .is_err()
        );
        assert!(parse_args(["--result-bytes".to_string(), "1".to_string()].into_iter()).is_err());
        assert!(parse_args(["--batches".to_string(), "6".to_string()].into_iter()).is_err());
    }

    #[test]
    fn smoke_campaign_passes() {
        let evidence = run(Config {
            records: 512,
            workload: Workload::Point,
            result_bytes: 64,
            batches: 10,
            operations_per_batch: 1_000,
            warmup_batches: 1,
        })
        .expect("campaign");
        assert!(evidence.hard_gate.passed);
    }

    #[test]
    fn one_hundred_thousand_record_aggregate_is_exact() {
        let dataset = Dataset::fixture(100_000).expect("dataset");
        let query = Query::fixture(Workload::Aggregate, 100_000, 64).expect("query");
        let capability = PreparedCapability::fixture(dataset.snapshot, query.result_budget);
        let command = PreparedCommand {
            capability_handle: capability.handle,
            capability_generation: capability.generation,
            query,
        };
        let exactness = prove_exactness(&dataset, capability, command, 64).expect("exactness");
        assert!(exactness.semantic_results_equal);
        assert!(exactness.receipts_equal);
    }
}
