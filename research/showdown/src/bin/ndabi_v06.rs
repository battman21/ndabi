use std::array;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ndabi_showdown::alloc::CountingAllocator;
use ndabi_showdown::kernel_v06::{
    self, Checkpoint, EventReceipt, KernelScratch, KernelState, PreparedCapability,
    PreparedCommand, CHECKPOINT_KEY,
};
use ndabi_showdown::measure::{
    finish_arm, measure_batch_prepared, ArmBatch, ArmMeasurement, Observation,
};
use serde::Serialize;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

const MEASUREMENT_CYCLES: usize = 4;
const BLOCKS_PER_ARM: usize = 16;
const TARGET_DIRECT_P95_NS: u64 = 2_500;
const TARGET_PREPARED_P95_NS: u64 = 6_000;
const TARGET_RECEIPT_NS: u64 = 500;
const TARGET_PREPARED_JSON_SPEEDUP: f64 = 3.0;
const TARGET_DIRECT_JSON_SPEEDUP: f64 = 4.0;

const LIMITATIONS: [&str; 10] = [
    "This is a local in-memory POC, not a production benchmark.",
    "The event slot is not durable storage.",
    "The checkpoint uses a fixture-only keyed hash, not production custody.",
    "The trusted local profile is not an independent federated state proof.",
    "The direct path excludes transport and human materialisation.",
    "The wire paths exclude network, TLS, and remote-provider latency.",
    "The host scheduler is not isolated, and sub-microsecond thread CPU includes clock overhead.",
    "The benchmark does not measure energy or hardware counters.",
    "The benchmark does not prove PostgreSQL, MongoDB, Supabase, or remote models.",
    "The format is a POC and not the public NDABI RFC.",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    V06,
    V07,
    V08,
    V09,
}

impl Profile {
    fn current() -> Result<Self, String> {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        match executable.file_stem().and_then(|value| value.to_str()) {
            Some("ndabi-v06") => Ok(Self::V06),
            Some("ndabi-v07") => Ok(Self::V07),
            Some("ndabi-v08") => Ok(Self::V08),
            Some("ndabi-v09") => Ok(Self::V09),
            _ => Err("the benchmark executable profile is unknown".to_string()),
        }
    }

    fn schema(self) -> &'static str {
        match self {
            Self::V06 => "ndabi-poc-result-v0.6",
            Self::V07 => "ndabi-poc-result-v0.7",
            Self::V08 => "ndabi-poc-result-v0.8",
            Self::V09 => "ndabi-poc-result-v0.9",
        }
    }

    fn status(self) -> &'static str {
        match self {
            Self::V06 => "local-architectural-poc-measurement",
            Self::V07 => "controlled-local-campaign-measurement",
            Self::V08 => "scheduler-controlled-local-campaign-measurement",
            Self::V09 => "paired-local-campaign-measurement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    StatelessJson,
    StatelessWire,
    PreparedWire,
    DirectKernel,
}

impl Arm {
    const ALL: [Self; 4] = [
        Self::StatelessJson,
        Self::StatelessWire,
        Self::PreparedWire,
        Self::DirectKernel,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::StatelessJson => "stateless-json",
            Self::StatelessWire => "stateless-wire",
            Self::PreparedWire => "prepared-wire",
            Self::DirectKernel => "direct-kernel",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::StatelessJson => "Stateless JSON + event receipt",
            Self::StatelessWire => "Stateless NDABI wire + event receipt",
            Self::PreparedWire => "Prepared NDABI wire + event receipt",
            Self::DirectKernel => "Prepared direct transition kernel",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::StatelessJson => 0,
            Self::StatelessWire => 1,
            Self::PreparedWire => 2,
            Self::DirectKernel => 3,
        }
    }
}

const BALANCED_SCHEDULE: [[Arm; 4]; 4] = [
    [
        Arm::StatelessJson,
        Arm::StatelessWire,
        Arm::PreparedWire,
        Arm::DirectKernel,
    ],
    [
        Arm::StatelessWire,
        Arm::PreparedWire,
        Arm::DirectKernel,
        Arm::StatelessJson,
    ],
    [
        Arm::PreparedWire,
        Arm::DirectKernel,
        Arm::StatelessJson,
        Arm::StatelessWire,
    ],
    [
        Arm::DirectKernel,
        Arm::StatelessJson,
        Arm::StatelessWire,
        Arm::PreparedWire,
    ],
];

#[derive(Clone, Copy, Debug, Serialize)]
struct Config {
    tasks: usize,
    changed_tasks: usize,
    iterations: usize,
    warmup: usize,
}

#[derive(Debug, Serialize)]
struct Environment {
    os: String,
    architecture: String,
    rustc: String,
    git_commit: String,
    git_worktree_state: String,
    scheduler_profile: &'static str,
    source_fingerprint_blake3: String,
}

#[derive(Clone, Debug, Serialize)]
struct Baseline {
    source: String,
    p95_ns: u64,
    p95_ci95_low_ns: u64,
    operations_per_second: f64,
    median_thread_cpu_ns: u64,
}

#[derive(Debug, Serialize)]
struct GateCheck {
    id: &'static str,
    label: &'static str,
    target: &'static str,
    observed: String,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct HardGate {
    passed: bool,
    checks: Vec<GateCheck>,
}

#[derive(Debug, Serialize)]
struct Exactness {
    states_equal: bool,
    receipts_equal: bool,
    canonical_events_equal: bool,
    human_views_equal: bool,
    replay_equal: bool,
    checkpoints_verify: bool,
    refusals_passed: usize,
    refusals_total: usize,
    deterministic_encodings: bool,
}

#[derive(Debug, Serialize)]
struct Ablations {
    arms: Vec<ArmMeasurement>,
    receipt_incremental_median_ns: u64,
    receipt_incremental_thread_cpu_ns: u64,
}

#[derive(Debug, Serialize)]
struct Attribution {
    prepared_vs_stateless_json_p95_speedup: f64,
    direct_vs_stateless_json_p95_speedup: f64,
    prepared_vs_stateless_json_conservative_p95_speedup: f64,
    direct_vs_stateless_json_conservative_p95_speedup: f64,
    prepared_vs_stateless_json_paired_p95_speedup_low: Option<f64>,
    direct_vs_stateless_json_paired_p95_speedup_low: Option<f64>,
    prepared_vs_v05_tuned_conservative_p95_speedup: Option<f64>,
    direct_vs_v05_tuned_conservative_p95_speedup: Option<f64>,
    prepared_request_reduction_percent: f64,
    prepared_response_reduction_percent: f64,
}

#[derive(Debug, Serialize)]
struct MemoryEvidence {
    state_bytes: u64,
    local_control_bytes: u64,
    event_slot_capacity_bytes: u64,
    v05_receipt_tree_reference_bytes: Option<u64>,
    local_control_reduction_percent: Option<f64>,
}

#[derive(Debug, Serialize)]
struct Examples {
    stateless_json: String,
    stateless_wire_hex: String,
    prepared_wire_hex: String,
    canonical_event_hex: String,
    exact_human_patch: String,
}

#[derive(Debug, Serialize)]
struct Report {
    schema: &'static str,
    status: &'static str,
    generated_at_unix_seconds: u64,
    environment: Environment,
    config: Config,
    v05_tuned_baseline: Option<Baseline>,
    arms: Vec<ArmMeasurement>,
    ablations: Ablations,
    exactness: Exactness,
    attribution: Attribution,
    memory: MemoryEvidence,
    hard_gate: HardGate,
    overall_verdict: &'static str,
    examples: Examples,
    limitations: [&'static str; 10],
}

struct Requests {
    json: Vec<u8>,
    stateless_wire: Vec<u8>,
    prepared_wire: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct PairedSpeedups {
    prepared_low: f64,
    direct_low: f64,
}

struct HotState {
    state: KernelState,
    scratch: KernelScratch,
    response: Vec<u8>,
    rendered: String,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("ndabi-v06: {error}");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), String> {
    let profile = Profile::current()?;
    let scheduler_profile = request_scheduler(profile)?;
    let (iterations, warmup) = parse_args(std::env::args().skip(1))?;
    let base = KernelState::fixture();
    let capability = PreparedCapability::fixture();
    capability.validate_prepared()?;
    let changes = kernel_v06::fixed_changes();
    let command = PreparedCommand::fixture(capability, changes);
    let requests = encode_requests(capability, &command, changes)?;
    let exactness = prove_exactness(&base, capability, &command, &requests)?;
    let (arms, paired_speedups) = measure_arms(
        profile, &base, capability, &command, &requests, iterations, warmup,
    )?;
    let ablations = measure_ablations(&base, capability, &command, iterations, warmup)?;
    let baseline = match profile {
        Profile::V06 => load_v05_baseline(Path::new("results/latest.json"))?,
        Profile::V07 | Profile::V08 | Profile::V09 => None,
    };
    let attribution = attribution(&arms, baseline.as_ref(), paired_speedups)?;
    let memory = memory_evidence(&base, baseline.as_ref())?;
    let hard_gate = match profile {
        Profile::V06 => hard_gate(
            &arms,
            &ablations,
            &exactness,
            &attribution,
            &memory,
            baseline.is_some(),
        )?,
        Profile::V07 | Profile::V08 | Profile::V09 => hard_gate_v07(
            &arms,
            &ablations,
            &exactness,
            &attribution,
            &memory,
            profile,
        )?,
    };
    let overall_verdict = if hard_gate.passed {
        "architectural-targets-pass"
    } else if exactness.states_equal
        && exactness.receipts_equal
        && exactness.replay_equal
        && exactness.refusals_passed == exactness.refusals_total
    {
        "promising"
    } else {
        "failed"
    };
    let examples = examples(&base, capability, &command, &requests)?;
    let report = Report {
        schema: profile.schema(),
        status: profile.status(),
        generated_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs(),
        environment: environment(profile, scheduler_profile),
        config: Config {
            tasks: kernel_v06::TASK_COUNT,
            changed_tasks: kernel_v06::CHANGE_COUNT,
            iterations,
            warmup,
        },
        v05_tuned_baseline: baseline,
        arms,
        ablations,
        exactness,
        attribution,
        memory,
        hard_gate,
        overall_verdict,
        examples,
        limitations: LIMITATIONS,
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)
        .map_err(|error| error.to_string())?;
    println!();
    Ok(())
}

fn encode_requests(
    capability: PreparedCapability,
    command: &PreparedCommand,
    changes: [kernel_v06::Change; kernel_v06::CHANGE_COUNT],
) -> Result<Requests, String> {
    let json =
        kernel_v06::encode_stateless_json_request(capability, command.expected_revision, changes)?;
    let mut stateless_wire = Vec::with_capacity(128);
    kernel_v06::encode_full_wire_request(&mut stateless_wire, capability, command)?;
    let mut prepared_wire = Vec::with_capacity(64);
    kernel_v06::encode_prepared_wire_request(&mut prepared_wire, command)?;
    Ok(Requests {
        json,
        stateless_wire,
        prepared_wire,
    })
}

fn measure_arms(
    profile: Profile,
    base: &KernelState,
    capability: PreparedCapability,
    command: &PreparedCommand,
    requests: &Requests,
    iterations: usize,
    warmup: usize,
) -> Result<(Vec<ArmMeasurement>, Option<PairedSpeedups>), String> {
    let mut batches: [Vec<ArmBatch>; 4] = array::from_fn(|_| Vec::new());
    let (measurement_cycles, samples_per_block) = if profile == Profile::V09 {
        (iterations / 40, 10)
    } else {
        (MEASUREMENT_CYCLES, iterations / BLOCKS_PER_ARM)
    };
    let blocks_per_arm = measurement_cycles * BALANCED_SCHEDULE.len();
    let warmup_per_block = warmup / blocks_per_arm;
    let warmup_remainder = warmup % blocks_per_arm;
    let mut arm_blocks = [0usize; 4];
    let mut hot_states: [HotState; 4] = array::from_fn(|_| HotState {
        state: base.clone(),
        scratch: KernelScratch::default(),
        response: Vec::with_capacity(192),
        rendered: String::with_capacity(1_024),
    });
    let changes = command.active_changes();
    let view_fingerprint = exact_view_fingerprint(base, capability, command)?;
    for _ in 0..measurement_cycles {
        for round in BALANCED_SCHEDULE {
            for arm in round {
                let index = arm.index();
                let block_warmup =
                    warmup_per_block + usize::from(arm_blocks[index] < warmup_remainder);
                arm_blocks[index] += 1;
                let batch = measure_batch_prepared(
                    &mut hot_states[index],
                    samples_per_block,
                    block_warmup,
                    |hot| {
                        hot.state.reset_changed_from(base, changes)?;
                        hot.scratch = KernelScratch::default();
                        hot.response.clear();
                        hot.rendered.clear();
                        Ok(())
                    },
                    |hot| run_arm(arm, capability, command, requests, hot, view_fingerprint),
                )?;
                batches[index].push(batch);
            }
        }
    }
    let paired_speedups = if profile == Profile::V09 {
        Some(PairedSpeedups {
            prepared_low: paired_speedup_low(&batches[0], &batches[2], 0x7072_6570)?,
            direct_low: paired_speedup_low(&batches[0], &batches[3], 0x6469_7265)?,
        })
    } else {
        None
    };
    let arms = Arm::ALL
        .iter()
        .map(|arm| {
            let index = arm.index();
            let request_bytes = request_len(*arm, requests);
            let hot = &hot_states[index];
            let retained = base.retained_bytes()
                + kernel_v06::control_bytes()
                + request_capacity(*arm, requests)
                + hot.response.capacity()
                + hot.rendered.capacity();
            finish_arm(
                arm.id(),
                arm.label(),
                request_bytes,
                retained,
                true,
                std::mem::take(&mut batches[index]),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((arms, paired_speedups))
}

fn paired_speedup_low(
    baseline: &[ArmBatch],
    candidate: &[ArmBatch],
    seed: u64,
) -> Result<f64, String> {
    if baseline.len() != candidate.len() || baseline.is_empty() {
        return Err("the paired arm blocks do not match".to_string());
    }
    let mut ratios = baseline
        .iter()
        .zip(candidate)
        .map(|(left, right)| left.p95_ns() as f64 / right.p95_ns().max(1) as f64)
        .collect::<Vec<_>>();
    ratios.sort_by(f64::total_cmp);
    let mut generator = seed.max(1);
    let mut sample = vec![0.0; ratios.len()];
    let mut medians = Vec::with_capacity(400);
    for _ in 0..400 {
        for value in &mut sample {
            generator ^= generator << 13;
            generator ^= generator >> 7;
            generator ^= generator << 17;
            *value = ratios[generator as usize % ratios.len()];
        }
        sample.sort_by(f64::total_cmp);
        medians.push(sample[(sample.len() - 1) / 2]);
    }
    medians.sort_by(f64::total_cmp);
    Ok(medians[((medians.len() - 1) as f64 * 0.025).floor() as usize])
}

fn run_arm(
    arm: Arm,
    capability: PreparedCapability,
    command: &PreparedCommand,
    requests: &Requests,
    hot: &mut HotState,
    view_fingerprint: u64,
) -> Result<Observation, String> {
    let receipt = match arm {
        Arm::StatelessJson => {
            let (decoded_capability, decoded_command) =
                kernel_v06::decode_stateless_json_request(&requests.json)?;
            let receipt = kernel_v06::execute_prepared(
                &decoded_capability,
                &decoded_command,
                &mut hot.state,
                &mut hot.scratch,
            )?;
            kernel_v06::encode_json_result_into(&mut hot.response, receipt)?;
            let decoded = kernel_v06::decode_json_result(&hot.response)?;
            require_equal_receipt(receipt, decoded)?;
            decoded
        }
        Arm::StatelessWire => {
            let (decoded_capability, decoded_command) =
                kernel_v06::decode_full_wire_request(&requests.stateless_wire)?;
            let receipt = kernel_v06::execute_prepared(
                &decoded_capability,
                &decoded_command,
                &mut hot.state,
                &mut hot.scratch,
            )?;
            kernel_v06::encode_wire_result_into(&mut hot.response, receipt)?;
            let decoded = kernel_v06::decode_wire_result(&hot.response)?;
            require_equal_receipt(receipt, decoded)?;
            decoded
        }
        Arm::PreparedWire => {
            let decoded_command =
                kernel_v06::decode_prepared_wire_request(&requests.prepared_wire)?;
            let receipt = kernel_v06::execute_prepared(
                &capability,
                &decoded_command,
                &mut hot.state,
                &mut hot.scratch,
            )?;
            kernel_v06::encode_wire_result_into(&mut hot.response, receipt)?;
            let decoded = kernel_v06::decode_wire_result(&hot.response)?;
            require_equal_receipt(receipt, decoded)?;
            decoded
        }
        Arm::DirectKernel => {
            kernel_v06::execute_prepared(&capability, command, &mut hot.state, &mut hot.scratch)?
        }
    };
    Ok(Observation {
        response_bytes: if arm == Arm::DirectKernel {
            0
        } else {
            hot.response.len()
        },
        semantic_digest: kernel_v06::hash_fingerprint(&receipt.chain_root),
        view_digest: view_fingerprint,
        rendered_bytes: 0,
    })
}

fn measure_ablations(
    base: &KernelState,
    capability: PreparedCapability,
    command: &PreparedCommand,
    iterations: usize,
    warmup: usize,
) -> Result<Ablations, String> {
    let changes = command.active_changes();
    let mut transition_state = base.clone();
    let transition = measure_batch_prepared(
        &mut transition_state,
        iterations,
        warmup,
        |state| state.reset_changed_from(base, changes),
        |state| {
            kernel_v06::execute_transition_only(&capability, command, state)?;
            Ok(Observation {
                response_bytes: 0,
                semantic_digest: state.revision,
                view_digest: 0,
                rendered_bytes: 0,
            })
        },
    )?;
    let transition = finish_arm(
        "transition-only",
        "Unsafe transition-only ceiling",
        0,
        base.retained_bytes(),
        true,
        vec![transition],
    )?;

    let mut event_hot = HotState {
        state: base.clone(),
        scratch: KernelScratch::default(),
        response: Vec::new(),
        rendered: String::with_capacity(1_024),
    };
    let event = measure_batch_prepared(
        &mut event_hot,
        iterations,
        warmup,
        |hot| {
            hot.state.reset_changed_from(base, changes)?;
            hot.scratch = KernelScratch::default();
            Ok(())
        },
        |hot| {
            let receipt = kernel_v06::execute_prepared(
                &capability,
                command,
                &mut hot.state,
                &mut hot.scratch,
            )?;
            Ok(receipt_observation(receipt, 0))
        },
    )?;
    let event = finish_arm(
        "event-receipt",
        "Canonical event transition",
        0,
        kernel_v06::control_bytes(),
        true,
        vec![event],
    )?;

    let materialised = measure_batch_prepared(
        &mut event_hot,
        iterations,
        warmup,
        |hot| {
            hot.state.reset_changed_from(base, changes)?;
            hot.scratch = KernelScratch::default();
            hot.rendered.clear();
            Ok(())
        },
        |hot| {
            let receipt = kernel_v06::execute_prepared(
                &capability,
                command,
                &mut hot.state,
                &mut hot.scratch,
            )?;
            let rendered = kernel_v06::render_patch_into(&mut hot.rendered, &hot.state, changes)?;
            Ok(receipt_observation(receipt, rendered))
        },
    )?;
    let materialised = finish_arm(
        "human-materialisation",
        "Event transition + exact human patch",
        0,
        kernel_v06::control_bytes() + event_hot.rendered.capacity(),
        true,
        vec![materialised],
    )?;

    let receipt = exact_receipt(base, capability, command)?;
    let mut checkpoint = Checkpoint::create(receipt, 32, &CHECKPOINT_KEY);
    let checkpoint_batch = measure_batch_prepared(
        &mut checkpoint,
        iterations,
        warmup,
        |_| Ok(()),
        |value| {
            *value = Checkpoint::create(receipt, 32, &CHECKPOINT_KEY);
            if !value.verify(receipt, &CHECKPOINT_KEY) {
                return Err("the measured checkpoint did not verify".to_string());
            }
            Ok(receipt_observation(receipt, 0))
        },
    )?;
    let checkpoint = finish_arm(
        "authenticated-checkpoint",
        "Fixture-authenticated checkpoint",
        0,
        std::mem::size_of::<Checkpoint>(),
        true,
        vec![checkpoint_batch],
    )?;
    let receipt_incremental_median_ns = event.median_ns.saturating_sub(transition.median_ns);
    let receipt_incremental_thread_cpu_ns = event
        .median_thread_cpu_ns
        .saturating_sub(transition.median_thread_cpu_ns);
    Ok(Ablations {
        arms: vec![transition, event, materialised, checkpoint],
        receipt_incremental_median_ns,
        receipt_incremental_thread_cpu_ns,
    })
}

fn prove_exactness(
    base: &KernelState,
    capability: PreparedCapability,
    command: &PreparedCommand,
    requests: &Requests,
) -> Result<Exactness, String> {
    let view_fingerprint = exact_view_fingerprint(base, capability, command)?;
    let mut states = Vec::new();
    let mut receipts = Vec::new();
    let mut events = Vec::new();
    let mut views = Vec::new();
    let mut deterministic_encodings = true;
    for arm in Arm::ALL {
        let mut first = HotState {
            state: base.clone(),
            scratch: KernelScratch::default(),
            response: Vec::with_capacity(192),
            rendered: String::with_capacity(1_024),
        };
        let first_observation = run_arm(
            arm,
            capability,
            command,
            requests,
            &mut first,
            view_fingerprint,
        )?;
        let mut second = HotState {
            state: base.clone(),
            scratch: KernelScratch::default(),
            response: Vec::with_capacity(192),
            rendered: String::with_capacity(1_024),
        };
        let second_observation = run_arm(
            arm,
            capability,
            command,
            requests,
            &mut second,
            view_fingerprint,
        )?;
        deterministic_encodings &= first.response == second.response
            && first.scratch.event == second.scratch.event
            && first_observation.semantic_digest == second_observation.semantic_digest;
        let mut view = String::with_capacity(1_024);
        kernel_v06::render_patch_into(&mut view, &first.state, command.active_changes())?;
        states.push(first.state);
        receipts.push(first.scratch.event.receipt);
        events.push(first.scratch.event.bytes[..usize::from(first.scratch.event.len)].to_vec());
        views.push(view);
    }
    let states_equal = states.windows(2).all(|pair| pair[0] == pair[1]);
    let receipts_equal = receipts.windows(2).all(|pair| pair[0] == pair[1]);
    let canonical_events_equal = events.windows(2).all(|pair| pair[0] == pair[1]);
    let human_views_equal = views.windows(2).all(|pair| pair[0] == pair[1]);
    let mut replay = base.clone();
    let mut replay_scratch = KernelScratch::default();
    kernel_v06::execute_prepared(&capability, command, &mut replay, &mut replay_scratch)?;
    let expected = replay.clone();
    replay = base.clone();
    let replay_receipt =
        kernel_v06::verify_and_replay_event(&capability, &replay_scratch.event, &mut replay)?;
    let replay_equal = replay == expected && replay_receipt == replay_scratch.event.receipt;
    let checkpoint = Checkpoint::create(replay_receipt, 1, &CHECKPOINT_KEY);
    let checkpoints_verify = checkpoint.verify(replay_receipt, &CHECKPOINT_KEY);
    let (refusals_passed, refusals_total) = refusal_suite(base, capability, command)?;
    Ok(Exactness {
        states_equal,
        receipts_equal,
        canonical_events_equal,
        human_views_equal,
        replay_equal,
        checkpoints_verify,
        refusals_passed,
        refusals_total,
        deterministic_encodings,
    })
}

fn refusal_suite(
    base: &KernelState,
    capability: PreparedCapability,
    command: &PreparedCommand,
) -> Result<(usize, usize), String> {
    let mut passed = 0;
    let mut total = 0;
    let mut check = |candidate_capability: PreparedCapability,
                     candidate_command: PreparedCommand| {
        total += 1;
        let mut state = base.clone();
        let mut scratch = KernelScratch::default();
        let refused = kernel_v06::execute_prepared(
            &candidate_capability,
            &candidate_command,
            &mut state,
            &mut scratch,
        )
        .is_err();
        if refused && state == *base {
            passed += 1;
        }
    };
    let mut bad = *command;
    bad.capability_handle ^= 1;
    check(capability, bad);
    let mut bad = *command;
    bad.capability_generation += 1;
    check(capability, bad);
    let mut bad = *command;
    bad.expected_revision += 1;
    check(capability, bad);
    let mut bad = *command;
    bad.change_count = 17;
    check(capability, bad);
    let mut bad = *command;
    bad.changes[1].task_ordinal = bad.changes[0].task_ordinal;
    check(capability, bad);
    let mut bad = *command;
    bad.changes[0].task_ordinal = 600;
    check(capability, bad);
    let mut bad = *command;
    bad.changes[0].status = 4;
    check(capability, bad);
    let mut bad_capability = capability;
    bad_capability.handle ^= 1;
    check(bad_capability, *command);

    let mut executed = base.clone();
    let mut scratch = KernelScratch::default();
    let receipt = kernel_v06::execute_prepared(&capability, command, &mut executed, &mut scratch)?;
    total += 1;
    scratch.event.bytes[0] ^= 1;
    let mut replay = base.clone();
    if kernel_v06::verify_and_replay_event(&capability, &scratch.event, &mut replay).is_err()
        && replay == *base
    {
        passed += 1;
    }
    total += 1;
    let mut checkpoint = Checkpoint::create(receipt, 1, &CHECKPOINT_KEY);
    checkpoint.authenticator[0] ^= 1;
    if !checkpoint.verify(receipt, &CHECKPOINT_KEY) {
        passed += 1;
    }
    Ok((passed, total))
}

fn hard_gate(
    arms: &[ArmMeasurement],
    ablations: &Ablations,
    exactness: &Exactness,
    attribution: &Attribution,
    memory: &MemoryEvidence,
    baseline_present: bool,
) -> Result<HardGate, String> {
    let prepared = find_arm(arms, "prepared-wire")?;
    let direct = find_arm(arms, "direct-kernel")?;
    let checks = vec![
        gate(
            "lossless-state",
            "Every arm and replay produce one canonical state",
            "exact",
            format!(
                "arms={}, replay={}",
                exactness.states_equal, exactness.replay_equal
            ),
            exactness.states_equal && exactness.replay_equal,
        ),
        gate(
            "lossless-output",
            "Every arm produces one exact human patch",
            "byte-identical",
            exactness.human_views_equal.to_string(),
            exactness.human_views_equal,
        ),
        gate(
            "receipt-and-event",
            "Receipts and canonical events match across arms",
            "exact",
            format!(
                "receipts={}, events={}",
                exactness.receipts_equal, exactness.canonical_events_equal
            ),
            exactness.receipts_equal && exactness.canonical_events_equal,
        ),
        gate(
            "security-refusals",
            "Every changed authority, command, event, and checkpoint refuses",
            "10/10",
            format!("{}/{}", exactness.refusals_passed, exactness.refusals_total),
            exactness.refusals_passed == exactness.refusals_total,
        ),
        gate(
            "direct-p95",
            "Direct kernel p95 upper interval",
            "≤2.5 µs",
            format!("{} ns", direct.p95_ci95_high_ns),
            direct.p95_ci95_high_ns <= TARGET_DIRECT_P95_NS,
        ),
        gate(
            "prepared-p95",
            "Prepared wire p95 upper interval",
            "≤6 µs",
            format!("{} ns", prepared.p95_ci95_high_ns),
            prepared.p95_ci95_high_ns <= TARGET_PREPARED_P95_NS,
        ),
        gate(
            "v05-speedup",
            "Local architectural paths beat the v0.5 tuned application path",
            "≥4× prepared and ≥8× direct",
            format!(
                "prepared={}, direct={}",
                optional_ratio(attribution.prepared_vs_v05_tuned_conservative_p95_speedup),
                optional_ratio(attribution.direct_vs_v05_tuned_conservative_p95_speedup)
            ),
            baseline_present
                && attribution
                    .prepared_vs_v05_tuned_conservative_p95_speedup
                    .is_some_and(|value| value >= 4.0)
                && attribution
                    .direct_vs_v05_tuned_conservative_p95_speedup
                    .is_some_and(|value| value >= 8.0),
        ),
        gate(
            "compact-control",
            "Prepared command and result stay within their control budgets",
            "≤64 bytes each",
            format!(
                "request={} bytes, response={} bytes",
                prepared.request_bytes, prepared.response_bytes
            ),
            prepared.request_bytes <= 64 && prepared.response_bytes <= 64,
        ),
        gate(
            "zero-allocation",
            "Prepared and direct hot paths allocate no Rust memory",
            "zero",
            format!(
                "prepared={:.1}, direct={:.1}",
                prepared.allocations_per_operation, direct.allocations_per_operation
            ),
            prepared.allocations_per_operation == 0.0 && direct.allocations_per_operation == 0.0,
        ),
        gate(
            "receipt-time",
            "Incremental local receipt cost",
            "≤500 ns",
            format!("{} ns", ablations.receipt_incremental_median_ns),
            ablations.receipt_incremental_median_ns <= TARGET_RECEIPT_NS,
        ),
        gate(
            "control-memory",
            "Local receipt-control state",
            "≤2 KiB",
            format!("{} bytes", memory.local_control_bytes),
            memory.local_control_bytes <= 2_048,
        ),
        gate(
            "determinism",
            "Repeated frames and events are byte-identical",
            "exact",
            exactness.deterministic_encodings.to_string(),
            exactness.deterministic_encodings,
        ),
    ];
    Ok(HardGate {
        passed: checks.iter().all(|check| check.passed),
        checks,
    })
}

fn hard_gate_v07(
    arms: &[ArmMeasurement],
    ablations: &Ablations,
    exactness: &Exactness,
    attribution: &Attribution,
    memory: &MemoryEvidence,
    profile: Profile,
) -> Result<HardGate, String> {
    let prepared = find_arm(arms, "prepared-wire")?;
    let direct = find_arm(arms, "direct-kernel")?;
    let (prepared_speedup, direct_speedup) = if profile == Profile::V09 {
        (
            attribution
                .prepared_vs_stateless_json_paired_p95_speedup_low
                .ok_or_else(|| "the paired prepared speedup is absent".to_string())?,
            attribution
                .direct_vs_stateless_json_paired_p95_speedup_low
                .ok_or_else(|| "the paired direct speedup is absent".to_string())?,
        )
    } else {
        (
            attribution.prepared_vs_stateless_json_conservative_p95_speedup,
            attribution.direct_vs_stateless_json_conservative_p95_speedup,
        )
    };
    let checks = vec![
        gate(
            "lossless-state",
            "Every arm and replay produce one canonical state",
            "exact",
            format!(
                "arms={}, replay={}",
                exactness.states_equal, exactness.replay_equal
            ),
            exactness.states_equal && exactness.replay_equal,
        ),
        gate(
            "lossless-output",
            "Every arm produces one exact human patch",
            "byte-identical",
            exactness.human_views_equal.to_string(),
            exactness.human_views_equal,
        ),
        gate(
            "receipt-and-event",
            "Receipts and canonical events match across arms",
            "exact",
            format!(
                "receipts={}, events={}",
                exactness.receipts_equal, exactness.canonical_events_equal
            ),
            exactness.receipts_equal && exactness.canonical_events_equal,
        ),
        gate(
            "security-refusals",
            "Every changed authority, command, event, and checkpoint refuses",
            "10/10",
            format!("{}/{}", exactness.refusals_passed, exactness.refusals_total),
            exactness.refusals_passed == exactness.refusals_total,
        ),
        gate(
            "direct-p95",
            "Direct kernel p95 upper interval",
            "≤2.5 µs",
            format!("{} ns", direct.p95_ci95_high_ns),
            direct.p95_ci95_high_ns <= TARGET_DIRECT_P95_NS,
        ),
        gate(
            "prepared-p95",
            "Prepared wire p95 upper interval",
            "≤6 µs",
            format!("{} ns", prepared.p95_ci95_high_ns),
            prepared.p95_ci95_high_ns <= TARGET_PREPARED_P95_NS,
        ),
        gate(
            "same-executable-speedup",
            "Local paths beat stateless JSON in the same executable",
            "≥3× prepared and ≥4× direct",
            format!(
                "prepared={:.2}×, direct={:.2}×",
                prepared_speedup, direct_speedup
            ),
            prepared_speedup >= TARGET_PREPARED_JSON_SPEEDUP
                && direct_speedup >= TARGET_DIRECT_JSON_SPEEDUP,
        ),
        gate(
            "compact-control",
            "Prepared command and result stay within their control budgets",
            "≤64 bytes each",
            format!(
                "request={} bytes, response={} bytes",
                prepared.request_bytes, prepared.response_bytes
            ),
            prepared.request_bytes <= 64 && prepared.response_bytes <= 64,
        ),
        gate(
            "zero-allocation",
            "Prepared and direct hot paths allocate no Rust memory",
            "zero",
            format!(
                "prepared={:.1}, direct={:.1}",
                prepared.allocations_per_operation, direct.allocations_per_operation
            ),
            prepared.allocations_per_operation == 0.0 && direct.allocations_per_operation == 0.0,
        ),
        gate(
            "receipt-time",
            "Incremental local receipt cost",
            "≤500 ns",
            format!("{} ns", ablations.receipt_incremental_median_ns),
            ablations.receipt_incremental_median_ns <= TARGET_RECEIPT_NS,
        ),
        gate(
            "control-memory",
            "Local receipt-control state",
            "≤2 KiB",
            format!("{} bytes", memory.local_control_bytes),
            memory.local_control_bytes <= 2_048,
        ),
        gate(
            "determinism",
            "Repeated frames and events are byte-identical",
            "exact",
            exactness.deterministic_encodings.to_string(),
            exactness.deterministic_encodings,
        ),
    ];
    Ok(HardGate {
        passed: checks.iter().all(|check| check.passed),
        checks,
    })
}

fn attribution(
    arms: &[ArmMeasurement],
    baseline: Option<&Baseline>,
    paired: Option<PairedSpeedups>,
) -> Result<Attribution, String> {
    let json = find_arm(arms, "stateless-json")?;
    let prepared = find_arm(arms, "prepared-wire")?;
    let direct = find_arm(arms, "direct-kernel")?;
    let prepared_vs_v05 = baseline
        .map(|value| value.p95_ci95_low_ns as f64 / prepared.p95_ci95_high_ns.max(1) as f64);
    let direct_vs_v05 =
        baseline.map(|value| value.p95_ci95_low_ns as f64 / direct.p95_ci95_high_ns.max(1) as f64);
    Ok(Attribution {
        prepared_vs_stateless_json_p95_speedup: json.p95_ns as f64 / prepared.p95_ns.max(1) as f64,
        direct_vs_stateless_json_p95_speedup: json.p95_ns as f64 / direct.p95_ns.max(1) as f64,
        prepared_vs_stateless_json_conservative_p95_speedup: json.p95_ci95_low_ns as f64
            / prepared.p95_ci95_high_ns.max(1) as f64,
        direct_vs_stateless_json_conservative_p95_speedup: json.p95_ci95_low_ns as f64
            / direct.p95_ci95_high_ns.max(1) as f64,
        prepared_vs_stateless_json_paired_p95_speedup_low: paired.map(|value| value.prepared_low),
        direct_vs_stateless_json_paired_p95_speedup_low: paired.map(|value| value.direct_low),
        prepared_vs_v05_tuned_conservative_p95_speedup: prepared_vs_v05,
        direct_vs_v05_tuned_conservative_p95_speedup: direct_vs_v05,
        prepared_request_reduction_percent: reduction(json.request_bytes, prepared.request_bytes),
        prepared_response_reduction_percent: reduction(
            json.response_bytes,
            prepared.response_bytes,
        ),
    })
}

fn memory_evidence(
    base: &KernelState,
    baseline: Option<&Baseline>,
) -> Result<MemoryEvidence, String> {
    let v05_receipt_tree_reference_bytes = if baseline.is_some() {
        let value: serde_json::Value = serde_json::from_slice(
            &fs::read("results/latest.json").map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        value["application"]["retained_memory"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == "local"))
            .and_then(|row| row["receipt_tree_bytes"].as_u64())
    } else {
        None
    };
    let local_control_bytes = kernel_v06::control_bytes() as u64;
    let local_control_reduction_percent =
        v05_receipt_tree_reference_bytes.map(|value| reduction(value, local_control_bytes));
    Ok(MemoryEvidence {
        state_bytes: base.retained_bytes() as u64,
        local_control_bytes,
        event_slot_capacity_bytes: kernel_v06::EVENT_CAPACITY as u64,
        v05_receipt_tree_reference_bytes,
        local_control_reduction_percent,
    })
}

fn examples(
    base: &KernelState,
    capability: PreparedCapability,
    command: &PreparedCommand,
    requests: &Requests,
) -> Result<Examples, String> {
    let mut state = base.clone();
    let mut scratch = KernelScratch::default();
    kernel_v06::execute_prepared(&capability, command, &mut state, &mut scratch)?;
    let mut view = String::with_capacity(1_024);
    kernel_v06::render_patch_into(&mut view, &state, command.active_changes())?;
    Ok(Examples {
        stateless_json: String::from_utf8(requests.json.clone())
            .map_err(|_| "the JSON example is not UTF-8".to_string())?,
        stateless_wire_hex: hex(&requests.stateless_wire),
        prepared_wire_hex: hex(&requests.prepared_wire),
        canonical_event_hex: hex(&scratch.event.bytes[..usize::from(scratch.event.len)]),
        exact_human_patch: view,
    })
}

fn exact_receipt(
    base: &KernelState,
    capability: PreparedCapability,
    command: &PreparedCommand,
) -> Result<EventReceipt, String> {
    let mut state = base.clone();
    let mut scratch = KernelScratch::default();
    kernel_v06::execute_prepared(&capability, command, &mut state, &mut scratch)
}

fn exact_view_fingerprint(
    base: &KernelState,
    capability: PreparedCapability,
    command: &PreparedCommand,
) -> Result<u64, String> {
    let mut state = base.clone();
    let mut scratch = KernelScratch::default();
    kernel_v06::execute_prepared(&capability, command, &mut state, &mut scratch)?;
    let mut view = String::with_capacity(1_024);
    kernel_v06::render_patch_into(&mut view, &state, command.active_changes())?;
    let hash = *blake3::hash(view.as_bytes()).as_bytes();
    Ok(kernel_v06::hash_fingerprint(&hash))
}

fn receipt_observation(receipt: EventReceipt, rendered_bytes: usize) -> Observation {
    Observation {
        response_bytes: 0,
        semantic_digest: kernel_v06::hash_fingerprint(&receipt.chain_root),
        view_digest: receipt.result_handle,
        rendered_bytes,
    }
}

fn request_len(arm: Arm, requests: &Requests) -> usize {
    match arm {
        Arm::StatelessJson => requests.json.len(),
        Arm::StatelessWire => requests.stateless_wire.len(),
        Arm::PreparedWire => requests.prepared_wire.len(),
        Arm::DirectKernel => 0,
    }
}

fn request_capacity(arm: Arm, requests: &Requests) -> usize {
    match arm {
        Arm::StatelessJson => requests.json.capacity(),
        Arm::StatelessWire => requests.stateless_wire.capacity(),
        Arm::PreparedWire => requests.prepared_wire.capacity(),
        Arm::DirectKernel => 0,
    }
}

fn require_equal_receipt(expected: EventReceipt, actual: EventReceipt) -> Result<(), String> {
    if expected != actual {
        return Err("the decoded event receipt does not match".to_string());
    }
    Ok(())
}

fn load_v05_baseline(path: &Path) -> Result<Option<Baseline>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if value["schema"] != "ndabi-poc-result-v0.5" {
        return Ok(None);
    }
    let arm = value["application"]["arms"]
        .as_array()
        .and_then(|arms| arms.iter().find(|arm| arm["id"] == "tuned"))
        .ok_or_else(|| "the v0.5 tuned application arm is absent".to_string())?;
    Ok(Some(Baseline {
        source: path.display().to_string(),
        p95_ns: required_u64(arm, "p95_ns")?,
        p95_ci95_low_ns: required_u64(arm, "p95_ci95_low_ns")?,
        operations_per_second: arm["operations_per_second"]
            .as_f64()
            .ok_or_else(|| "the v0.5 operations rate is absent".to_string())?,
        median_thread_cpu_ns: required_u64(arm, "median_thread_cpu_ns")?,
    }))
}

fn required_u64(value: &serde_json::Value, key: &str) -> Result<u64, String> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("the v0.5 {key} value is absent"))
}

fn find_arm<'a>(arms: &'a [ArmMeasurement], id: &str) -> Result<&'a ArmMeasurement, String> {
    arms.iter()
        .find(|arm| arm.id == id)
        .ok_or_else(|| format!("the {id} measurement is absent"))
}

fn gate(
    id: &'static str,
    label: &'static str,
    target: &'static str,
    observed: String,
    passed: bool,
) -> GateCheck {
    GateCheck {
        id,
        label,
        target,
        observed,
        passed,
    }
}

fn reduction(baseline: u64, candidate: u64) -> f64 {
    if baseline == 0 {
        return 0.0;
    }
    (baseline as f64 - candidate as f64) / baseline as f64 * 100.0
}

fn optional_ratio(value: Option<f64>) -> String {
    value
        .map(|ratio| format!("{ratio:.2}×"))
        .unwrap_or_else(|| "unavailable".to_string())
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<(usize, usize), String> {
    let mut iterations = 2_000usize;
    let mut warmup = 100usize;
    while let Some(argument) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{argument} needs a value"))?;
        match argument.as_str() {
            "--iterations" => {
                iterations = value
                    .parse()
                    .map_err(|_| "--iterations needs an integer".to_string())?;
            }
            "--warmup" => {
                warmup = value
                    .parse()
                    .map_err(|_| "--warmup needs an integer".to_string())?;
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if iterations < BLOCKS_PER_ARM || !iterations.is_multiple_of(BLOCKS_PER_ARM) {
        return Err(format!(
            "--iterations must be at least {BLOCKS_PER_ARM} and divisible by {BLOCKS_PER_ARM}"
        ));
    }
    if warmup > 100_000 {
        return Err("--warmup must not exceed 100000".to_string());
    }
    Ok((iterations, warmup))
}

fn request_scheduler(profile: Profile) -> Result<&'static str, String> {
    if profile != Profile::V08 {
        return Ok("operating-system-default");
    }
    request_interactive_qos()?;
    Ok("macos-user-interactive")
}

#[cfg(target_os = "macos")]
fn request_interactive_qos() -> Result<(), String> {
    const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
    unsafe extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
    // The recorded QoS request reduces P-core and E-core migration during the controlled campaign.
    let status = unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) };
    if status != 0 {
        return Err(format!(
            "macOS refused the user-interactive scheduler request with status {status}"
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn request_interactive_qos() -> Result<(), String> {
    Err("the v0.8 scheduler profile requires macOS".to_string())
}

fn environment(profile: Profile, scheduler_profile: &'static str) -> Environment {
    Environment {
        os: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        rustc: command_output("rustc", &["--version"]),
        git_commit: command_output("git", &["rev-parse", "HEAD"]),
        git_worktree_state: if command_output("git", &["status", "--porcelain"]).is_empty() {
            "clean".to_string()
        } else {
            "dirty".to_string()
        },
        scheduler_profile,
        source_fingerprint_blake3: source_fingerprint(profile),
    }
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

fn source_fingerprint(profile: Profile) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(include_bytes!("ndabi_v06.rs"));
    hasher.update(include_bytes!("../kernel_v06.rs"));
    hasher.update(include_bytes!("../durable_v07.rs"));
    hasher.update(include_bytes!("../measure.rs"));
    hasher.update(include_bytes!("../alloc.rs"));
    hasher.update(include_bytes!("../../Cargo.toml"));
    hasher.update(include_bytes!("../../Cargo.lock"));
    match profile {
        Profile::V06 => {
            hasher.update(include_bytes!("ndabi_v06.rs"));
            hasher.update(include_bytes!("../../validation_suite_v06.py"));
            hasher.update(include_bytes!(
                "../../../../specs/ndabi_poc_preregistration_v0_6.md"
            ))
        }
        Profile::V07 => {
            hasher.update(include_bytes!("ndabi_v07.rs"));
            hasher.update(include_bytes!("../../validation_suite_v07.py"));
            hasher.update(include_bytes!(
                "../../../../specs/ndabi_poc_preregistration_v0_7.md"
            ))
        }
        Profile::V08 => {
            hasher.update(include_bytes!("ndabi_v08.rs"));
            hasher.update(include_bytes!("../../validation_suite_v07.py"));
            hasher.update(include_bytes!("../../validation_suite_v08.py"));
            hasher.update(include_bytes!(
                "../../../../specs/ndabi_poc_preregistration_v0_8.md"
            ))
        }
        Profile::V09 => {
            hasher.update(include_bytes!("ndabi_v09.rs"));
            hasher.update(include_bytes!("../../validation_suite_v07.py"));
            hasher.update(include_bytes!("../../validation_suite_v09.py"));
            hasher.update(include_bytes!(
                "../../../../specs/ndabi_poc_preregistration_v0_9.md"
            ))
        }
    };
    hasher.finalize().to_hex().to_string()
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prepared_frame_stays_within_the_frozen_budget() {
        let capability = PreparedCapability::fixture();
        let changes = kernel_v06::fixed_changes();
        let command = PreparedCommand::fixture(capability, changes);
        let requests = encode_requests(capability, &command, changes).expect("encode");
        assert!(requests.prepared_wire.len() <= 64);
        let receipt =
            exact_receipt(&KernelState::fixture(), capability, &command).expect("receipt");
        let mut response = Vec::new();
        kernel_v06::encode_wire_result_into(&mut response, receipt).expect("response");
        assert!(response.len() <= 64);
    }

    #[test]
    fn missing_v05_evidence_remains_explicit() {
        assert!(load_v05_baseline(Path::new("does-not-exist.json"))
            .expect("load")
            .is_none());
    }
}
