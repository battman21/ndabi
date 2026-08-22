use std::fmt;
use std::io::Write;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::measure::{
    finish_arm, measure_batch_prepared, median_operation_timing, ArmBatch, ArmMeasurement,
    Observation, PhaseMeasurement, RetainedMemoryBreakdown,
};
use crate::receipt::{
    hash_fingerprint, hash_hex, parse_hash, Receipt as AppReceipt, ReceiptItem, ReceiptPlan,
    ReceiptTree, ReceiptUpdate, HASH_BYTES,
};
use crate::wire::{
    append_crc32, hex, push_envelope, push_u32, push_u64, validate_envelope, verify_crc32,
    Envelope, Reader,
};

const APP_MAGIC: &[u8; 4] = b"NDAA";
const APP_RESPONSE_MAGIC: &[u8; 4] = b"NDAP";
const APP_VERSION: u8 = 1;
const APPLY_PATCH: u8 = 0x21;
const BASE_REVISION: u64 = 7;
const MEASUREMENT_CYCLES: usize = 10;
const BALANCED_SCHEDULE: [[AppArm; 4]; 4] = [
    [
        AppArm::FullJson,
        AppArm::PatchJson,
        AppArm::NdabiWire,
        AppArm::NdabiLocal,
    ],
    [
        AppArm::PatchJson,
        AppArm::NdabiWire,
        AppArm::NdabiLocal,
        AppArm::FullJson,
    ],
    [
        AppArm::NdabiWire,
        AppArm::NdabiLocal,
        AppArm::FullJson,
        AppArm::PatchJson,
    ],
    [
        AppArm::NdabiLocal,
        AppArm::FullJson,
        AppArm::PatchJson,
        AppArm::NdabiWire,
    ],
];
const MEASUREMENT_BLOCKS_PER_ARM: usize = BALANCED_SCHEDULE.len() * MEASUREMENT_CYCLES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppArm {
    FullJson,
    PatchJson,
    NdabiWire,
    NdabiLocal,
}

impl AppArm {
    pub const ALL: [Self; 4] = [
        Self::FullJson,
        Self::PatchJson,
        Self::NdabiWire,
        Self::NdabiLocal,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::FullJson => "human",
            Self::PatchJson => "tuned",
            Self::NdabiWire => "wire",
            Self::NdabiLocal => "local",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::FullJson => "Named JSON + complete state",
            Self::PatchJson => "Compact JSON + state patch",
            Self::NdabiWire => "NDABI wire patch",
            Self::NdabiLocal => "NDABI local patch",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::FullJson => 0,
            Self::PatchJson => 1,
            Self::NdabiWire => 2,
            Self::NdabiLocal => 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Task {
    pub id: u32,
    pub status: u8,
    pub priority: u8,
    pub title: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AppState {
    pub revision: u64,
    pub tasks: Vec<Task>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
struct AppChange {
    task_id: u32,
    status: u8,
    priority: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AppCommand {
    envelope: Envelope,
    expected_revision: u64,
    changes: Vec<AppChange>,
}

#[derive(Debug)]
struct AppRoundTrip {
    response: Vec<u8>,
    receipt: AppReceipt,
    envelope: Envelope,
    rendered_bytes: usize,
}

struct AppHotState {
    client: AppState,
    receipt_tree: ReceiptTree,
    response: Vec<u8>,
    rendered: String,
}

#[derive(Debug, Serialize)]
pub struct AppExamples {
    pub human_request: String,
    pub tuned_request: String,
    pub ndabi_hex: String,
    pub ndabi_disassembly: String,
    pub human_view: String,
}

#[derive(Debug, Serialize)]
pub struct AppEvidence {
    pub task_count: usize,
    pub changed_task_count: usize,
    pub arms: Vec<ArmMeasurement>,
    pub semantic_results_equal: bool,
    pub human_views_equal: bool,
    pub trusted_envelopes_equal: bool,
    pub receipts_verified: bool,
    pub refusals_passed: u32,
    pub refusals_total: u32,
    pub deterministic_encodings: bool,
    pub diagnostic_samples: usize,
    pub measurement_cycles: usize,
    pub measurement_schedule: [&'static str; 4],
    pub phase_profiles: Vec<PhaseMeasurement>,
    pub retained_memory: Vec<RetainedMemoryBreakdown>,
    pub receipt_ablation: ReceiptAblation,
    pub receipt_pipeline: ReceiptPipeline,
    pub examples: AppExamples,
}

#[derive(Debug, Serialize)]
pub struct ReceiptAblation {
    pub changed_items: usize,
    pub roots_equal: bool,
    pub full_rebuild_median_ns: u64,
    pub incremental_median_ns: u64,
    pub full_rebuild_median_thread_cpu_ns: u64,
    pub incremental_median_thread_cpu_ns: u64,
    pub wall_reduction_percent: f64,
    pub thread_cpu_reduction_percent: f64,
    pub incremental_allocations_per_operation: f64,
    pub target_reduction_percent: f64,
    pub target_passed: bool,
}

#[derive(Debug, Serialize)]
pub struct ReceiptPipeline {
    pub producer_median_ns: u64,
    pub producer_median_thread_cpu_ns: u64,
    pub verifier_median_ns: u64,
    pub verifier_median_thread_cpu_ns: u64,
}

#[derive(Serialize, Deserialize)]
struct FullRequest {
    protocol_version: u8,
    authority: Envelope,
    expected_revision: u64,
    action: String,
    changes: Vec<AppChange>,
    response_mode: String,
}

#[derive(Serialize, Deserialize)]
struct PatchRequest {
    #[serde(rename = "v")]
    version: u8,
    #[serde(rename = "e")]
    envelope: Envelope,
    #[serde(rename = "r")]
    expected_revision: u64,
    #[serde(rename = "c")]
    changes: Vec<(u32, u8, u8)>,
}

#[derive(Serialize, Deserialize)]
struct FullReceipt {
    revision: u64,
    semantic_digest: String,
    human_view_digest: String,
}

#[derive(Serialize, Deserialize)]
struct FullResponse {
    state: AppState,
    receipt: FullReceipt,
}

#[derive(Serialize, Deserialize)]
struct PatchResponse {
    #[serde(rename = "n")]
    next_revision: u64,
    #[serde(rename = "p")]
    patches: Vec<(u32, u8, u8)>,
    #[serde(rename = "x")]
    receipt: (String, String),
}

#[derive(Deserialize)]
struct PatchRequestStack {
    #[serde(rename = "v")]
    version: u8,
    #[serde(rename = "e")]
    envelope: Envelope,
    #[serde(rename = "r")]
    expected_revision: u64,
    #[serde(rename = "c")]
    changes: StackChanges,
}

#[derive(Deserialize)]
struct PatchResponseStack<'a> {
    #[serde(rename = "n")]
    next_revision: u64,
    #[serde(rename = "p")]
    patches: StackChanges,
    #[serde(borrow, rename = "x")]
    receipt: (&'a str, &'a str),
}

struct StackChanges {
    items: [AppChange; 16],
    len: usize,
}

impl ReceiptItem for Task {
    fn receipt_id(&self) -> u32 {
        self.id
    }

    fn receipt_status(&self) -> u8 {
        self.status
    }

    fn receipt_priority(&self) -> u8 {
        self.priority
    }

    fn receipt_title(&self) -> &str {
        &self.title
    }
}

impl ReceiptUpdate for AppChange {
    fn receipt_id(&self) -> u32 {
        self.task_id
    }

    fn receipt_status(&self) -> u8 {
        self.status
    }

    fn receipt_priority(&self) -> u8 {
        self.priority
    }
}

impl<'de> Deserialize<'de> for StackChanges {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ChangesVisitor;

        impl<'de> Visitor<'de> for ChangesVisitor {
            type Value = StackChanges;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("at most 16 compact application changes")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = [AppChange::default(); 16];
                let mut len = 0;
                while let Some(change) = sequence.next_element::<(u32, u8, u8)>()? {
                    if len == items.len() {
                        return Err(de::Error::custom(
                            "compact application changes exceed the stack limit",
                        ));
                    }
                    items[len] = AppChange {
                        task_id: change.0,
                        status: change.1,
                        priority: change.2,
                    };
                    len += 1;
                }
                Ok(StackChanges { items, len })
            }
        }

        deserializer.deserialize_seq(ChangesVisitor)
    }
}

pub fn run(source_rows: usize, iterations: usize, warmup: usize) -> Result<AppEvidence, String> {
    let task_count = (source_rows / 8).clamp(128, 1_024);
    let base = fixture(task_count)?;
    let changes = fixed_changes(task_count)?;
    let expected = apply_to_clone(&base, &changes)?;
    let expected_view = render_full(&expected);
    let base_receipt_tree = ReceiptTree::new(base.revision, &base.tasks)?;
    let receipt = ReceiptTree::new(expected.revision, &expected.tasks)?.receipt();
    let envelope = Envelope::valid(16);
    let requests: Vec<(AppArm, Vec<u8>)> = AppArm::ALL
        .iter()
        .map(|arm| {
            Ok((
                *arm,
                encode_request(*arm, envelope, BASE_REVISION, &changes)?,
            ))
        })
        .collect::<Result<_, String>>()?;

    let mut exact_states = Vec::new();
    let mut exact_views = Vec::new();
    let mut exact_envelopes = Vec::new();
    let mut receipts_verified = true;
    let mut deterministic_encodings = requests.iter().all(|(arm, request)| {
        encode_request(*arm, envelope, BASE_REVISION, &changes)
            .map(|repeat| repeat == *request)
            .unwrap_or(false)
    });
    for (arm, request) in &requests {
        let mut first_client = base.clone();
        let first = if *arm == AppArm::NdabiLocal {
            process_local(envelope, BASE_REVISION, &changes, &base, &mut first_client)?
        } else {
            process(*arm, request, &base, &mut first_client, receipt)?
        };
        let mut second_client = base.clone();
        let second = if *arm == AppArm::NdabiLocal {
            process_local(envelope, BASE_REVISION, &changes, &base, &mut second_client)?
        } else {
            process(*arm, request, &base, &mut second_client, receipt)?
        };
        deterministic_encodings &= first.response == second.response;
        let first_view = render_full(&first_client);
        receipts_verified &= first.receipt
            == ReceiptTree::new(first_client.revision, &first_client.tasks)?.receipt();
        exact_states.push(first_client.clone());
        exact_views.push(first_view);
        exact_envelopes.push(first.envelope);
    }

    let semantic_results_equal = exact_states.iter().all(|state| state == &expected);
    let human_views_equal = exact_views.iter().all(|view| view == &expected_view);
    let trusted_envelopes_equal = exact_envelopes.windows(2).all(|pair| pair[0] == pair[1]);

    let mut batches: [Vec<ArmBatch>; 4] = std::array::from_fn(|_| Vec::new());
    let samples_per_block = iterations / MEASUREMENT_BLOCKS_PER_ARM;
    let warmup_per_block = warmup / MEASUREMENT_BLOCKS_PER_ARM;
    let warmup_remainder = warmup % MEASUREMENT_BLOCKS_PER_ARM;
    let mut arm_block_counts = [0usize; 4];
    let mut hot_states: [AppHotState; 4] = std::array::from_fn(|index| AppHotState {
        client: base.clone(),
        receipt_tree: base_receipt_tree.clone(),
        response: if index == AppArm::NdabiLocal.index() {
            Vec::new()
        } else {
            Vec::with_capacity(256)
        },
        rendered: String::with_capacity(1_024),
    });
    for _ in 0..MEASUREMENT_CYCLES {
        for round in BALANCED_SCHEDULE {
            for arm in round {
                let arm_index = arm.index();
                let block_warmup =
                    warmup_per_block + usize::from(arm_block_counts[arm_index] < warmup_remainder);
                arm_block_counts[arm_index] += 1;
                let request = &requests[arm_index].1;
                let hot_state = &mut hot_states[arm_index];
                let batch = measure_batch_prepared(
                    hot_state,
                    samples_per_block,
                    block_warmup,
                    |state| {
                        reset_client(&base, &changes, &mut state.client)?;
                        state.receipt_tree.clone_from(&base_receipt_tree);
                        Ok(())
                    },
                    |state| match arm {
                        AppArm::PatchJson => process_tuned_fast(
                            request,
                            &base,
                            &mut state.client,
                            &mut state.receipt_tree,
                            &mut state.response,
                            &mut state.rendered,
                        ),
                        AppArm::NdabiWire => process_wire_fast(
                            request,
                            &base,
                            &mut state.client,
                            &mut state.receipt_tree,
                            &mut state.response,
                            &mut state.rendered,
                        ),
                        AppArm::NdabiLocal => process_local_fast(
                            envelope,
                            BASE_REVISION,
                            &changes,
                            &base,
                            &mut state.client,
                            &mut state.receipt_tree,
                            &mut state.rendered,
                        ),
                        _ => {
                            let round_trip =
                                process(arm, request, &base, &mut state.client, receipt)?;
                            Ok(Observation {
                                response_bytes: round_trip.response.len(),
                                semantic_digest: hash_fingerprint(
                                    &round_trip.receipt.semantic_root,
                                ),
                                view_digest: hash_fingerprint(&round_trip.receipt.view_root),
                                rendered_bytes: round_trip.rendered_bytes,
                            })
                        }
                    },
                )?;
                batches[arm_index].push(batch);
            }
        }
    }
    let retained_memory = AppArm::ALL
        .iter()
        .map(|arm| {
            let hot_state = &hot_states[arm.index()];
            let request_capacity_bytes = requests[arm.index()].1.capacity();
            let response_capacity_bytes = hot_state.response.capacity();
            let rendered_capacity_bytes = hot_state.rendered.capacity();
            let receipt_tree_bytes = hot_state.receipt_tree.retained_bytes();
            let state_bytes = state_retained_bytes(&hot_state.client);
            RetainedMemoryBreakdown {
                id: arm.id().to_string(),
                label: arm.label().to_string(),
                request_capacity_bytes: request_capacity_bytes as u64,
                response_capacity_bytes: response_capacity_bytes as u64,
                rendered_capacity_bytes: rendered_capacity_bytes as u64,
                receipt_tree_bytes: receipt_tree_bytes as u64,
                state_bytes: state_bytes as u64,
                engine_handle_bytes: 0,
                total_bytes: (request_capacity_bytes
                    + response_capacity_bytes
                    + rendered_capacity_bytes
                    + receipt_tree_bytes
                    + state_bytes) as u64,
            }
        })
        .collect::<Vec<_>>();
    let measurements = AppArm::ALL
        .iter()
        .map(|arm| {
            let request_bytes = requests[arm.index()].1.len();
            let hot_state = &hot_states[arm.index()];
            let retained_rust_bytes = requests[arm.index()].1.capacity()
                + hot_state.response.capacity()
                + hot_state.rendered.capacity()
                + hot_state.receipt_tree.retained_bytes()
                + state_retained_bytes(&hot_state.client);
            finish_arm(
                arm.id(),
                arm.label(),
                request_bytes,
                retained_rust_bytes,
                deterministic_encodings,
                std::mem::take(&mut batches[arm.index()]),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let diagnostic_samples = iterations.clamp(20, 500);
    let phase_profiles = profile_stages(
        &requests,
        envelope,
        &base,
        &changes,
        receipt,
        diagnostic_samples,
        (warmup / 4).min(25),
    )?;
    let receipt_ablation = measure_receipt_ablation(
        &base,
        &expected,
        &changes,
        diagnostic_samples,
        (warmup / 4).min(25),
    )?;
    let receipt_pipeline = measure_receipt_pipeline(
        &base,
        &changes,
        receipt,
        diagnostic_samples,
        (warmup / 4).min(25),
    )?;

    let (refusals_passed, refusals_total) = refusal_suite(&base, &changes, receipt)?;
    let human_request = String::from_utf8(requests[0].1.clone())
        .map_err(|_| "human application request is not UTF-8".to_string())?;
    let tuned_request = String::from_utf8(requests[1].1.clone())
        .map_err(|_| "tuned application request is not UTF-8".to_string())?;
    let human_view = expected_view.lines().take(6).collect::<Vec<_>>().join("\n");

    Ok(AppEvidence {
        task_count,
        changed_task_count: changes.len(),
        arms: measurements,
        semantic_results_equal,
        human_views_equal,
        trusted_envelopes_equal,
        receipts_verified,
        refusals_passed,
        refusals_total,
        deterministic_encodings,
        diagnostic_samples,
        measurement_cycles: MEASUREMENT_CYCLES,
        measurement_schedule: [
            "human,tuned,wire,local",
            "tuned,wire,local,human",
            "wire,local,human,tuned",
            "local,human,tuned,wire",
        ],
        phase_profiles,
        retained_memory,
        receipt_ablation,
        receipt_pipeline,
        examples: AppExamples {
            human_request,
            tuned_request,
            ndabi_hex: hex(&requests[2].1),
            ndabi_disassembly: disassemble_request(&requests[2].1)?,
            human_view,
        },
    })
}

fn measure_receipt_pipeline(
    base: &AppState,
    changes: &[AppChange],
    receipt: AppReceipt,
    iterations: usize,
    warmup: usize,
) -> Result<ReceiptPipeline, String> {
    let producer_tree = ReceiptTree::new(base.revision, &base.tasks)?;
    let producer = median_operation_timing(iterations, warmup, || {
        std::hint::black_box(
            producer_tree
                .plan(&base.tasks, changes, receipt.revision)?
                .receipt(),
        );
        Ok(())
    })?;
    let verifier_tree = ReceiptTree::new(base.revision, &base.tasks)?;
    let verifier = median_operation_timing(iterations, warmup, || {
        std::hint::black_box(verify_patch_receipt(
            &verifier_tree,
            base,
            changes,
            receipt,
        )?);
        Ok(())
    })?;
    Ok(ReceiptPipeline {
        producer_median_ns: producer.wall_ns,
        producer_median_thread_cpu_ns: producer.thread_cpu_ns,
        verifier_median_ns: verifier.wall_ns,
        verifier_median_thread_cpu_ns: verifier.thread_cpu_ns,
    })
}

fn measure_receipt_ablation(
    base: &AppState,
    expected: &AppState,
    changes: &[AppChange],
    iterations: usize,
    warmup: usize,
) -> Result<ReceiptAblation, String> {
    let expected_receipt = ReceiptTree::new(expected.revision, &expected.tasks)?.receipt();
    let mut full_tree = ReceiptTree::new(base.revision, &base.tasks)?;
    let full_batch = crate::measure::measure_batch(iterations, warmup, || {
        let receipt = full_tree.rebuild(expected.revision, &expected.tasks)?;
        Ok(receipt_observation(receipt))
    })?;
    let full_retained_bytes = full_tree.retained_bytes();
    let full = finish_arm(
        "full-rebuild",
        "Complete receipt rebuild",
        0,
        full_retained_bytes,
        true,
        vec![full_batch],
    )?;

    let incremental_tree = ReceiptTree::new(base.revision, &base.tasks)?;
    let incremental_receipt = incremental_tree
        .plan(&base.tasks, changes, expected.revision)?
        .receipt();
    let incremental_batch = crate::measure::measure_batch(iterations, warmup, || {
        let receipt = incremental_tree
            .plan(&base.tasks, changes, expected.revision)?
            .receipt();
        Ok(receipt_observation(receipt))
    })?;
    let incremental = finish_arm(
        "incremental",
        "Incremental receipt proof",
        0,
        incremental_tree.retained_bytes(),
        true,
        vec![incremental_batch],
    )?;
    let wall_reduction_percent = reduction_percent(full.median_ns, incremental.median_ns);
    let thread_cpu_reduction_percent =
        reduction_percent(full.median_thread_cpu_ns, incremental.median_thread_cpu_ns);
    let target_reduction_percent = 80.0;

    Ok(ReceiptAblation {
        changed_items: changes.len(),
        roots_equal: incremental_receipt == expected_receipt,
        full_rebuild_median_ns: full.median_ns,
        incremental_median_ns: incremental.median_ns,
        full_rebuild_median_thread_cpu_ns: full.median_thread_cpu_ns,
        incremental_median_thread_cpu_ns: incremental.median_thread_cpu_ns,
        wall_reduction_percent,
        thread_cpu_reduction_percent,
        incremental_allocations_per_operation: incremental.allocations_per_operation,
        target_reduction_percent,
        target_passed: incremental_receipt == expected_receipt
            && thread_cpu_reduction_percent >= target_reduction_percent,
    })
}

fn receipt_observation(receipt: AppReceipt) -> Observation {
    Observation {
        response_bytes: 0,
        semantic_digest: hash_fingerprint(&receipt.semantic_root),
        view_digest: hash_fingerprint(&receipt.view_root),
        rendered_bytes: 0,
    }
}

fn reduction_percent(baseline: u64, candidate: u64) -> f64 {
    if baseline == 0 {
        return 0.0;
    }
    (baseline as f64 - candidate as f64) / baseline as f64 * 100.0
}

fn profile_stages(
    requests: &[(AppArm, Vec<u8>)],
    envelope: Envelope,
    base: &AppState,
    changes: &[AppChange],
    receipt: AppReceipt,
    iterations: usize,
    warmup: usize,
) -> Result<Vec<PhaseMeasurement>, String> {
    let mut profiles = Vec::new();
    for arm in AppArm::ALL {
        let request = &requests[arm.index()].1;
        let admission = median_operation_timing(iterations, warmup, || {
            if arm == AppArm::NdabiLocal {
                validate_operation(envelope, BASE_REVISION, changes, base)?;
                std::hint::black_box((envelope, BASE_REVISION, changes));
            } else if arm == AppArm::PatchJson {
                let (decoded_envelope, decoded_revision, decoded_changes, count) =
                    decode_tuned_request_stack(request)?;
                validate_operation(
                    decoded_envelope,
                    decoded_revision,
                    &decoded_changes[..count],
                    base,
                )?;
                std::hint::black_box((decoded_envelope, decoded_revision, decoded_changes));
            } else {
                let command = decode_request(arm, request)?;
                validate_operation(
                    command.envelope,
                    command.expected_revision,
                    &command.changes,
                    base,
                )?;
                std::hint::black_box(command);
            }
            Ok(())
        })?;

        let mut execution_client = base.clone();
        let execution = median_operation_timing(iterations, warmup, || {
            reset_client(base, changes, &mut execution_client)?;
            apply_in_place(&mut execution_client, changes)?;
            execution_client.revision = receipt.revision;
            std::hint::black_box(&execution_client);
            Ok(())
        })?;

        let mut result_client = base.clone();
        let base_receipt_tree = ReceiptTree::new(base.revision, &base.tasks)?;
        let mut result_receipt_tree = base_receipt_tree.clone();
        let mut response = Vec::with_capacity(128);
        let mut rendered = String::with_capacity(1_024);
        let result = median_operation_timing(iterations, warmup, || {
            reset_client(base, changes, &mut result_client)?;
            result_receipt_tree.clone_from(&base_receipt_tree);
            match arm {
                AppArm::NdabiLocal => {
                    let plan = verify_patch_receipt(
                        &result_receipt_tree,
                        &result_client,
                        changes,
                        receipt,
                    )?;
                    apply_in_place(&mut result_client, changes)?;
                    result_client.revision = receipt.revision;
                    result_receipt_tree.commit(&plan)?;
                    std::hint::black_box(render_patch_into(
                        &mut rendered,
                        &result_client,
                        changes,
                    )?);
                }
                AppArm::NdabiWire => {
                    encode_wire_response_into(&mut response, changes, receipt)?;
                    std::hint::black_box(apply_wire_response(
                        &response,
                        base,
                        &mut result_client,
                        &mut result_receipt_tree,
                        &mut rendered,
                    )?);
                }
                AppArm::PatchJson => {
                    encode_tuned_response_into(&mut response, changes, receipt)?;
                    std::hint::black_box(apply_tuned_response(
                        &response,
                        base,
                        &mut result_client,
                        &mut result_receipt_tree,
                        &mut rendered,
                    )?);
                }
                _ => {
                    let response = encode_response(arm, base, changes, receipt)?;
                    let (patches, decoded_receipt, complete_state) =
                        decode_response(arm, &response)?;
                    if let Some(state) = complete_state {
                        verify_semantic_receipt(&state, decoded_receipt)?;
                        std::hint::black_box(render_full(&state));
                        result_client = state;
                    } else {
                        let plan = verify_patch_receipt(
                            &result_receipt_tree,
                            &result_client,
                            &patches,
                            decoded_receipt,
                        )?;
                        apply_in_place(&mut result_client, &patches)?;
                        result_client.revision = decoded_receipt.revision;
                        result_receipt_tree.commit(&plan)?;
                        std::hint::black_box(render_patch_into(
                            &mut rendered,
                            &result_client,
                            &patches,
                        )?);
                    }
                }
            }
            Ok(())
        })?;

        profiles.push(PhaseMeasurement {
            id: arm.id().to_string(),
            label: arm.label().to_string(),
            admission_median_ns: admission.wall_ns,
            admission_median_thread_cpu_ns: admission.thread_cpu_ns,
            execution_median_ns: execution.wall_ns,
            execution_median_thread_cpu_ns: execution.thread_cpu_ns,
            result_median_ns: result.wall_ns,
            result_median_thread_cpu_ns: result.thread_cpu_ns,
        });
    }
    Ok(profiles)
}

fn fixture(task_count: usize) -> Result<AppState, String> {
    let mut tasks = Vec::with_capacity(task_count);
    for index in 0..task_count {
        let id = u32::try_from(index + 1).map_err(|_| "task identifier overflow".to_string())?;
        tasks.push(Task {
            id,
            status: u8::try_from(id % 3).map_err(|_| "task status overflow".to_string())?,
            priority: u8::try_from((id * 7) % 5)
                .map_err(|_| "task priority overflow".to_string())?,
            title: format!("Review trajectory {id:04}"),
        });
    }
    Ok(AppState {
        revision: BASE_REVISION,
        tasks,
    })
}

fn fixed_changes(task_count: usize) -> Result<Vec<AppChange>, String> {
    let step = (task_count / 8).max(1);
    (0..8)
        .map(|index| {
            let offset = (index * step).min(task_count - 1);
            Ok(AppChange {
                task_id: u32::try_from(offset + 1)
                    .map_err(|_| "change identifier overflow".to_string())?,
                status: u8::try_from((index + 1) % 4)
                    .map_err(|_| "change status overflow".to_string())?,
                priority: u8::try_from((index * 3 + 2) % 5)
                    .map_err(|_| "change priority overflow".to_string())?,
            })
        })
        .collect()
}

fn encode_request(
    arm: AppArm,
    envelope: Envelope,
    expected_revision: u64,
    changes: &[AppChange],
) -> Result<Vec<u8>, String> {
    match arm {
        AppArm::FullJson => serde_json::to_vec(&FullRequest {
            protocol_version: 1,
            authority: envelope,
            expected_revision,
            action: "set-task-fields".to_string(),
            changes: changes.to_vec(),
            response_mode: "complete-state".to_string(),
        })
        .map_err(|error| error.to_string()),
        AppArm::PatchJson => serde_json::to_vec(&PatchRequest {
            version: 1,
            envelope,
            expected_revision,
            changes: changes
                .iter()
                .map(|change| (change.task_id, change.status, change.priority))
                .collect(),
        })
        .map_err(|error| error.to_string()),
        AppArm::NdabiWire => {
            let mut bytes = Vec::with_capacity(96);
            bytes.extend_from_slice(APP_MAGIC);
            bytes.push(APP_VERSION);
            bytes.push(APPLY_PATCH);
            push_envelope(&mut bytes, envelope);
            push_u64(&mut bytes, expected_revision);
            bytes.push(
                u8::try_from(changes.len())
                    .map_err(|_| "application change count exceeds frame limit".to_string())?,
            );
            for change in changes {
                push_u32(&mut bytes, change.task_id);
                bytes.push(change.status);
                bytes.push(change.priority);
            }
            append_crc32(&mut bytes);
            Ok(bytes)
        }
        AppArm::NdabiLocal => Ok(Vec::new()),
    }
}

fn decode_request(arm: AppArm, bytes: &[u8]) -> Result<AppCommand, String> {
    match arm {
        AppArm::FullJson => {
            let request: FullRequest =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            if request.protocol_version != 1
                || request.action != "set-task-fields"
                || request.response_mode != "complete-state"
            {
                return Err("complete-state request shape is not authorised".to_string());
            }
            Ok(AppCommand {
                envelope: request.authority,
                expected_revision: request.expected_revision,
                changes: request.changes,
            })
        }
        AppArm::PatchJson => {
            let request: PatchRequest =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            if request.version != 1 {
                return Err("patch request version is not authorised".to_string());
            }
            Ok(AppCommand {
                envelope: request.envelope,
                expected_revision: request.expected_revision,
                changes: request
                    .changes
                    .into_iter()
                    .map(|change| AppChange {
                        task_id: change.0,
                        status: change.1,
                        priority: change.2,
                    })
                    .collect(),
            })
        }
        AppArm::NdabiWire => {
            let body = verify_crc32(bytes)?;
            let mut reader = Reader::new(body);
            if reader.take(4)? != APP_MAGIC {
                return Err("application frame magic does not match".to_string());
            }
            if reader.u8()? != APP_VERSION || reader.u8()? != APPLY_PATCH {
                return Err("application frame version or opcode is not authorised".to_string());
            }
            let envelope = reader.envelope()?;
            let expected_revision = reader.u64()?;
            let count = usize::from(reader.u8()?);
            let mut changes = Vec::with_capacity(count);
            for _ in 0..count {
                changes.push(AppChange {
                    task_id: reader.u32()?,
                    status: reader.u8()?,
                    priority: reader.u8()?,
                });
            }
            if reader.remaining() != 0 {
                return Err("application frame has trailing bytes".to_string());
            }
            Ok(AppCommand {
                envelope,
                expected_revision,
                changes,
            })
        }
        AppArm::NdabiLocal => Err("NDABI local has no wire request".to_string()),
    }
}

fn validate_operation(
    envelope: Envelope,
    expected_revision: u64,
    changes: &[AppChange],
    base: &AppState,
) -> Result<(), String> {
    validate_envelope(envelope, changes.len())?;
    if expected_revision != base.revision {
        return Err("application revision is stale".to_string());
    }
    validate_changes(changes, base)
}

fn validate_changes(changes: &[AppChange], base: &AppState) -> Result<(), String> {
    for change in changes {
        if change.status > 3 || change.priority > 4 {
            return Err("application change value is outside the typed range".to_string());
        }
        if change.task_id == 0
            || usize::try_from(change.task_id).unwrap_or(usize::MAX) > base.tasks.len()
        {
            return Err("application change names an unknown task".to_string());
        }
    }
    Ok(())
}

fn process(
    arm: AppArm,
    request: &[u8],
    base: &AppState,
    client: &mut AppState,
    expected_receipt: AppReceipt,
) -> Result<AppRoundTrip, String> {
    let command = decode_request(arm, request)?;
    validate_operation(
        command.envelope,
        command.expected_revision,
        &command.changes,
        base,
    )?;
    let response = encode_response(arm, base, &command.changes, expected_receipt)?;
    let (patches, receipt, complete_state) = decode_response(arm, &response)?;

    let rendered_bytes = if let Some(state) = complete_state {
        verify_semantic_receipt(&state, receipt)?;
        let view = render_full(&state);
        let bytes = view.len();
        *client = state;
        bytes
    } else {
        let mut receipt_tree = ReceiptTree::new(client.revision, &client.tasks)?;
        let plan = verify_patch_receipt(&receipt_tree, client, &patches, receipt)?;
        apply_in_place(client, &patches)?;
        client.revision = receipt.revision;
        receipt_tree.commit(&plan)?;
        render_patch(client, &patches)?.len()
    };

    Ok(AppRoundTrip {
        response,
        receipt,
        envelope: command.envelope,
        rendered_bytes,
    })
}

fn process_local(
    envelope: Envelope,
    expected_revision: u64,
    changes: &[AppChange],
    base: &AppState,
    client: &mut AppState,
) -> Result<AppRoundTrip, String> {
    validate_operation(envelope, expected_revision, changes, base)?;
    let mut receipt_tree = ReceiptTree::new(client.revision, &client.tasks)?;
    let plan = receipt_tree.plan(&client.tasks, changes, client.revision + 1)?;
    let receipt = plan.receipt();
    apply_in_place(client, changes)?;
    client.revision = receipt.revision;
    receipt_tree.commit(&plan)?;
    let rendered_bytes = render_patch(client, changes)?.len();
    Ok(AppRoundTrip {
        response: Vec::new(),
        receipt,
        envelope,
        rendered_bytes,
    })
}

fn process_wire_fast(
    request: &[u8],
    base: &AppState,
    client: &mut AppState,
    receipt_tree: &mut ReceiptTree,
    response: &mut Vec<u8>,
    rendered: &mut String,
) -> Result<Observation, String> {
    let (envelope, expected_revision, changes, change_count) = decode_wire_request_stack(request)?;
    let changes = &changes[..change_count];
    validate_operation(envelope, expected_revision, changes, base)?;
    let receipt = receipt_tree
        .plan(&client.tasks, changes, client.revision + 1)?
        .receipt();
    encode_wire_response_into(response, changes, receipt)?;
    let (decoded_receipt, rendered_bytes) =
        apply_wire_response(response, base, client, receipt_tree, rendered)?;
    Ok(Observation {
        response_bytes: response.len(),
        semantic_digest: hash_fingerprint(&decoded_receipt.semantic_root),
        view_digest: hash_fingerprint(&decoded_receipt.view_root),
        rendered_bytes,
    })
}

fn process_tuned_fast(
    request: &[u8],
    base: &AppState,
    client: &mut AppState,
    receipt_tree: &mut ReceiptTree,
    response: &mut Vec<u8>,
    rendered: &mut String,
) -> Result<Observation, String> {
    let (envelope, expected_revision, changes, count) = decode_tuned_request_stack(request)?;
    let changes = &changes[..count];
    validate_operation(envelope, expected_revision, changes, base)?;
    let receipt = receipt_tree
        .plan(&client.tasks, changes, client.revision + 1)?
        .receipt();
    encode_tuned_response_into(response, changes, receipt)?;
    let (decoded_receipt, rendered_bytes) =
        apply_tuned_response(response, base, client, receipt_tree, rendered)?;
    Ok(Observation {
        response_bytes: response.len(),
        semantic_digest: hash_fingerprint(&decoded_receipt.semantic_root),
        view_digest: hash_fingerprint(&decoded_receipt.view_root),
        rendered_bytes,
    })
}

fn process_local_fast(
    envelope: Envelope,
    expected_revision: u64,
    changes: &[AppChange],
    base: &AppState,
    client: &mut AppState,
    receipt_tree: &mut ReceiptTree,
    rendered: &mut String,
) -> Result<Observation, String> {
    validate_operation(envelope, expected_revision, changes, base)?;
    let plan = receipt_tree.plan(&client.tasks, changes, client.revision + 1)?;
    let receipt = plan.receipt();
    apply_in_place(client, changes)?;
    client.revision = receipt.revision;
    receipt_tree.commit(&plan)?;
    let rendered_bytes = render_patch_into(rendered, client, changes)?;
    Ok(Observation {
        response_bytes: 0,
        semantic_digest: hash_fingerprint(&receipt.semantic_root),
        view_digest: hash_fingerprint(&receipt.view_root),
        rendered_bytes,
    })
}

fn decode_tuned_request_stack(
    bytes: &[u8],
) -> Result<(Envelope, u64, [AppChange; 16], usize), String> {
    let request: PatchRequestStack =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if request.version != 1 {
        return Err("patch request version is not authorised".to_string());
    }
    Ok((
        request.envelope,
        request.expected_revision,
        request.changes.items,
        request.changes.len,
    ))
}

fn decode_wire_request_stack(
    bytes: &[u8],
) -> Result<(Envelope, u64, [AppChange; 16], usize), String> {
    let body = verify_crc32(bytes)?;
    let mut reader = Reader::new(body);
    if reader.take(4)? != APP_MAGIC {
        return Err("application frame magic does not match".to_string());
    }
    if reader.u8()? != APP_VERSION || reader.u8()? != APPLY_PATCH {
        return Err("application frame version or opcode is not authorised".to_string());
    }
    let envelope = reader.envelope()?;
    let expected_revision = reader.u64()?;
    let count = usize::from(reader.u8()?);
    if count > 16 {
        return Err("application frame exceeds the stack change limit".to_string());
    }
    let mut changes = [AppChange::default(); 16];
    for change in changes.iter_mut().take(count) {
        *change = AppChange {
            task_id: reader.u32()?,
            status: reader.u8()?,
            priority: reader.u8()?,
        };
    }
    if reader.remaining() != 0 {
        return Err("application frame has trailing bytes".to_string());
    }
    Ok((envelope, expected_revision, changes, count))
}

fn encode_wire_response_into(
    response: &mut Vec<u8>,
    changes: &[AppChange],
    receipt: AppReceipt,
) -> Result<(), String> {
    response.clear();
    response.extend_from_slice(APP_RESPONSE_MAGIC);
    response.push(APP_VERSION);
    response.push(0);
    push_u64(response, receipt.revision);
    response.extend_from_slice(&receipt.semantic_root);
    response.extend_from_slice(&receipt.view_root);
    response.push(
        u8::try_from(changes.len())
            .map_err(|_| "application patch count exceeds frame limit".to_string())?,
    );
    for change in changes {
        push_u32(response, change.task_id);
        response.push(change.status);
        response.push(change.priority);
    }
    append_crc32(response);
    Ok(())
}

fn apply_wire_response(
    bytes: &[u8],
    base: &AppState,
    client: &mut AppState,
    receipt_tree: &mut ReceiptTree,
    rendered: &mut String,
) -> Result<(AppReceipt, usize), String> {
    let body = verify_crc32(bytes)?;
    let mut reader = Reader::new(body);
    if reader.take(4)? != APP_RESPONSE_MAGIC {
        return Err("application response magic does not match".to_string());
    }
    if reader.u8()? != APP_VERSION || reader.u8()? != 0 {
        return Err("application response version or flags do not match".to_string());
    }
    let receipt = AppReceipt {
        revision: reader.u64()?,
        semantic_root: reader
            .take(HASH_BYTES)?
            .try_into()
            .map_err(|_| "application semantic root has the wrong length".to_string())?,
        view_root: reader
            .take(HASH_BYTES)?
            .try_into()
            .map_err(|_| "application view root has the wrong length".to_string())?,
    };
    if receipt.revision != base.revision + 1 {
        return Err("application response revision does not advance once".to_string());
    }
    let count = usize::from(reader.u8()?);
    if count > 16 {
        return Err("application response exceeds the stack patch limit".to_string());
    }
    let mut changes = [AppChange::default(); 16];
    for change in changes.iter_mut().take(count) {
        *change = AppChange {
            task_id: reader.u32()?,
            status: reader.u8()?,
            priority: reader.u8()?,
        };
    }
    if reader.remaining() != 0 {
        return Err("application response has trailing bytes".to_string());
    }
    let changes = &changes[..count];
    validate_changes(changes, base)?;
    let plan = verify_patch_receipt(receipt_tree, client, changes, receipt)?;
    apply_in_place(client, changes)?;
    client.revision = receipt.revision;
    receipt_tree.commit(&plan)?;
    let rendered_bytes = render_patch_into(rendered, client, changes)?;
    Ok((receipt, rendered_bytes))
}

fn encode_tuned_response_into(
    response: &mut Vec<u8>,
    changes: &[AppChange],
    receipt: AppReceipt,
) -> Result<(), String> {
    response.clear();
    write!(response, "{{\"n\":{},\"p\":[", receipt.revision).map_err(|error| error.to_string())?;
    for (index, change) in changes.iter().enumerate() {
        if index != 0 {
            response.push(b',');
        }
        write!(
            response,
            "[{},{},{}]",
            change.task_id, change.status, change.priority
        )
        .map_err(|error| error.to_string())?;
    }
    response.extend_from_slice(b"],\"x\":[\"");
    write_hash_hex(response, &receipt.semantic_root);
    response.extend_from_slice(b"\",\"");
    write_hash_hex(response, &receipt.view_root);
    response.extend_from_slice(b"\"]}");
    Ok(())
}

fn write_hash_hex(output: &mut Vec<u8>, hash: &[u8; HASH_BYTES]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in hash {
        output.push(HEX[usize::from(byte >> 4)]);
        output.push(HEX[usize::from(byte & 0x0f)]);
    }
}

fn apply_tuned_response(
    bytes: &[u8],
    base: &AppState,
    client: &mut AppState,
    receipt_tree: &mut ReceiptTree,
    rendered: &mut String,
) -> Result<(AppReceipt, usize), String> {
    let response: PatchResponseStack<'_> =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let receipt = AppReceipt {
        revision: response.next_revision,
        semantic_root: parse_hash(response.receipt.0)?,
        view_root: parse_hash(response.receipt.1)?,
    };
    if receipt.revision != base.revision + 1 {
        return Err("application response revision does not advance once".to_string());
    }
    let changes = &response.patches.items[..response.patches.len];
    validate_changes(changes, base)?;
    let plan = verify_patch_receipt(receipt_tree, client, changes, receipt)?;
    apply_in_place(client, changes)?;
    client.revision = receipt.revision;
    receipt_tree.commit(&plan)?;
    let rendered_bytes = render_patch_into(rendered, client, changes)?;
    Ok((receipt, rendered_bytes))
}

fn verify_semantic_receipt(state: &AppState, receipt: AppReceipt) -> Result<(), String> {
    let actual = ReceiptTree::new(state.revision, &state.tasks)?.receipt();
    if actual.semantic_root != receipt.semantic_root {
        return Err("application response semantic digest does not match".to_string());
    }
    if actual.view_root != receipt.view_root {
        return Err("application response view digest does not match".to_string());
    }
    Ok(())
}

fn verify_patch_receipt(
    receipt_tree: &ReceiptTree,
    state: &AppState,
    changes: &[AppChange],
    receipt: AppReceipt,
) -> Result<ReceiptPlan, String> {
    if receipt.revision != state.revision + 1 {
        return Err("application response revision does not advance once".to_string());
    }
    let plan = receipt_tree.plan(&state.tasks, changes, receipt.revision)?;
    let actual = plan.receipt();
    if actual.semantic_root != receipt.semantic_root {
        return Err("application response semantic digest does not match".to_string());
    }
    if actual.view_root != receipt.view_root {
        return Err("application response view digest does not match".to_string());
    }
    Ok(plan)
}

fn encode_response(
    arm: AppArm,
    base: &AppState,
    changes: &[AppChange],
    receipt: AppReceipt,
) -> Result<Vec<u8>, String> {
    match arm {
        AppArm::FullJson => serde_json::to_vec(&FullResponse {
            state: apply_to_clone(base, changes)?,
            receipt: FullReceipt {
                revision: receipt.revision,
                semantic_digest: hash_hex(&receipt.semantic_root),
                human_view_digest: hash_hex(&receipt.view_root),
            },
        })
        .map_err(|error| error.to_string()),
        AppArm::PatchJson => serde_json::to_vec(&PatchResponse {
            next_revision: receipt.revision,
            patches: changes
                .iter()
                .map(|change| (change.task_id, change.status, change.priority))
                .collect(),
            receipt: (
                hash_hex(&receipt.semantic_root),
                hash_hex(&receipt.view_root),
            ),
        })
        .map_err(|error| error.to_string()),
        AppArm::NdabiWire => {
            let mut bytes = Vec::with_capacity(80 + changes.len() * 6);
            bytes.extend_from_slice(APP_RESPONSE_MAGIC);
            bytes.push(APP_VERSION);
            bytes.push(0);
            push_u64(&mut bytes, receipt.revision);
            bytes.extend_from_slice(&receipt.semantic_root);
            bytes.extend_from_slice(&receipt.view_root);
            bytes.push(
                u8::try_from(changes.len())
                    .map_err(|_| "application patch count exceeds frame limit".to_string())?,
            );
            for change in changes {
                push_u32(&mut bytes, change.task_id);
                bytes.push(change.status);
                bytes.push(change.priority);
            }
            append_crc32(&mut bytes);
            Ok(bytes)
        }
        AppArm::NdabiLocal => Ok(Vec::new()),
    }
}

fn decode_response(
    arm: AppArm,
    bytes: &[u8],
) -> Result<(Vec<AppChange>, AppReceipt, Option<AppState>), String> {
    match arm {
        AppArm::FullJson => {
            let response: FullResponse =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            let receipt = AppReceipt {
                revision: response.receipt.revision,
                semantic_root: parse_hash(&response.receipt.semantic_digest)?,
                view_root: parse_hash(&response.receipt.human_view_digest)?,
            };
            Ok((Vec::new(), receipt, Some(response.state)))
        }
        AppArm::PatchJson => {
            let response: PatchResponse =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            Ok((
                response
                    .patches
                    .into_iter()
                    .map(|patch| AppChange {
                        task_id: patch.0,
                        status: patch.1,
                        priority: patch.2,
                    })
                    .collect(),
                AppReceipt {
                    revision: response.next_revision,
                    semantic_root: parse_hash(&response.receipt.0)?,
                    view_root: parse_hash(&response.receipt.1)?,
                },
                None,
            ))
        }
        AppArm::NdabiWire => {
            let body = verify_crc32(bytes)?;
            let mut reader = Reader::new(body);
            if reader.take(4)? != APP_RESPONSE_MAGIC {
                return Err("application response magic does not match".to_string());
            }
            if reader.u8()? != APP_VERSION || reader.u8()? != 0 {
                return Err("application response version or flags do not match".to_string());
            }
            let receipt = AppReceipt {
                revision: reader.u64()?,
                semantic_root: reader
                    .take(HASH_BYTES)?
                    .try_into()
                    .map_err(|_| "application semantic root has the wrong length".to_string())?,
                view_root: reader
                    .take(HASH_BYTES)?
                    .try_into()
                    .map_err(|_| "application view root has the wrong length".to_string())?,
            };
            let count = usize::from(reader.u8()?);
            let mut patches = Vec::with_capacity(count);
            for _ in 0..count {
                patches.push(AppChange {
                    task_id: reader.u32()?,
                    status: reader.u8()?,
                    priority: reader.u8()?,
                });
            }
            if reader.remaining() != 0 {
                return Err("application response has trailing bytes".to_string());
            }
            Ok((patches, receipt, None))
        }
        AppArm::NdabiLocal => Err("NDABI local has no wire response".to_string()),
    }
}

fn apply_to_clone(base: &AppState, changes: &[AppChange]) -> Result<AppState, String> {
    let mut state = base.clone();
    apply_in_place(&mut state, changes)?;
    state.revision = base.revision + 1;
    Ok(state)
}

fn apply_in_place(state: &mut AppState, changes: &[AppChange]) -> Result<(), String> {
    for change in changes {
        let index =
            usize::try_from(change.task_id - 1).map_err(|_| "task index overflow".to_string())?;
        let task = state
            .tasks
            .get_mut(index)
            .ok_or_else(|| "patch names an unknown task".to_string())?;
        task.status = change.status;
        task.priority = change.priority;
    }
    Ok(())
}

fn reset_client(
    base: &AppState,
    changes: &[AppChange],
    client: &mut AppState,
) -> Result<(), String> {
    client.revision = base.revision;
    for change in changes {
        let index =
            usize::try_from(change.task_id - 1).map_err(|_| "task index overflow".to_string())?;
        let source = base
            .tasks
            .get(index)
            .ok_or_else(|| "base task is absent".to_string())?;
        let destination = client
            .tasks
            .get_mut(index)
            .ok_or_else(|| "client task is absent".to_string())?;
        destination.status = source.status;
        destination.priority = source.priority;
    }
    Ok(())
}

fn state_retained_bytes(state: &AppState) -> usize {
    std::mem::size_of::<AppState>()
        + state.tasks.capacity() * std::mem::size_of::<Task>()
        + state
            .tasks
            .iter()
            .map(|task| task.title.capacity())
            .sum::<usize>()
}

fn render_full(state: &AppState) -> String {
    let mut output = format!("<main data-revision=\"{}\">\n", state.revision);
    for task in &state.tasks {
        render_task(&mut output, task);
    }
    output.push_str("</main>");
    output
}

fn render_patch(state: &AppState, changes: &[AppChange]) -> Result<String, String> {
    let mut output = String::new();
    render_patch_into(&mut output, state, changes)?;
    Ok(output)
}

fn render_patch_into(
    output: &mut String,
    state: &AppState,
    changes: &[AppChange],
) -> Result<usize, String> {
    output.clear();
    for change in changes {
        let index =
            usize::try_from(change.task_id - 1).map_err(|_| "task index overflow".to_string())?;
        let task = state
            .tasks
            .get(index)
            .ok_or_else(|| "render patch names an unknown task".to_string())?;
        render_task(output, task);
    }
    Ok(output.len())
}

fn render_task(output: &mut String, task: &Task) {
    use std::fmt::Write;
    let _ = writeln!(
        output,
        "  <article data-task=\"{}\"><h2>{}</h2><p>Status {}. Priority {}.</p></article>",
        task.id, task.title, task.status, task.priority
    );
}

fn disassemble_request(bytes: &[u8]) -> Result<String, String> {
    let command = decode_request(AppArm::NdabiWire, bytes)?;
    let changes = command
        .changes
        .iter()
        .map(|change| format!("{}:{}:{}", change.task_id, change.status, change.priority))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "v1 APPLY_PATCH principal={} purpose={} tenant={} snapshot={} max_changes={} deadline={} nonce={} expected_revision={} changes=[{}]",
        command.envelope.principal,
        command.envelope.purpose,
        command.envelope.tenant,
        command.envelope.snapshot,
        command.envelope.max_items,
        command.envelope.deadline,
        command.envelope.nonce,
        command.expected_revision,
        changes
    ))
}

fn refusal_suite(
    base: &AppState,
    changes: &[AppChange],
    receipt: AppReceipt,
) -> Result<(u32, u32), String> {
    let mut passed = 0;
    let mut total = 0;
    for arm in [AppArm::FullJson, AppArm::PatchJson, AppArm::NdabiWire] {
        let mut cases = Vec::new();

        let mut wrong_principal = Envelope::valid(16);
        wrong_principal.principal ^= 1;
        cases.push(encode_request(
            arm,
            wrong_principal,
            BASE_REVISION,
            changes,
        )?);

        cases.push(encode_request(
            arm,
            Envelope::valid(16),
            BASE_REVISION - 1,
            changes,
        )?);

        let mut excessive = changes.to_vec();
        while excessive.len() < 17 {
            excessive.push(excessive[0]);
        }
        cases.push(encode_request(
            arm,
            Envelope::valid(16),
            BASE_REVISION,
            &excessive,
        )?);

        cases.push(match arm {
            AppArm::NdabiWire => vec![0x4e, 0x44, 0x41],
            AppArm::NdabiLocal => unreachable!("local commands are tested separately"),
            _ => b"{".to_vec(),
        });

        for case in cases {
            total += 1;
            let mut client = base.clone();
            let before = client.clone();
            if process(arm, &case, base, &mut client, receipt).is_err() {
                if client != before {
                    return Err("a refused application request changed client state".to_string());
                }
                passed += 1;
            }
        }
    }
    let local_cases = [
        ({
            let mut envelope = Envelope::valid(16);
            envelope.principal ^= 1;
            (envelope, BASE_REVISION, changes)
        }),
        (Envelope::valid(16), BASE_REVISION - 1, changes),
    ];
    for (local_envelope, local_revision, local_changes) in local_cases {
        total += 1;
        let mut client = base.clone();
        let before = client.clone();
        if process_local(
            local_envelope,
            local_revision,
            local_changes,
            base,
            &mut client,
        )
        .is_err()
        {
            if client != before {
                return Err("a refused local application command changed state".to_string());
            }
            passed += 1;
        }
    }
    let mut excessive = changes.to_vec();
    while excessive.len() < 17 {
        excessive.push(excessive[0]);
    }
    total += 1;
    let mut client = base.clone();
    let before = client.clone();
    if process_local(
        Envelope::valid(16),
        BASE_REVISION,
        &excessive,
        base,
        &mut client,
    )
    .is_err()
    {
        if client != before {
            return Err("a refused local application command changed state".to_string());
        }
        passed += 1;
    }
    Ok((passed, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_application_arms_produce_the_same_human_view() {
        let evidence = run(1_024, 40, 2).expect("application benchmark");
        assert!(evidence.semantic_results_equal);
        assert!(evidence.human_views_equal);
        assert!(evidence.trusted_envelopes_equal);
        assert!(evidence.receipts_verified);
        assert_eq!(evidence.refusals_passed, evidence.refusals_total);
    }

    #[test]
    fn binary_application_request_round_trips() {
        let changes = fixed_changes(128).expect("changes");
        let envelope = Envelope::valid(16);
        let encoded =
            encode_request(AppArm::NdabiWire, envelope, BASE_REVISION, &changes).expect("encode");
        let decoded = decode_request(AppArm::NdabiWire, &encoded).expect("decode");
        assert_eq!(decoded.envelope, envelope);
        assert_eq!(decoded.expected_revision, BASE_REVISION);
        assert_eq!(decoded.changes, changes);
    }

    #[test]
    fn tuned_application_fast_path_preserves_the_json_contract() {
        let base = fixture(128).expect("base state");
        let changes = fixed_changes(128).expect("changes");
        let expected = apply_to_clone(&base, &changes).expect("expected state");
        let receipt = ReceiptTree::new(expected.revision, &expected.tasks)
            .expect("receipt tree")
            .receipt();
        let expected_bytes =
            encode_response(AppArm::PatchJson, &base, &changes, receipt).expect("reference encode");
        let mut fast_bytes = Vec::new();
        encode_tuned_response_into(&mut fast_bytes, &changes, receipt).expect("fast encode");
        assert_eq!(fast_bytes, expected_bytes);

        let mut client = base.clone();
        let mut receipt_tree =
            ReceiptTree::new(base.revision, &base.tasks).expect("base receipt tree");
        let mut rendered = String::new();
        let decoded = apply_tuned_response(
            &fast_bytes,
            &base,
            &mut client,
            &mut receipt_tree,
            &mut rendered,
        )
        .expect("fast response");
        assert_eq!(decoded.0, receipt);
        assert_eq!(client, expected);
    }

    #[test]
    fn tuned_application_receipt_refuses_before_state_change() {
        let base = fixture(128).expect("base state");
        let changes = fixed_changes(128).expect("changes");
        let expected = apply_to_clone(&base, &changes).expect("expected state");
        let valid_receipt = ReceiptTree::new(expected.revision, &expected.tasks)
            .expect("receipt tree")
            .receipt();
        let mut wrong_semantic = valid_receipt;
        wrong_semantic.semantic_root[0] ^= 1;
        let mut wrong_view = valid_receipt;
        wrong_view.view_root[0] ^= 1;
        for (receipt, message) in [
            (
                wrong_semantic,
                "application response semantic digest does not match",
            ),
            (
                wrong_view,
                "application response view digest does not match",
            ),
        ] {
            let mut response = Vec::new();
            encode_tuned_response_into(&mut response, &changes, receipt).expect("encode");
            let mut client = base.clone();
            let before = client.clone();
            let mut receipt_tree =
                ReceiptTree::new(base.revision, &base.tasks).expect("base receipt tree");
            let tree_before = receipt_tree.receipt();
            let mut rendered = String::new();
            assert_eq!(
                apply_tuned_response(
                    &response,
                    &base,
                    &mut client,
                    &mut receipt_tree,
                    &mut rendered,
                )
                .expect_err("wrong receipt must refuse"),
                message
            );
            assert_eq!(client, before);
            assert_eq!(receipt_tree.receipt(), tree_before);
        }
    }
}
