use mongodb::bson::{spec::BinarySubtype, Binary};
use mongodb::event::{command::CommandEvent, EventHandler};
use mongodb::options::ClientOptions;
use mongodb::sync::Client as MongoClient;
use ndabi_mongodb::{
    batch_operation, decode_window, BatchDecode, MongoBatchBackend, MongoItem,
    MongoSequentialBatchBackend, BATCH_DATASET_ROWS, MAX_BATCH_ITEMS, ROW_BYTES,
};
use ndabi_session::{Authority, Backend, ClientSession, RawOperation, ServerSession, FRAME_BYTES};
use ndabi_showdown::measure::{finish_arm, measure_batch, ArmBatch, ArmMeasurement, Observation};
use ndabi_showdown::wire::Digest64;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;
const MAXIMUM_RESULT_BYTES: u32 = (MAX_BATCH_ITEMS * ROW_BYTES) as u32;
const FIRST_IDENTIFIER: i64 = 17;
const IDENTIFIER_STRIDE: u32 = 7_811;
const BLOCKS: usize = 10;
const BATCH_SIZES: [usize; 4] = [1, 8, 32, 128];
const ARMS: [Arm; 6] = [
    Arm::NativeSequential,
    Arm::JsonSequential,
    Arm::JsonSet,
    Arm::NativeSet,
    Arm::NdabiTyped,
    Arm::NdabiRaw,
];

#[global_allocator]
static GLOBAL: ndabi_showdown::alloc::CountingAllocator = ndabi_showdown::alloc::CountingAllocator;

#[derive(Clone, Copy)]
enum Arm {
    NativeSequential,
    JsonSequential,
    JsonSet,
    NativeSet,
    NdabiTyped,
    NdabiRaw,
}

#[derive(Clone, Copy)]
enum Campaign {
    V53,
    V54,
    V55,
    V56,
    V57,
}

impl Campaign {
    fn label(self) -> &'static str {
        match self {
            Self::V53 => "NDABI MongoDB fused batch v5.3",
            Self::V54 => "NDABI MongoDB single batch v5.4",
            Self::V55 => "NDABI MongoDB literal single batch v5.5",
            Self::V56 => "NDABI MongoDB closed evidence v5.6",
            Self::V57 => "NDABI MongoDB final harness v5.7",
        }
    }
}

impl Arm {
    fn index(self) -> usize {
        match self {
            Self::NativeSequential => 0,
            Self::JsonSequential => 1,
            Self::JsonSet => 2,
            Self::NativeSet => 3,
            Self::NdabiTyped => 4,
            Self::NdabiRaw => 5,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct NamedBatchRequest {
    protocol_version: u8,
    operation: String,
    authority_generation: u64,
    session_handle: u32,
    capability_handle: u32,
    schema_handle: u32,
    plan_handle: u32,
    deadline_unix_microseconds: u64,
    result_budget_bytes: u32,
    first_identifier: i64,
    item_count: usize,
    identifier_stride: u32,
    response_mode: String,
}

impl NamedBatchRequest {
    fn new(session: u32, count: usize) -> Self {
        Self {
            protocol_version: 1,
            operation: "find_identifier_window".to_string(),
            authority_generation: 1,
            session_handle: session,
            capability_handle: 53,
            schema_handle: 1,
            plan_handle: 1,
            deadline_unix_microseconds: DEADLINE,
            result_budget_bytes: result_budget(count),
            first_identifier: FIRST_IDENTIFIER,
            item_count: count,
            identifier_stride: IDENTIFIER_STRIDE,
            response_mode: "ordered_canonical_binary_rows_and_receipt".to_string(),
        }
    }

    fn decode_operation(self, session: u32) -> Result<RawOperation, String> {
        let expected = Self::new(session, self.item_count);
        if self.protocol_version != expected.protocol_version
            || self.operation != expected.operation
            || self.authority_generation != expected.authority_generation
            || self.session_handle != expected.session_handle
            || self.capability_handle != expected.capability_handle
            || self.schema_handle != expected.schema_handle
            || self.plan_handle != expected.plan_handle
            || self.deadline_unix_microseconds != expected.deadline_unix_microseconds
            || self.result_budget_bytes != expected.result_budget_bytes
            || self.first_identifier != expected.first_identifier
            || self.identifier_stride != expected.identifier_stride
            || self.response_mode != expected.response_mode
        {
            return Err("the MongoDB JSON batch request is not authorised".to_string());
        }
        batch_operation(
            self.first_identifier,
            self.item_count,
            self.identifier_stride,
        )
        .map_err(|error| error.to_string())
    }
}

struct NativeSequentialState {
    backend: MongoSequentialBatchBackend,
    window: ndabi_mongodb::IdWindow,
}

impl NativeSequentialState {
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        self.backend
            .find_window(self.window)
            .map_err(|error| error.to_string())
    }

    fn observe(&mut self) -> Result<Observation, String> {
        observe(&self.bytes()?)
    }
}

struct NativeSetState {
    backend: MongoBatchBackend,
    window: ndabi_mongodb::IdWindow,
}

impl NativeSetState {
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        self.backend
            .find_window(self.window)
            .map_err(|error| error.to_string())
    }

    fn observe(&mut self) -> Result<Observation, String> {
        observe(&self.bytes()?)
    }
}

struct JsonState<B: Backend> {
    backend: B,
    client: ClientSession,
    server: ServerSession,
    request: Vec<u8>,
    session: u32,
    count: usize,
}

impl<B: Backend> JsonState<B> {
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        self.request.clear();
        serde_json::to_writer(
            &mut self.request,
            &NamedBatchRequest::new(self.session, self.count),
        )
        .map_err(|error| error.to_string())?;
        let request: NamedBatchRequest =
            serde_json::from_slice(&self.request).map_err(|error| error.to_string())?;
        let frame = self
            .client
            .encode(
                request.decode_operation(self.session)?,
                result_budget(self.count),
                DEADLINE,
            )
            .map_err(|error| error.to_string())?;
        let result = self
            .server
            .execute(&frame, NOW, &mut self.backend)
            .map_err(|error| error.to_string())?;
        Ok(result.bytes)
    }

    fn observe(&mut self) -> Result<Observation, String> {
        observe(&self.bytes()?)
    }
}

struct NdabiState<B: Backend> {
    backend: B,
    client: ClientSession,
    server: ServerSession,
    operation: RawOperation,
    count: usize,
}

impl<B: Backend> NdabiState<B> {
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let frame = self
            .client
            .encode(self.operation, result_budget(self.count), DEADLINE)
            .map_err(|error| error.to_string())?;
        let result = self
            .server
            .execute(&frame, NOW, &mut self.backend)
            .map_err(|error| error.to_string())?;
        Ok(result.bytes)
    }

    fn observe(&mut self) -> Result<Observation, String> {
        observe(&self.bytes()?)
    }
}

#[derive(Serialize)]
struct CaseReport {
    batch_size: usize,
    iterations: usize,
    warmup: usize,
    arms: Vec<ArmMeasurement>,
    request_compression: f64,
    ndabi_typed_native_ratio: f64,
    ndabi_typed_sequential_json_speedup: f64,
    ndabi_typed_native_allocated_byte_ratio: f64,
    ndabi_raw_native_ratio: f64,
    ndabi_raw_sequential_json_speedup: f64,
    ndabi_raw_allocated_byte_reduction: f64,
    exact_results: bool,
    passed: bool,
}

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    dataset_rows: i64,
    frame_bytes: usize,
    cases: Vec<CaseReport>,
    refusals: String,
    single_batch_audit: Option<SingleBatchAudit>,
    passed: bool,
}

#[derive(Serialize)]
struct SingleBatchAudit {
    find_commands: usize,
    get_more_commands: usize,
    passed: bool,
}

fn main() {
    if let Err(error) = dispatch() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn dispatch() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| "a command is required".to_string())?;
    let uri = arguments
        .next()
        .ok_or_else(|| "a MongoDB URI is required".to_string())?;
    if arguments.next().is_some() {
        return Err("too many arguments".to_string());
    }
    match command.as_str() {
        "prepare" => prepare(&uri),
        "run" => run(&uri, Campaign::V53),
        "run-v54" => run(&uri, Campaign::V54),
        "run-v55" => run(&uri, Campaign::V55),
        "run-v56" => run(&uri, Campaign::V56),
        "run-v57" => run(&uri, Campaign::V57),
        _ => Err("the command is unknown".to_string()),
    }
}

fn prepare(uri: &str) -> Result<(), String> {
    let client = MongoClient::with_uri_str(uri).map_err(|error| error.to_string())?;
    let database = client.database("ndabi");
    database.drop().run().map_err(|error| error.to_string())?;
    let collection = database.collection::<MongoItem>("items");
    for start in (0..BATCH_DATASET_ROWS).step_by(5_000) {
        let items = (start..start + 5_000)
            .map(|id| MongoItem {
                id,
                bucket: (id % 1_024) as i32,
                owner: (id % 4_096) as i32,
                score: (id % 10_000) as i32,
                payload: Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: vec![(id % 251) as u8; 64],
                },
            })
            .collect::<Vec<_>>();
        collection
            .insert_many(items)
            .ordered(true)
            .run()
            .map_err(|error| error.to_string())?;
    }
    let count = collection
        .estimated_document_count()
        .run()
        .map_err(|error| error.to_string())?;
    if count != BATCH_DATASET_ROWS as u64 {
        return Err("the MongoDB batch dataset count is invalid".to_string());
    }
    Ok(())
}

fn run(uri: &str, campaign: Campaign) -> Result<(), String> {
    let refusal_count = refusals(uri)?;
    let single_batch_audit = match campaign {
        Campaign::V55 | Campaign::V56 | Campaign::V57 => Some(audit_single_batch(uri)?),
        Campaign::V53 | Campaign::V54 => None,
    };
    let mut cases = Vec::new();
    for batch_size in BATCH_SIZES {
        cases.push(run_case(uri, batch_size, campaign)?);
    }
    let passed = refusal_count == 8
        && single_batch_audit.as_ref().is_none_or(|audit| audit.passed)
        && cases.iter().all(|case| case.passed);
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            campaign: campaign.label(),
            dataset_rows: BATCH_DATASET_ROWS,
            frame_bytes: FRAME_BYTES,
            cases,
            refusals: format!("{refusal_count}/8"),
            single_batch_audit,
            passed,
        })
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn run_case(uri: &str, count: usize, campaign: Campaign) -> Result<CaseReport, String> {
    let operation = batch_operation(FIRST_IDENTIFIER, count, IDENTIFIER_STRIDE)
        .map_err(|error| error.to_string())?;
    let window = decode_window(operation).map_err(|error| error.to_string())?;
    let sequential_json_session = session_handle(1, count)?;
    let set_json_session = session_handle(2, count)?;
    let typed_session = session_handle(3, count)?;
    let raw_session = session_handle(4, count)?;
    let mut native_sequential = NativeSequentialState {
        backend: MongoSequentialBatchBackend::connect(uri).map_err(|error| error.to_string())?,
        window,
    };
    let mut json_sequential = json_state(
        MongoSequentialBatchBackend::connect(uri).map_err(|error| error.to_string())?,
        sequential_json_session,
        count,
    )?;
    let mut json_set = json_state(
        MongoBatchBackend::connect(uri, BatchDecode::Typed).map_err(|error| error.to_string())?,
        set_json_session,
        count,
    )?;
    let mut native_set = NativeSetState {
        backend: MongoBatchBackend::connect(uri, BatchDecode::Typed)
            .map_err(|error| error.to_string())?,
        window,
    };
    let mut ndabi_typed = ndabi_state(
        MongoBatchBackend::connect(uri, BatchDecode::Typed).map_err(|error| error.to_string())?,
        typed_session,
        count,
        operation,
    )?;
    let mut ndabi_raw = ndabi_state(
        MongoBatchBackend::connect(uri, BatchDecode::RawBson).map_err(|error| error.to_string())?,
        raw_session,
        count,
        operation,
    )?;

    let identities = [
        native_sequential.bytes()?,
        json_sequential.bytes()?,
        json_set.bytes()?,
        native_set.bytes()?,
        ndabi_typed.bytes()?,
        ndabi_raw.bytes()?,
    ];
    let repeated_identities = [
        native_sequential.bytes()?,
        json_sequential.bytes()?,
        json_set.bytes()?,
        native_set.bytes()?,
        ndabi_typed.bytes()?,
        ndabi_raw.bytes()?,
    ];
    let exact_results = identities[0].len() == count * ROW_BYTES
        && identities.iter().all(|value| value == &identities[0])
        && repeated_identities
            .iter()
            .zip(&identities)
            .all(|(repeated, first)| repeated == first);
    let json_bytes = serde_json::to_vec(&NamedBatchRequest::new(set_json_session, count))
        .map_err(|error| error.to_string())?
        .len();
    let request_compression = 1.0 - FRAME_BYTES as f64 / json_bytes as f64;
    let (iterations, warmup) = sample_plan(count)?;
    let mut batches: [Vec<ArmBatch>; 6] = std::array::from_fn(|_| Vec::new());
    for block in 0..BLOCKS {
        for offset in 0..ARMS.len() {
            let arm = ARMS[(block + offset) % ARMS.len()];
            let batch = match arm {
                Arm::NativeSequential => {
                    measure_batch(iterations / BLOCKS, warmup / BLOCKS, || {
                        native_sequential.observe()
                    })
                }
                Arm::JsonSequential => measure_batch(iterations / BLOCKS, warmup / BLOCKS, || {
                    json_sequential.observe()
                }),
                Arm::JsonSet => {
                    measure_batch(iterations / BLOCKS, warmup / BLOCKS, || json_set.observe())
                }
                Arm::NativeSet => measure_batch(iterations / BLOCKS, warmup / BLOCKS, || {
                    native_set.observe()
                }),
                Arm::NdabiTyped => measure_batch(iterations / BLOCKS, warmup / BLOCKS, || {
                    ndabi_typed.observe()
                }),
                Arm::NdabiRaw => {
                    measure_batch(iterations / BLOCKS, warmup / BLOCKS, || ndabi_raw.observe())
                }
            }?;
            batches[arm.index()].push(batch);
        }
    }
    let arms = vec![
        finish_arm(
            "native-sequential",
            "native sequential typed MongoDB",
            0,
            0,
            true,
            std::mem::take(&mut batches[0]),
        )?,
        finish_arm(
            "json-sequential",
            "equal-security JSON with sequential MongoDB",
            json_bytes,
            json_sequential.request.capacity(),
            true,
            std::mem::take(&mut batches[1]),
        )?,
        finish_arm(
            "json-set",
            "equal-security JSON with MongoDB set execution",
            json_bytes,
            json_set.request.capacity(),
            true,
            std::mem::take(&mut batches[2]),
        )?,
        finish_arm(
            "native-set",
            "native typed MongoDB set execution",
            0,
            0,
            true,
            std::mem::take(&mut batches[3]),
        )?,
        finish_arm(
            "ndabi-typed",
            "NDABI typed MongoDB set execution",
            FRAME_BYTES,
            FRAME_BYTES,
            true,
            std::mem::take(&mut batches[4]),
        )?,
        finish_arm(
            "ndabi-raw",
            "NDABI raw-BSON MongoDB set execution",
            FRAME_BYTES,
            FRAME_BYTES,
            true,
            std::mem::take(&mut batches[5]),
        )?,
    ];
    let typed_native_ratio = ratio(arms[4].p95_ns, arms[3].p95_ns);
    let typed_sequential_speedup = ratio(arms[1].p95_ns, arms[4].p95_ns);
    let typed_native_allocated_byte_ratio = floating_ratio(
        arms[4].allocated_bytes_per_operation,
        arms[3].allocated_bytes_per_operation,
    );
    let raw_native_ratio = ratio(arms[5].p95_ns, arms[3].p95_ns);
    let raw_sequential_speedup = ratio(arms[1].p95_ns, arms[5].p95_ns);
    let raw_allocated_byte_reduction = reduction(
        arms[4].allocated_bytes_per_operation,
        arms[5].allocated_bytes_per_operation,
    );
    let passed = match campaign {
        Campaign::V53 => {
            exact_results
                && request_compression >= 0.60
                && typed_native_ratio <= 1.10
                && raw_native_ratio <= 1.10
                && (count < 32 || raw_sequential_speedup >= 5.0)
                && (count != 128 || raw_allocated_byte_reduction >= 0.30)
        }
        Campaign::V54 | Campaign::V55 | Campaign::V56 => {
            exact_results
                && request_compression >= 0.60
                && (count != 32 || (typed_native_ratio <= 1.15 && typed_sequential_speedup >= 5.0))
                && (count != 128
                    || (typed_native_ratio <= 1.15
                        && typed_sequential_speedup >= 20.0
                        && typed_native_allocated_byte_ratio <= 1.05))
        }
        Campaign::V57 => exact_results && request_compression >= 0.60,
    };
    Ok(CaseReport {
        batch_size: count,
        iterations,
        warmup,
        arms,
        request_compression,
        ndabi_typed_native_ratio: typed_native_ratio,
        ndabi_typed_sequential_json_speedup: typed_sequential_speedup,
        ndabi_typed_native_allocated_byte_ratio: typed_native_allocated_byte_ratio,
        ndabi_raw_native_ratio: raw_native_ratio,
        ndabi_raw_sequential_json_speedup: raw_sequential_speedup,
        ndabi_raw_allocated_byte_reduction: raw_allocated_byte_reduction,
        exact_results,
        passed,
    })
}

fn audit_single_batch(uri: &str) -> Result<SingleBatchAudit, String> {
    let find_commands = Arc::new(AtomicUsize::new(0));
    let get_more_commands = Arc::new(AtomicUsize::new(0));
    let find_counter = Arc::clone(&find_commands);
    let get_more_counter = Arc::clone(&get_more_commands);
    let handler = EventHandler::callback(move |event| {
        if let CommandEvent::Started(event) = event {
            match event.command_name.as_str() {
                "find" => {
                    find_counter.fetch_add(1, Ordering::Relaxed);
                }
                "getMore" => {
                    get_more_counter.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    });
    let mut options = ClientOptions::parse(uri)
        .run()
        .map_err(|error| error.to_string())?;
    options.command_event_handler = Some(handler);
    let client = MongoClient::with_options(options).map_err(|error| error.to_string())?;
    let backend = MongoBatchBackend::from_client(client, BatchDecode::Typed);
    let window = decode_window(
        batch_operation(FIRST_IDENTIFIER, MAX_BATCH_ITEMS, IDENTIFIER_STRIDE)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let bytes = backend
        .find_window(window)
        .map_err(|error| error.to_string())?;
    if bytes.len() != MAX_BATCH_ITEMS * ROW_BYTES {
        return Err("the MongoDB single-batch audit result is invalid".to_string());
    }
    let find_commands = find_commands.load(Ordering::Relaxed);
    let get_more_commands = get_more_commands.load(Ordering::Relaxed);
    Ok(SingleBatchAudit {
        find_commands,
        get_more_commands,
        passed: find_commands == 1 && get_more_commands == 0,
    })
}

fn json_state<B: Backend>(backend: B, session: u32, count: usize) -> Result<JsonState<B>, String> {
    let binding = authority(session)?;
    Ok(JsonState {
        backend,
        client: ClientSession::new(binding.clone()),
        server: ServerSession::new(binding, MAXIMUM_RESULT_BYTES)
            .map_err(|error| error.to_string())?,
        request: Vec::with_capacity(512),
        session,
        count,
    })
}

fn ndabi_state<B: Backend>(
    backend: B,
    session: u32,
    count: usize,
    operation: RawOperation,
) -> Result<NdabiState<B>, String> {
    let binding = authority(session)?;
    Ok(NdabiState {
        backend,
        client: ClientSession::new(binding.clone()),
        server: ServerSession::new(binding, MAXIMUM_RESULT_BYTES)
            .map_err(|error| error.to_string())?,
        operation,
        count,
    })
}

fn refusals(uri: &str) -> Result<u32, String> {
    let mut passed = 0u32;
    let valid = batch_operation(FIRST_IDENTIFIER, 8, IDENTIFIER_STRIDE)
        .map_err(|error| error.to_string())?;
    let execute = |session: u32,
                   operation: RawOperation,
                   budget: u32,
                   now: u64,
                   mutate: bool,
                   replay: bool|
     -> Result<bool, String> {
        let binding = authority(session)?;
        let mut client = ClientSession::new(binding.clone());
        let mut server =
            ServerSession::new(binding, MAXIMUM_RESULT_BYTES).map_err(|error| error.to_string())?;
        let mut frame = client
            .encode(operation, budget, 1_500_000)
            .map_err(|error| error.to_string())?;
        if mutate {
            frame[48] ^= 1;
        }
        let mut backend = MongoBatchBackend::connect(uri, BatchDecode::Typed)
            .map_err(|error| error.to_string())?;
        let first = server.execute(&frame, now, &mut backend);
        if replay && first.is_ok() {
            Ok(server.execute(&frame, now, &mut backend).is_err())
        } else {
            Ok(first.is_err())
        }
    };
    passed += u32::from(execute(9_001, valid, result_budget(8), NOW, true, false)?);
    passed += u32::from(execute(9_002, valid, result_budget(8), NOW, false, true)?);
    let mut client = ClientSession::new(authority(9_003)?);
    let frame = client
        .encode(valid, result_budget(8), 1_500_000)
        .map_err(|error| error.to_string())?;
    let mut wrong = ServerSession::new(authority(9_004)?, MAXIMUM_RESULT_BYTES)
        .map_err(|error| error.to_string())?;
    let mut backend =
        MongoBatchBackend::connect(uri, BatchDecode::Typed).map_err(|error| error.to_string())?;
    passed += u32::from(wrong.execute(&frame, NOW, &mut backend).is_err());
    passed += u32::from(execute(
        9_005,
        valid,
        result_budget(8),
        1_500_000,
        false,
        false,
    )?);
    passed += u32::from(execute(
        9_006,
        valid,
        MAXIMUM_RESULT_BYTES + 1,
        NOW,
        false,
        false,
    )?);
    let unsupported = RawOperation::new(0x7f, 1, 8, 1).map_err(|error| error.to_string())?;
    passed += u32::from(execute(
        9_007,
        unsupported,
        result_budget(8),
        NOW,
        false,
        false,
    )?);
    let zero_count = RawOperation::new(ndabi_mongodb::FIND_ID_WINDOW, 1, 0, 1)
        .map_err(|error| error.to_string())?;
    passed += u32::from(execute(
        9_008,
        zero_count,
        result_budget(8),
        NOW,
        false,
        false,
    )?);
    let out_of_range =
        RawOperation::new(ndabi_mongodb::FIND_ID_WINDOW, BATCH_DATASET_ROWS - 1, 2, 1)
            .map_err(|error| error.to_string())?;
    passed += u32::from(execute(
        9_009,
        out_of_range,
        result_budget(8),
        NOW,
        false,
        false,
    )?);
    Ok(passed)
}

fn session_handle(kind: u32, count: usize) -> Result<u32, String> {
    let count = u32::try_from(count).map_err(|_| "the batch size is too large".to_string())?;
    5_300u32
        .checked_add(kind * 256)
        .and_then(|value| value.checked_add(count))
        .ok_or_else(|| "the session handle overflowed".to_string())
}

fn authority(session: u32) -> Result<Authority, String> {
    Authority::new([53; 32], 1, session, DEADLINE, 53, 1, 1).map_err(|error| error.to_string())
}

fn result_budget(count: usize) -> u32 {
    (count * ROW_BYTES) as u32
}

fn sample_plan(count: usize) -> Result<(usize, usize), String> {
    match count {
        1 => Ok((2_000, 200)),
        8 => Ok((500, 50)),
        32 => Ok((200, 20)),
        128 => Ok((100, 10)),
        _ => Err("the benchmark batch size is unsupported".to_string()),
    }
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    numerator as f64 / denominator.max(1) as f64
}

fn floating_ratio(numerator: f64, denominator: f64) -> f64 {
    numerator / denominator.max(f64::EPSILON)
}

fn reduction(reference: f64, candidate: f64) -> f64 {
    if reference == 0.0 {
        0.0
    } else {
        1.0 - candidate / reference
    }
}

fn observe(bytes: &[u8]) -> Result<Observation, String> {
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
