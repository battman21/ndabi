use mongodb::bson::{doc, spec::BinarySubtype, Binary};
use mongodb::sync::Client as MongoClient;
use ndabi_mongodb::{operation, MongoBackend, MongoItem, ROW_BYTES};
use ndabi_session::{Authority, ClientSession, RawOperation, ServerSession, FRAME_BYTES};
use ndabi_showdown::measure::{finish_arm, measure_batch, ArmBatch, ArmMeasurement, Observation};
use ndabi_showdown::wire::Digest64;
use serde::{Deserialize, Serialize};

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;
const MAXIMUM_RESULT_BYTES: u32 = 256;
const ITERATIONS: usize = 10_000;
const WARMUP: usize = 1_000;
const BLOCKS: usize = 20;
const SCHEDULE: [[Arm; 3]; 3] = [
    [Arm::Native, Arm::Json, Arm::Ndabi],
    [Arm::Json, Arm::Ndabi, Arm::Native],
    [Arm::Ndabi, Arm::Native, Arm::Json],
];

#[global_allocator]
static GLOBAL: ndabi_showdown::alloc::CountingAllocator = ndabi_showdown::alloc::CountingAllocator;

#[derive(Clone, Copy)]
enum Arm {
    Native,
    Json,
    Ndabi,
}

impl Arm {
    fn index(self) -> usize {
        match self {
            Self::Native => 0,
            Self::Json => 1,
            Self::Ndabi => 2,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct NamedRequest {
    protocol_version: u8,
    operation: String,
    authority_generation: u64,
    session_handle: u32,
    capability_handle: u32,
    schema_handle: u32,
    plan_handle: u32,
    deadline_unix_microseconds: u64,
    result_budget_bytes: u32,
    identifier: i64,
    response_mode: String,
}

impl NamedRequest {
    fn for_id(id: i64) -> Self {
        Self {
            protocol_version: 1,
            operation: "find_by_identifier".to_string(),
            authority_generation: 1,
            session_handle: 47,
            capability_handle: 10,
            schema_handle: 11,
            plan_handle: 12,
            deadline_unix_microseconds: DEADLINE,
            result_budget_bytes: MAXIMUM_RESULT_BYTES,
            identifier: id,
            response_mode: "canonical_binary_row_and_receipt".to_string(),
        }
    }

    fn decode_operation(self) -> Result<RawOperation, String> {
        let expected = Self::for_id(self.identifier);
        if self.protocol_version != expected.protocol_version
            || self.operation != expected.operation
            || self.authority_generation != expected.authority_generation
            || self.session_handle != expected.session_handle
            || self.capability_handle != expected.capability_handle
            || self.schema_handle != expected.schema_handle
            || self.plan_handle != expected.plan_handle
            || self.deadline_unix_microseconds != expected.deadline_unix_microseconds
            || self.result_budget_bytes != expected.result_budget_bytes
            || self.response_mode != expected.response_mode
        {
            return Err("the MongoDB JSON request is not authorised".to_string());
        }
        operation(self.identifier).map_err(|error| error.to_string())
    }
}

struct NativeState {
    backend: MongoBackend,
    sequence: u64,
}

impl NativeState {
    fn observe(&mut self) -> Result<Observation, String> {
        let id = next_id(&mut self.sequence);
        let bytes = self
            .backend
            .find_by_id(id)
            .map_err(|error| error.to_string())?;
        observe(&bytes)
    }
}

struct JsonState {
    backend: MongoBackend,
    client: ClientSession,
    server: ServerSession,
    request: Vec<u8>,
    sequence: u64,
}

impl JsonState {
    fn observe(&mut self) -> Result<Observation, String> {
        let id = next_id(&mut self.sequence);
        self.request.clear();
        serde_json::to_writer(&mut self.request, &NamedRequest::for_id(id))
            .map_err(|error| error.to_string())?;
        let request: NamedRequest =
            serde_json::from_slice(&self.request).map_err(|error| error.to_string())?;
        let frame = self
            .client
            .encode(request.decode_operation()?, MAXIMUM_RESULT_BYTES, DEADLINE)
            .map_err(|error| error.to_string())?;
        let result = self
            .server
            .execute(&frame, NOW, &mut self.backend)
            .map_err(|error| error.to_string())?;
        observe(&result.bytes)
    }
}

struct NdabiState {
    backend: MongoBackend,
    client: ClientSession,
    server: ServerSession,
    sequence: u64,
}

impl NdabiState {
    fn observe(&mut self) -> Result<Observation, String> {
        let id = next_id(&mut self.sequence);
        let frame = self
            .client
            .encode(
                operation(id).map_err(|error| error.to_string())?,
                MAXIMUM_RESULT_BYTES,
                DEADLINE,
            )
            .map_err(|error| error.to_string())?;
        let result = self
            .server
            .execute(&frame, NOW, &mut self.backend)
            .map_err(|error| error.to_string())?;
        observe(&result.bytes)
    }
}

#[derive(Serialize)]
struct Report {
    campaign: &'static str,
    dataset_rows: usize,
    arms: Vec<ArmMeasurement>,
    request_compression: f64,
    ndabi_native_p95_ratio: f64,
    ndabi_json_p95_ratio: f64,
    refusals: String,
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
        "run" => run(&uri),
        _ => Err("the command is unknown".to_string()),
    }
}

fn prepare(uri: &str) -> Result<(), String> {
    let client = MongoClient::with_uri_str(uri).map_err(|error| error.to_string())?;
    let database = client.database("ndabi");
    database.drop().run().map_err(|error| error.to_string())?;
    let collection = database.collection::<MongoItem>("items");
    for start in (0..100_000).step_by(1_000) {
        let items = (start..start + 1_000)
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
    if collection
        .estimated_document_count()
        .run()
        .map_err(|error| error.to_string())?
        != 100_000
    {
        return Err("the MongoDB dataset count is invalid".to_string());
    }
    Ok(())
}

fn run(uri: &str) -> Result<(), String> {
    let native_backend = connect(uri)?;
    let json_backend = connect(uri)?;
    let ndabi_backend = connect(uri)?;
    let json_authority = authority(47)?;
    let ndabi_authority = authority(48)?;
    let mut native = NativeState {
        backend: native_backend,
        sequence: 0,
    };
    let mut json = JsonState {
        backend: json_backend,
        client: ClientSession::new(json_authority.clone()),
        server: ServerSession::new(json_authority, MAXIMUM_RESULT_BYTES)
            .map_err(|error| error.to_string())?,
        request: Vec::with_capacity(512),
        sequence: 0,
    };
    let mut ndabi = NdabiState {
        backend: ndabi_backend,
        client: ClientSession::new(ndabi_authority.clone()),
        server: ServerSession::new(ndabi_authority, MAXIMUM_RESULT_BYTES)
            .map_err(|error| error.to_string())?,
        sequence: 0,
    };
    let expected = connect(uri)?
        .find_by_id(0)
        .map_err(|error| error.to_string())?;
    let native_identity = native.observe()?;
    let json_identity = json.observe()?;
    let ndabi_identity = ndabi.observe()?;
    if expected.len() != ROW_BYTES
        || native_identity.semantic_digest != json_identity.semantic_digest
        || json_identity.semantic_digest != ndabi_identity.semantic_digest
    {
        return Err("the MongoDB arm results differ".to_string());
    }
    let refusal_count = refusals(uri)?;
    let json_bytes = serde_json::to_vec(&NamedRequest::for_id(99_999))
        .map_err(|error| error.to_string())?
        .len();
    let request_compression = 1.0 - FRAME_BYTES as f64 / json_bytes as f64;
    let mut batches: [Vec<ArmBatch>; 3] = std::array::from_fn(|_| Vec::new());
    for block in 0..BLOCKS {
        for arm in SCHEDULE[block % SCHEDULE.len()] {
            let batch = match arm {
                Arm::Native => {
                    measure_batch(ITERATIONS / BLOCKS, WARMUP / BLOCKS, || native.observe())
                }
                Arm::Json => measure_batch(ITERATIONS / BLOCKS, WARMUP / BLOCKS, || json.observe()),
                Arm::Ndabi => {
                    measure_batch(ITERATIONS / BLOCKS, WARMUP / BLOCKS, || ndabi.observe())
                }
            }?;
            batches[arm.index()].push(batch);
        }
    }
    let arms = vec![
        finish_arm(
            "native",
            "native typed MongoDB",
            0,
            0,
            true,
            std::mem::take(&mut batches[0]),
        )?,
        finish_arm(
            "json",
            "equal-security MongoDB JSON gateway",
            json_bytes,
            json.request.capacity(),
            true,
            std::mem::take(&mut batches[1]),
        )?,
        finish_arm(
            "ndabi",
            "shared-session NDABI MongoDB",
            FRAME_BYTES,
            FRAME_BYTES,
            true,
            std::mem::take(&mut batches[2]),
        )?,
    ];
    let native_ratio = arms[2].p95_ns as f64 / arms[0].p95_ns as f64;
    let json_ratio = arms[2].p95_ns as f64 / arms[1].p95_ns as f64;
    let passed = refusal_count == 6
        && request_compression >= 0.50
        && native_ratio <= 1.10
        && json_ratio <= 1.10;
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            campaign: "NDABI MongoDB point profile v4.7",
            dataset_rows: 100_000,
            arms,
            request_compression,
            ndabi_native_p95_ratio: native_ratio,
            ndabi_json_p95_ratio: json_ratio,
            refusals: format!("{refusal_count}/6"),
            passed,
        })
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn refusals(uri: &str) -> Result<u32, String> {
    let mut passed = 0;
    let valid = operation(1).map_err(|error| error.to_string())?;
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
            let mut backend = connect(uri)?;
            let first = server.execute(&frame, now, &mut backend);
            if replay && first.is_ok() {
                Ok(server.execute(&frame, now, &mut backend).is_err())
            } else {
                Ok(first.is_err())
            }
        };
    passed += u32::from(execute(501, valid, 256, NOW, true, false)?);
    passed += u32::from(execute(502, valid, 256, NOW, false, true)?);
    let mut client = ClientSession::new(authority(503)?);
    let frame = client
        .encode(valid, 256, 1_500_000)
        .map_err(|error| error.to_string())?;
    let mut wrong = ServerSession::new(authority(504)?, 256).map_err(|error| error.to_string())?;
    passed += u32::from(wrong.execute(&frame, NOW, &mut connect(uri)?).is_err());
    passed += u32::from(execute(505, valid, 256, 1_500_000, false, false)?);
    passed += u32::from(execute(506, valid, 257, NOW, false, false)?);
    let unsupported = RawOperation::new(0x22, 1, 0, 0).map_err(|error| error.to_string())?;
    passed += u32::from(execute(507, unsupported, 256, NOW, false, false)?);
    Ok(passed)
}

fn authority(session: u32) -> Result<Authority, String> {
    Authority::new([47; 32], 1, session, DEADLINE, 10, 11, 12).map_err(|error| error.to_string())
}

fn connect(uri: &str) -> Result<MongoBackend, String> {
    MongoBackend::connect(uri).map_err(|error| error.to_string())
}

fn next_id(sequence: &mut u64) -> i64 {
    *sequence += 1;
    4_242
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
