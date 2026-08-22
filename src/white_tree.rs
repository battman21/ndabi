use std::mem::size_of;

use ndabi_session::{Backend as SessionBackend, RawOperation, SessionError};
use olx_core::context::{AsOf, ContextPack, HandleSeeds, SeedSpec};
use olx_core::fixtures;
use olx_core::goal::ProfileKey;
use olx_core::model::{
    Bitemporal, EventId, EvidenceRef, Governance, Member, PartitionId, SensitivityClass,
    TrajectoryId,
};
use olx_core::scan::ScanReport;
use olx_core::store::ChunkStore;
use olx_core::store_ext::StoreExt;
use serde::{Deserialize, Serialize};

use crate::measure::{finish_arm, measure_batch, ArmBatch, ArmMeasurement, Observation};
use crate::wire::{
    append_crc32, hex, push_envelope, push_u16, push_u32, push_u64, validate_envelope,
    verify_crc32, Digest64, Envelope, Reader,
};

const REQUEST_MAGIC: &[u8; 4] = b"NDAW";
const RESPONSE_MAGIC: &[u8; 4] = b"NDAZ";
const VERSION: u8 = 1;
const EXECUTE_CONTEXT: u8 = 0x31;
const QUERY_HANDLE: u16 = 41;
const PREPARED_SNAPSHOT_HANDLE: i64 = 1;
const MEASUREMENT_CYCLES: usize = 10;
const BALANCED_SCHEDULE: [[WhiteTreeArm; 4]; 4] = [
    [
        WhiteTreeArm::ReadableJson,
        WhiteTreeArm::SemanticJson,
        WhiteTreeArm::NdabiWire,
        WhiteTreeArm::NdabiLocal,
    ],
    [
        WhiteTreeArm::SemanticJson,
        WhiteTreeArm::NdabiWire,
        WhiteTreeArm::NdabiLocal,
        WhiteTreeArm::ReadableJson,
    ],
    [
        WhiteTreeArm::NdabiWire,
        WhiteTreeArm::NdabiLocal,
        WhiteTreeArm::ReadableJson,
        WhiteTreeArm::SemanticJson,
    ],
    [
        WhiteTreeArm::NdabiLocal,
        WhiteTreeArm::ReadableJson,
        WhiteTreeArm::SemanticJson,
        WhiteTreeArm::NdabiWire,
    ],
];
const MEASUREMENT_BLOCKS_PER_ARM: usize = BALANCED_SCHEDULE.len() * MEASUREMENT_CYCLES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WhiteTreeArm {
    ReadableJson,
    SemanticJson,
    NdabiWire,
    NdabiLocal,
}

impl WhiteTreeArm {
    const ALL: [Self; 4] = [
        Self::ReadableJson,
        Self::SemanticJson,
        Self::NdabiWire,
        Self::NdabiLocal,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::ReadableJson => "human",
            Self::SemanticJson => "tuned",
            Self::NdabiWire => "wire",
            Self::NdabiLocal => "local",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ReadableJson => "Named JSON + governed context",
            Self::SemanticJson => "Semantic handle JSON + governed context",
            Self::NdabiWire => "NDABI wire + governed context",
            Self::NdabiLocal => "NDABI local + governed context",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::ReadableJson => 0,
            Self::SemanticJson => 1,
            Self::NdabiWire => 2,
            Self::NdabiLocal => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhiteTreeQuery {
    trajectory_id: u64,
    seed_ordinal: u32,
    valid_time: i64,
    system_time: i64,
    max_hops: u16,
}

impl WhiteTreeQuery {
    fn fixed() -> Self {
        Self {
            trajectory_id: 100,
            seed_ordinal: 3,
            valid_time: 5_000,
            system_time: 5_000,
            max_hops: 3,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ReadableRequest {
    protocol_version: u8,
    operation: String,
    trajectory_id: u64,
    seed_member_ordinal: u32,
    as_of_valid_time_microseconds: i64,
    as_of_system_time_microseconds: i64,
    maximum_causal_hops: u16,
    authority: Envelope,
    response_mode: String,
}

#[derive(Serialize, Deserialize)]
struct SemanticRequest {
    #[serde(rename = "v")]
    version: u8,
    #[serde(rename = "h")]
    handle: u16,
    #[serde(rename = "a")]
    arguments: (u64, u32, i64, i64, u16),
    #[serde(rename = "e")]
    envelope: Envelope,
}

#[derive(Serialize, Deserialize)]
struct WhiteTreeResponse {
    pack: ContextPack,
}

struct WhiteTreeFixture {
    store: ChunkStore,
    _root: tempfile::TempDir,
}

/// Execute the fixed governed White Tree profile behind the shared NDABI session boundary.
pub struct WhiteTreePreparedBackend {
    fixture: WhiteTreeFixture,
    response: Vec<u8>,
}

impl WhiteTreePreparedBackend {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            fixture: fixture()?,
            response: Vec::with_capacity(1_024),
        })
    }

    pub fn operation() -> RawOperation {
        let query = WhiteTreeQuery::fixed();
        let packed = (query.seed_ordinal << 16) | u32::from(query.max_hops);
        RawOperation::new(
            EXECUTE_CONTEXT,
            query.trajectory_id as i64,
            PREPARED_SNAPSHOT_HANDLE,
            packed,
        )
        .expect("the fixed White Tree operation is valid")
    }
}

impl SessionBackend for WhiteTreePreparedBackend {
    fn execute(&mut self, operation: RawOperation) -> Result<Vec<u8>, SessionError> {
        if operation != Self::operation() {
            return Err(SessionError::profile_refused(
                "the White Tree prepared operation is unsupported",
            ));
        }
        let (pack, _) = execute(&self.fixture, WhiteTreeQuery::fixed())
            .map_err(|_| SessionError::profile_refused("the White Tree governed query refused"))?;
        encode_wire_response(&mut self.response, &pack).map_err(|_| {
            SessionError::profile_refused("the White Tree response encoding failed")
        })?;
        Ok(self.response.clone())
    }
}

struct HotState {
    fixture: WhiteTreeFixture,
    response: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct WhiteTreeExamples {
    pub human_request: String,
    pub tuned_request: String,
    pub ndabi_hex: String,
    pub ndabi_disassembly: String,
    pub human_result: String,
}

#[derive(Debug, Serialize)]
pub struct WhiteTreeEvidence {
    pub arms: Vec<ArmMeasurement>,
    pub semantic_results_equal: bool,
    pub receipts_equal: bool,
    pub trusted_envelopes_equal: bool,
    pub refusals_passed: u32,
    pub refusals_total: u32,
    pub refused_engine_executions: u64,
    pub deterministic_encodings: bool,
    pub partitions_scanned: u64,
    pub partitions_pruned: u64,
    pub physical_bytes_read: u64,
    pub measurement_cycles: usize,
    pub measurement_schedule: [&'static str; 4],
    pub examples: WhiteTreeExamples,
}

#[derive(Clone, Copy)]
struct ResultIdentity {
    semantic_digest: u64,
    receipt_digest: u64,
    envelope: Envelope,
    scan: ScanReport,
}

pub fn run(iterations: usize, warmup: usize) -> Result<WhiteTreeEvidence, String> {
    let query = WhiteTreeQuery::fixed();
    let envelope = Envelope::valid(16);
    let requests = WhiteTreeArm::ALL
        .iter()
        .map(|arm| Ok((*arm, encode_request(*arm, query, envelope)?)))
        .collect::<Result<Vec<_>, String>>()?;

    let mut identities = Vec::new();
    let mut deterministic_encodings = true;
    let mut human_result = String::new();
    for (arm, request) in &requests {
        deterministic_encodings &= encode_request(*arm, query, envelope)? == *request;
        let mut state = HotState {
            fixture: fixture()?,
            response: Vec::with_capacity(1_024),
        };
        let first = process(*arm, request, query, envelope, &mut state)?;
        let first_bytes = state.response.clone();
        let second = process(*arm, request, query, envelope, &mut state)?;
        deterministic_encodings &= first_bytes == state.response;
        if *arm == WhiteTreeArm::ReadableJson {
            human_result = String::from_utf8(first_bytes)
                .map_err(|_| "White Tree readable result is not UTF-8".to_string())?;
        }
        identities.push((first, second));
    }
    let semantic_results_equal = identities
        .windows(2)
        .all(|pair| pair[0].0.semantic_digest == pair[1].0.semantic_digest)
        && identities
            .iter()
            .all(|pair| pair.0.semantic_digest == pair.1.semantic_digest);
    let receipts_equal = identities
        .windows(2)
        .all(|pair| pair[0].0.receipt_digest == pair[1].0.receipt_digest)
        && identities
            .iter()
            .all(|pair| pair.0.receipt_digest == pair.1.receipt_digest);
    let trusted_envelopes_equal = identities
        .iter()
        .all(|pair| pair.0.envelope == envelope && pair.1.envelope == envelope);

    let mut batches: [Vec<ArmBatch>; 4] = std::array::from_fn(|_| Vec::new());
    let mut states = WhiteTreeArm::ALL
        .iter()
        .map(|_| {
            Ok(HotState {
                fixture: fixture()?,
                response: Vec::with_capacity(1_024),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let samples_per_block = iterations / MEASUREMENT_BLOCKS_PER_ARM;
    let warmup_per_block = warmup / MEASUREMENT_BLOCKS_PER_ARM;
    let warmup_remainder = warmup % MEASUREMENT_BLOCKS_PER_ARM;
    let mut block_counts = [0usize; 4];
    for _ in 0..MEASUREMENT_CYCLES {
        for round in BALANCED_SCHEDULE {
            for arm in round {
                let index = arm.index();
                let block_warmup =
                    warmup_per_block + usize::from(block_counts[index] < warmup_remainder);
                block_counts[index] += 1;
                let request = &requests[index].1;
                let batch = measure_batch(samples_per_block, block_warmup, || {
                    let identity = process(arm, request, query, envelope, &mut states[index])?;
                    Ok(Observation {
                        response_bytes: states[index].response.len(),
                        semantic_digest: identity.semantic_digest,
                        view_digest: identity.receipt_digest,
                        rendered_bytes: 0,
                    })
                })?;
                batches[index].push(batch);
            }
        }
    }

    let arms = WhiteTreeArm::ALL
        .iter()
        .map(|arm| {
            let index = arm.index();
            finish_arm(
                arm.id(),
                arm.label(),
                requests[index].1.len(),
                requests[index].1.capacity()
                    + states[index].response.capacity()
                    + size_of::<ChunkStore>(),
                deterministic_encodings,
                std::mem::take(&mut batches[index]),
            )
        })
        .collect::<Result<Vec<_>, String>>()?;

    let reference = identities
        .first()
        .ok_or_else(|| "White Tree reference result is absent".to_string())?
        .0;
    let (refusals_passed, refusals_total, refused_engine_executions) = refusal_suite(query)?;
    Ok(WhiteTreeEvidence {
        arms,
        semantic_results_equal,
        receipts_equal,
        trusted_envelopes_equal,
        refusals_passed,
        refusals_total,
        refused_engine_executions,
        deterministic_encodings,
        partitions_scanned: reference.scan.partitions_scanned as u64,
        partitions_pruned: reference.scan.partitions_pruned as u64,
        physical_bytes_read: reference.scan.bytes_scanned,
        measurement_cycles: MEASUREMENT_CYCLES,
        measurement_schedule: [
            "human,tuned,wire,local",
            "tuned,wire,local,human",
            "wire,local,human,tuned",
            "local,human,tuned,wire",
        ],
        examples: WhiteTreeExamples {
            human_request: String::from_utf8(requests[0].1.clone())
                .map_err(|_| "White Tree readable request is not UTF-8".to_string())?,
            tuned_request: String::from_utf8(requests[1].1.clone())
                .map_err(|_| "White Tree semantic request is not UTF-8".to_string())?,
            ndabi_hex: hex(&requests[2].1),
            ndabi_disassembly: disassemble_request(&requests[2].1)?,
            human_result,
        },
    })
}

fn fixture() -> Result<WhiteTreeFixture, String> {
    let root = tempfile::Builder::new()
        .prefix("ndabi-white-tree-")
        .tempdir()
        .map_err(|error| error.to_string())?;
    let store = ChunkStore::create(
        root.path(),
        vec![
            (PartitionId(1), fixtures::software_ops_corpus()),
            (PartitionId(2), fixtures::spatial_dwell_corpus()),
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(WhiteTreeFixture { store, _root: root })
}

fn execute(
    fixture: &WhiteTreeFixture,
    query: WhiteTreeQuery,
) -> Result<(ContextPack, ScanReport), String> {
    let (outcome, report) = fixture
        .store
        .assemble_context_pack(
            TrajectoryId(query.trajectory_id),
            SeedSpec::Member(query.seed_ordinal),
            &HandleSeeds::default(),
            AsOf {
                valid: query.valid_time,
                system: query.system_time,
            },
            &fixtures::external_ml_profile(),
            usize::from(query.max_hops),
        )
        .map_err(|error| error.to_string())?;
    outcome
        .map(|pack| (pack, report))
        .map_err(|error| format!("White Tree context query refused: {error:?}"))
}

fn process(
    arm: WhiteTreeArm,
    request: &[u8],
    local_query: WhiteTreeQuery,
    local_envelope: Envelope,
    state: &mut HotState,
) -> Result<ResultIdentity, String> {
    let (query, envelope) = if arm == WhiteTreeArm::NdabiLocal {
        (local_query, local_envelope)
    } else {
        decode_request(arm, request)?
    };
    validate(query, envelope)?;
    let (pack, scan) = execute(&state.fixture, query)?;
    match arm {
        WhiteTreeArm::ReadableJson | WhiteTreeArm::SemanticJson => {
            state.response.clear();
            serde_json::to_writer(&mut state.response, &WhiteTreeResponse { pack })
                .map_err(|error| error.to_string())?;
            let decoded: WhiteTreeResponse =
                serde_json::from_slice(&state.response).map_err(|error| error.to_string())?;
            identity(&decoded.pack, scan, envelope)
        }
        WhiteTreeArm::NdabiWire => {
            encode_wire_response(&mut state.response, &pack)?;
            let decoded = decode_wire_response(&state.response)?;
            identity(&decoded, scan, envelope)
        }
        WhiteTreeArm::NdabiLocal => {
            state.response.clear();
            identity(&pack, scan, envelope)
        }
    }
}

fn identity(
    pack: &ContextPack,
    scan: ScanReport,
    envelope: Envelope,
) -> Result<ResultIdentity, String> {
    Ok(ResultIdentity {
        semantic_digest: digest_pack(pack, false)?,
        receipt_digest: digest_pack(pack, true)?,
        envelope,
        scan,
    })
}

fn digest_pack(pack: &ContextPack, receipt_only: bool) -> Result<u64, String> {
    let bytes = if receipt_only {
        serde_json::to_vec(&pack.receipt)
    } else {
        serde_json::to_vec(pack)
    }
    .map_err(|error| error.to_string())?;
    let mut digest = Digest64::new();
    digest.update(&bytes);
    Ok(digest.finish())
}

fn validate(query: WhiteTreeQuery, envelope: Envelope) -> Result<(), String> {
    validate_envelope(envelope, usize::from(query.max_hops))?;
    if query != WhiteTreeQuery::fixed() {
        return Err("White Tree query is not an authorised prepared operation".to_string());
    }
    Ok(())
}

fn encode_request(
    arm: WhiteTreeArm,
    query: WhiteTreeQuery,
    envelope: Envelope,
) -> Result<Vec<u8>, String> {
    match arm {
        WhiteTreeArm::ReadableJson => serde_json::to_vec(&ReadableRequest {
            protocol_version: VERSION,
            operation: "assemble_governed_context".to_string(),
            trajectory_id: query.trajectory_id,
            seed_member_ordinal: query.seed_ordinal,
            as_of_valid_time_microseconds: query.valid_time,
            as_of_system_time_microseconds: query.system_time,
            maximum_causal_hops: query.max_hops,
            authority: envelope,
            response_mode: "complete_context_and_receipt".to_string(),
        })
        .map_err(|error| error.to_string()),
        WhiteTreeArm::SemanticJson => serde_json::to_vec(&SemanticRequest {
            version: VERSION,
            handle: QUERY_HANDLE,
            arguments: (
                query.trajectory_id,
                query.seed_ordinal,
                query.valid_time,
                query.system_time,
                query.max_hops,
            ),
            envelope,
        })
        .map_err(|error| error.to_string()),
        WhiteTreeArm::NdabiWire => {
            let mut bytes = Vec::with_capacity(80);
            bytes.extend_from_slice(REQUEST_MAGIC);
            bytes.push(VERSION);
            bytes.push(EXECUTE_CONTEXT);
            push_u16(&mut bytes, QUERY_HANDLE);
            push_envelope(&mut bytes, envelope);
            push_u64(&mut bytes, query.trajectory_id);
            push_u32(&mut bytes, query.seed_ordinal);
            push_i64(&mut bytes, query.valid_time);
            push_i64(&mut bytes, query.system_time);
            push_u16(&mut bytes, query.max_hops);
            append_crc32(&mut bytes);
            Ok(bytes)
        }
        WhiteTreeArm::NdabiLocal => Ok(Vec::new()),
    }
}

fn decode_request(arm: WhiteTreeArm, bytes: &[u8]) -> Result<(WhiteTreeQuery, Envelope), String> {
    match arm {
        WhiteTreeArm::ReadableJson => {
            let request: ReadableRequest =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            if request.protocol_version != VERSION
                || request.operation != "assemble_governed_context"
                || request.response_mode != "complete_context_and_receipt"
            {
                return Err("White Tree readable request shape is not authorised".to_string());
            }
            Ok((
                WhiteTreeQuery {
                    trajectory_id: request.trajectory_id,
                    seed_ordinal: request.seed_member_ordinal,
                    valid_time: request.as_of_valid_time_microseconds,
                    system_time: request.as_of_system_time_microseconds,
                    max_hops: request.maximum_causal_hops,
                },
                request.authority,
            ))
        }
        WhiteTreeArm::SemanticJson => {
            let request: SemanticRequest =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            if request.version != VERSION || request.handle != QUERY_HANDLE {
                return Err("White Tree semantic handle is not authorised".to_string());
            }
            Ok((
                WhiteTreeQuery {
                    trajectory_id: request.arguments.0,
                    seed_ordinal: request.arguments.1,
                    valid_time: request.arguments.2,
                    system_time: request.arguments.3,
                    max_hops: request.arguments.4,
                },
                request.envelope,
            ))
        }
        WhiteTreeArm::NdabiWire => {
            let body = verify_crc32(bytes)?;
            let mut reader = Reader::new(body);
            if reader.take(4)? != REQUEST_MAGIC
                || reader.u8()? != VERSION
                || reader.u8()? != EXECUTE_CONTEXT
                || reader.u16()? != QUERY_HANDLE
            {
                return Err("White Tree NDABI request header is not authorised".to_string());
            }
            let envelope = reader.envelope()?;
            let query = WhiteTreeQuery {
                trajectory_id: reader.u64()?,
                seed_ordinal: reader.u32()?,
                valid_time: read_i64(&mut reader)?,
                system_time: read_i64(&mut reader)?,
                max_hops: reader.u16()?,
            };
            if reader.remaining() != 0 {
                return Err("White Tree NDABI request has trailing bytes".to_string());
            }
            Ok((query, envelope))
        }
        WhiteTreeArm::NdabiLocal => Err("White Tree local binding has no request".to_string()),
    }
}

fn encode_wire_response(output: &mut Vec<u8>, pack: &ContextPack) -> Result<(), String> {
    output.clear();
    output.extend_from_slice(RESPONSE_MAGIC);
    output.push(VERSION);
    push_u16_checked(output, pack.members.len(), "member count")?;
    for member in &pack.members {
        push_u64(output, member.event_id.0);
        push_u32(output, member.ordinal);
        push_u32(output, member.role);
        push_i64(output, member.time.valid);
        push_i64(output, member.time.system);
        push_u16_checked(output, member.evidence.len(), "member evidence count")?;
        for evidence in &member.evidence {
            push_u64(output, evidence.0);
        }
        output.push(sensitivity_code(member.governance.max_sensitivity));
        push_u32(output, member.governance.jurisdictions);
        push_u32(output, member.governance.rights);
        push_u32(output, member.governance.export_policy);
    }
    encode_evidence(output, &pack.evidence)?;
    let receipt = &pack.receipt;
    push_u64(output, receipt.trajectory_id);
    push_u32(output, receipt.version_id);
    push_u32(output, receipt.seed_ordinal);
    push_i64(output, receipt.as_of.valid);
    push_i64(output, receipt.as_of.system);
    encode_profile(output, receipt.profile_key);
    encode_evidence(output, &receipt.used_evidence)?;
    encode_u32_values(output, &receipt.withheld_ordinals, "withheld count")?;
    encode_u32_values(output, &receipt.unknown_ordinals, "unknown count")?;
    push_u16_checked(output, receipt.hops_used, "hop count")?;
    append_crc32(output);
    Ok(())
}

fn decode_wire_response(bytes: &[u8]) -> Result<ContextPack, String> {
    let body = verify_crc32(bytes)?;
    let mut reader = Reader::new(body);
    if reader.take(4)? != RESPONSE_MAGIC || reader.u8()? != VERSION {
        return Err("White Tree NDABI response header does not match".to_string());
    }
    let member_count = usize::from(reader.u16()?);
    let mut members = Vec::with_capacity(member_count);
    for _ in 0..member_count {
        let event_id = EventId(reader.u64()?);
        let ordinal = reader.u32()?;
        let role = reader.u32()?;
        let time = Bitemporal {
            valid: read_i64(&mut reader)?,
            system: read_i64(&mut reader)?,
        };
        let evidence = decode_evidence(&mut reader)?;
        let governance = Governance {
            max_sensitivity: decode_sensitivity(reader.u8()?)?,
            jurisdictions: reader.u32()?,
            rights: reader.u32()?,
            export_policy: reader.u32()?,
        };
        members.push(Member {
            event_id,
            ordinal,
            role,
            time,
            evidence,
            governance,
        });
    }
    let evidence = decode_evidence(&mut reader)?;
    let trajectory_id = reader.u64()?;
    let version_id = reader.u32()?;
    let seed_ordinal = reader.u32()?;
    let as_of = AsOf {
        valid: read_i64(&mut reader)?,
        system: read_i64(&mut reader)?,
    };
    let profile_key = decode_profile(&mut reader)?;
    let used_evidence = decode_evidence(&mut reader)?;
    let withheld_ordinals = decode_u32_values(&mut reader)?;
    let unknown_ordinals = decode_u32_values(&mut reader)?;
    let hops_used = usize::from(reader.u16()?);
    if reader.remaining() != 0 {
        return Err("White Tree NDABI response has trailing bytes".to_string());
    }
    Ok(ContextPack {
        members,
        evidence,
        receipt: olx_core::context::ContextReceipt {
            trajectory_id,
            version_id,
            seed_ordinal,
            as_of,
            profile_key,
            used_evidence,
            withheld_ordinals,
            unknown_ordinals,
            hops_used,
        },
    })
}

fn encode_evidence(output: &mut Vec<u8>, values: &[EvidenceRef]) -> Result<(), String> {
    push_u16_checked(output, values.len(), "evidence count")?;
    for value in values {
        push_u64(output, value.0);
    }
    Ok(())
}

fn decode_evidence(reader: &mut Reader<'_>) -> Result<Vec<EvidenceRef>, String> {
    let count = usize::from(reader.u16()?);
    (0..count).map(|_| Ok(EvidenceRef(reader.u64()?))).collect()
}

fn encode_u32_values(output: &mut Vec<u8>, values: &[u32], name: &str) -> Result<(), String> {
    push_u16_checked(output, values.len(), name)?;
    for value in values {
        push_u32(output, *value);
    }
    Ok(())
}

fn decode_u32_values(reader: &mut Reader<'_>) -> Result<Vec<u32>, String> {
    let count = usize::from(reader.u16()?);
    (0..count).map(|_| reader.u32()).collect()
}

fn encode_profile(output: &mut Vec<u8>, profile: ProfileKey) {
    push_u32(output, profile.profile_bit);
    output.push(sensitivity_code(profile.max_sensitivity));
    push_u32(output, profile.jurisdictions);
    push_u32(output, profile.rights);
}

fn decode_profile(reader: &mut Reader<'_>) -> Result<ProfileKey, String> {
    Ok(ProfileKey {
        profile_bit: reader.u32()?,
        max_sensitivity: decode_sensitivity(reader.u8()?)?,
        jurisdictions: reader.u32()?,
        rights: reader.u32()?,
    })
}

fn sensitivity_code(value: SensitivityClass) -> u8 {
    match value {
        SensitivityClass::None => 0,
        SensitivityClass::BusinessConfidential => 1,
        SensitivityClass::PersonalData => 2,
        SensitivityClass::EmployeeHr => 3,
        SensitivityClass::LocationPrecise => 4,
        SensitivityClass::Health => 5,
        SensitivityClass::LegalPrivilege => 6,
    }
}

fn decode_sensitivity(value: u8) -> Result<SensitivityClass, String> {
    match value {
        0 => Ok(SensitivityClass::None),
        1 => Ok(SensitivityClass::BusinessConfidential),
        2 => Ok(SensitivityClass::PersonalData),
        3 => Ok(SensitivityClass::EmployeeHr),
        4 => Ok(SensitivityClass::LocationPrecise),
        5 => Ok(SensitivityClass::Health),
        6 => Ok(SensitivityClass::LegalPrivilege),
        _ => Err("White Tree sensitivity code is unknown".to_string()),
    }
}

fn push_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn read_i64(reader: &mut Reader<'_>) -> Result<i64, String> {
    let bytes: [u8; 8] = reader
        .take(8)?
        .try_into()
        .map_err(|_| "i64 is truncated".to_string())?;
    Ok(i64::from_le_bytes(bytes))
}

fn push_u16_checked(output: &mut Vec<u8>, value: usize, name: &str) -> Result<(), String> {
    push_u16(
        output,
        u16::try_from(value).map_err(|_| format!("White Tree {name} exceeds the frame limit"))?,
    );
    Ok(())
}

fn disassemble_request(bytes: &[u8]) -> Result<String, String> {
    let (query, envelope) = decode_request(WhiteTreeArm::NdabiWire, bytes)?;
    Ok(format!(
        "v1 EXECUTE_CONTEXT handle={QUERY_HANDLE} principal={} purpose={} tenant={} snapshot={} trajectory={} seed={} valid={} system={} max_hops={}",
        envelope.principal,
        envelope.purpose,
        envelope.tenant,
        envelope.snapshot,
        query.trajectory_id,
        query.seed_ordinal,
        query.valid_time,
        query.system_time,
        query.max_hops,
    ))
}

fn refusal_suite(query: WhiteTreeQuery) -> Result<(u32, u32, u64), String> {
    let mut cases = Vec::new();
    let mut wrong_principal = Envelope::valid(16);
    wrong_principal.principal ^= 1;
    cases.push(encode_request(
        WhiteTreeArm::NdabiWire,
        query,
        wrong_principal,
    )?);
    let mut wrong_query = query;
    wrong_query.max_hops += 1;
    cases.push(encode_request(
        WhiteTreeArm::NdabiWire,
        wrong_query,
        Envelope::valid(16),
    )?);
    let mut corrupt = encode_request(WhiteTreeArm::NdabiWire, query, Envelope::valid(16))?;
    corrupt[0] ^= 1;
    cases.push(corrupt);

    let mut passed = 0;
    let mut executions = 0u64;
    for case in cases {
        let outcome = decode_request(WhiteTreeArm::NdabiWire, &case)
            .and_then(|(decoded_query, envelope)| validate(decoded_query, envelope))
            .map(|_| executions += 1);
        if outcome.is_err() {
            passed += 1;
        }
    }
    Ok((passed, 3, executions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_round_trip_preserves_the_complete_governed_pack() {
        let fixture = fixture().expect("fixture");
        let (pack, scan) = execute(&fixture, WhiteTreeQuery::fixed()).expect("query");
        let mut bytes = Vec::new();
        encode_wire_response(&mut bytes, &pack).expect("encode");
        let decoded = decode_wire_response(&bytes).expect("decode");
        assert_eq!(decoded, pack);
        assert_eq!(scan.partitions_scanned, 1);
    }

    #[test]
    fn governed_fixture_prunes_the_unrelated_partition() {
        let fixture = fixture().expect("fixture");
        let (pack, scan) = execute(&fixture, WhiteTreeQuery::fixed()).expect("query");
        assert_eq!(pack.members.len(), 4);
        assert_eq!(scan.partitions_scanned, 1);
        assert_eq!(scan.partitions_pruned, 1);
        assert_eq!(scan.bytes_read_from_blocked, 0);
    }

    #[test]
    fn mutation_fails_before_engine_execution() {
        let query = WhiteTreeQuery::fixed();
        let (passed, total, executions) = refusal_suite(query).expect("refusal suite");
        assert_eq!(passed, total);
        assert_eq!(executions, 0);
    }

    #[test]
    fn shared_session_executes_the_complete_governed_result() {
        let authority =
            ndabi_session::Authority::new([19; 32], 11, 12, 2_000, 13, 14, 15).expect("authority");
        let mut client = ndabi_session::ClientSession::new(authority.clone());
        let mut server = ndabi_session::ServerSession::new(authority, 8_192).expect("server");
        let frame = client
            .encode(WhiteTreePreparedBackend::operation(), 8_192, 1_500)
            .expect("frame");
        let mut backend = WhiteTreePreparedBackend::new().expect("backend");
        let result = server
            .execute(&frame, 1_000, &mut backend)
            .expect("execution");
        let decoded = decode_wire_response(&result.bytes).expect("result");
        assert_eq!(decoded.members.len(), 4);
        assert_eq!(decoded.receipt.trajectory_id, 100);
    }

    #[test]
    fn shared_session_refuses_a_changed_profile_operation() {
        let authority =
            ndabi_session::Authority::new([19; 32], 11, 12, 2_000, 13, 14, 15).expect("authority");
        let mut client = ndabi_session::ClientSession::new(authority.clone());
        let mut server = ndabi_session::ServerSession::new(authority, 8_192).expect("server");
        let operation =
            RawOperation::new(EXECUTE_CONTEXT, 101, 1, (3 << 16) | 3).expect("operation");
        let frame = client.encode(operation, 8_192, 1_500).expect("frame");
        let mut backend = WhiteTreePreparedBackend::new().expect("backend");
        assert!(server.execute(&frame, 1_000, &mut backend).is_err());
    }
}
