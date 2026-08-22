use std::borrow::Cow;
use std::fmt;
use std::io::Write;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::measure::{
    finish_arm, measure_batch, median_operation_timing, ArmBatch, ArmMeasurement, Observation,
    PhaseMeasurement, RetainedMemoryBreakdown,
};
use crate::sqlite::Database;
use crate::wire::{
    append_crc32, hex, push_envelope, push_u16, push_u32, push_u64, validate_envelope,
    verify_crc32, Digest64, Envelope, Reader,
};

const DATABASE_MAGIC: &[u8; 4] = b"NDAQ";
const DATABASE_RESPONSE_MAGIC: &[u8; 4] = b"NDAR";
const DATABASE_VERSION: u8 = 1;
const EXECUTE_HANDLE: u8 = 0x11;
const QUERY_HANDLE: u16 = 17;
const MEASUREMENT_CYCLES: usize = 10;
const BALANCED_SCHEDULE: [[DbArm; 4]; 4] = [
    [
        DbArm::SqlJson,
        DbArm::PreparedJson,
        DbArm::NdabiWire,
        DbArm::NdabiLocal,
    ],
    [
        DbArm::PreparedJson,
        DbArm::NdabiWire,
        DbArm::NdabiLocal,
        DbArm::SqlJson,
    ],
    [
        DbArm::NdabiWire,
        DbArm::NdabiLocal,
        DbArm::SqlJson,
        DbArm::PreparedJson,
    ],
    [
        DbArm::NdabiLocal,
        DbArm::SqlJson,
        DbArm::PreparedJson,
        DbArm::NdabiWire,
    ],
];
const MEASUREMENT_BLOCKS_PER_ARM: usize = BALANCED_SCHEDULE.len() * MEASUREMENT_CYCLES;

const SQL: &str = "SELECT id, owner, score, updated_at, title FROM records WHERE tenant_id = ?1 AND owner = ?2 AND active = 1 AND score >= ?3 ORDER BY score DESC, id ASC LIMIT ?4";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbArm {
    SqlJson,
    PreparedJson,
    NdabiWire,
    NdabiLocal,
}

impl DbArm {
    pub const ALL: [Self; 4] = [
        Self::SqlJson,
        Self::PreparedJson,
        Self::NdabiWire,
        Self::NdabiLocal,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::SqlJson => "human",
            Self::PreparedJson => "tuned",
            Self::NdabiWire => "wire",
            Self::NdabiLocal => "local",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::SqlJson => "SQL + named JSON",
            Self::PreparedJson => "Prepared handle + compact JSON",
            Self::NdabiWire => "NDABI wire",
            Self::NdabiLocal => "NDABI local",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::SqlJson => 0,
            Self::PreparedJson => 1,
            Self::NdabiWire => 2,
            Self::NdabiLocal => 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DbRow {
    pub id: u32,
    pub owner: u16,
    pub score: u16,
    pub updated_at: u64,
    pub title: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DbQuery {
    owner: u16,
    min_score: u16,
    limit: u16,
}

impl DbQuery {
    fn fixed() -> Self {
        Self {
            owner: 7,
            min_score: 250,
            limit: 24,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DbReceipt {
    snapshot: u64,
    row_count: u16,
    result_digest: u64,
}

#[derive(Debug)]
struct DbRoundTrip {
    response: Vec<u8>,
    rows: Vec<DbRow>,
    receipt: DbReceipt,
    envelope: Envelope,
}

#[derive(Debug, Serialize)]
pub struct DbExamples {
    pub human_request: String,
    pub tuned_request: String,
    pub ndabi_hex: String,
    pub ndabi_disassembly: String,
    pub human_result: String,
}

#[derive(Debug, Serialize)]
pub struct DbEvidence {
    pub arms: Vec<ArmMeasurement>,
    pub semantic_results_equal: bool,
    pub trusted_envelopes_equal: bool,
    pub receipts_verified: bool,
    pub refusals_passed: u32,
    pub refusals_total: u32,
    pub refused_database_executions: u64,
    pub deterministic_encodings: bool,
    pub diagnostic_samples: usize,
    pub measurement_cycles: usize,
    pub measurement_schedule: [&'static str; 4],
    pub phase_profiles: Vec<PhaseMeasurement>,
    pub retained_memory: Vec<RetainedMemoryBreakdown>,
    pub examples: DbExamples,
}

#[derive(Serialize, Deserialize)]
struct SqlParameters {
    tenant_id: u32,
    owner: u16,
    minimum_score: u16,
    limit: u16,
}

#[derive(Serialize, Deserialize)]
struct SqlRequest {
    protocol_version: u8,
    operation: String,
    sql: String,
    parameters: SqlParameters,
    authority: Envelope,
    output_format: String,
}

#[derive(Serialize, Deserialize)]
struct PreparedRequest {
    #[serde(rename = "v")]
    version: u8,
    #[serde(rename = "h")]
    handle: u16,
    #[serde(rename = "a")]
    arguments: (u32, u16, u16, u16),
    #[serde(rename = "e")]
    envelope: Envelope,
}

#[derive(Serialize, Deserialize)]
struct VerboseReceipt {
    snapshot: u64,
    rows_returned: u16,
    result_digest: String,
}

#[derive(Serialize, Deserialize)]
struct VerboseResponse {
    rows: Vec<DbRow>,
    receipt: VerboseReceipt,
}

#[derive(Serialize, Deserialize)]
struct CompactResponse {
    #[serde(rename = "r")]
    rows: Vec<(u32, u16, u16, u64, String)>,
    #[serde(rename = "x")]
    receipt: (u64, u16, String),
}

#[derive(Deserialize)]
struct CompactResponseScan<'a> {
    #[serde(rename = "r")]
    rows: CompactRowsScan,
    #[serde(borrow, rename = "x")]
    receipt: (u64, u16, &'a str),
}

struct CompactRowsScan {
    row_count: u16,
    result_digest: u64,
}

struct BorrowedCompactRow<'a>(u32, u16, u16, u64, BorrowedText<'a>);

struct BorrowedText<'a>(Cow<'a, str>);

impl<'de> Deserialize<'de> for BorrowedText<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TextVisitor;

        impl<'de> Visitor<'de> for TextVisitor {
            type Value = BorrowedText<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a database title")
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BorrowedText(Cow::Borrowed(value)))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BorrowedText(Cow::Owned(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BorrowedText(Cow::Owned(value)))
            }
        }

        deserializer.deserialize_string(TextVisitor)
    }
}

impl<'de> Deserialize<'de> for BorrowedCompactRow<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RowVisitor;

        impl<'de> Visitor<'de> for RowVisitor {
            type Value = BorrowedCompactRow<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a compact database row")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let id = required(&mut sequence, "row id")?;
                let owner = required(&mut sequence, "row owner")?;
                let score = required(&mut sequence, "row score")?;
                let updated_at = required(&mut sequence, "row timestamp")?;
                let title = required(&mut sequence, "row title")?;
                if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("compact database row has extra fields"));
                }
                Ok(BorrowedCompactRow(id, owner, score, updated_at, title))
            }
        }

        deserializer.deserialize_tuple(5, RowVisitor)
    }
}

impl<'de> Deserialize<'de> for CompactRowsScan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RowsVisitor;

        impl<'de> Visitor<'de> for RowsVisitor {
            type Value = CompactRowsScan;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("compact database rows")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut digest = Digest64::new();
                let mut count = 0u16;
                while let Some(row) = sequence.next_element::<BorrowedCompactRow<'de>>()? {
                    update_row_digest(&mut digest, row.0, row.1, row.2, row.3, row.4 .0.as_ref());
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| de::Error::custom("database row count overflow"))?;
                }
                Ok(CompactRowsScan {
                    row_count: count,
                    result_digest: digest.finish(),
                })
            }
        }

        deserializer.deserialize_seq(RowsVisitor)
    }
}

fn required<'de, A, T>(sequence: &mut A, field: &str) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: Deserialize<'de>,
{
    sequence
        .next_element()?
        .ok_or_else(|| de::Error::custom(format!("compact database row lacks {field}")))
}

pub fn run(rows: usize, iterations: usize, warmup: usize) -> Result<DbEvidence, String> {
    let query = DbQuery::fixed();
    let envelope = Envelope::valid(32);
    let requests: Vec<(DbArm, Vec<u8>)> = DbArm::ALL
        .iter()
        .map(|arm| Ok((*arm, encode_request(*arm, query, envelope)?)))
        .collect::<Result<_, String>>()?;

    let mut exact_rows = Vec::new();
    let mut exact_receipts = Vec::new();
    let mut exact_envelopes = Vec::new();
    let mut receipts_verified = true;
    let mut deterministic_encodings = requests.iter().all(|(arm, request)| {
        encode_request(*arm, query, envelope)
            .map(|repeat| repeat == *request)
            .unwrap_or(false)
    });
    for (arm, request) in &requests {
        let mut connection = fixture(rows)?;
        let mut executions = 0;
        let first = if *arm == DbArm::NdabiLocal {
            process_local(&mut connection, query, envelope, &mut executions)?
        } else {
            process(&mut connection, *arm, request, &mut executions)?
        };
        let second = if *arm == DbArm::NdabiLocal {
            process_local(&mut connection, query, envelope, &mut executions)?
        } else {
            process(&mut connection, *arm, request, &mut executions)?
        };
        deterministic_encodings &= first.response == second.response;
        receipts_verified &= first.receipt.row_count
            == u16::try_from(first.rows.len()).map_err(|_| "row count overflow".to_string())?
            && first.receipt.result_digest == digest_rows(&first.rows);
        exact_rows.push(first.rows);
        exact_receipts.push(first.receipt);
        exact_envelopes.push(first.envelope);
    }

    let semantic_results_equal = exact_rows.windows(2).all(|pair| pair[0] == pair[1])
        && exact_receipts.windows(2).all(|pair| pair[0] == pair[1]);
    let trusted_envelopes_equal = exact_envelopes.windows(2).all(|pair| pair[0] == pair[1]);

    let mut batches: [Vec<ArmBatch>; 4] = std::array::from_fn(|_| Vec::new());
    let samples_per_block = iterations / MEASUREMENT_BLOCKS_PER_ARM;
    let warmup_per_block = warmup / MEASUREMENT_BLOCKS_PER_ARM;
    let warmup_remainder = warmup % MEASUREMENT_BLOCKS_PER_ARM;
    let mut arm_block_counts = [0usize; 4];
    let mut measurement_connections = DbArm::ALL
        .iter()
        .map(|_| fixture(rows))
        .collect::<Result<Vec<_>, _>>()?;
    let mut execution_counts = [0u64; 4];
    let mut response_buffers: [Vec<u8>; 4] = std::array::from_fn(|index| {
        if index == DbArm::NdabiLocal.index() {
            Vec::new()
        } else {
            Vec::with_capacity(1_024)
        }
    });
    for _ in 0..MEASUREMENT_CYCLES {
        for round in BALANCED_SCHEDULE {
            for arm in round {
                let arm_index = arm.index();
                let block_warmup =
                    warmup_per_block + usize::from(arm_block_counts[arm_index] < warmup_remainder);
                arm_block_counts[arm_index] += 1;
                let request = &requests[arm_index].1;
                let connection = &mut measurement_connections[arm_index];
                let executions = &mut execution_counts[arm_index];
                let response_buffer = &mut response_buffers[arm_index];
                let batch = measure_batch(samples_per_block, block_warmup, || match arm {
                    DbArm::NdabiWire => {
                        process_wire_fast(connection, request, executions, response_buffer)
                    }
                    DbArm::PreparedJson => {
                        process_tuned_fast(connection, request, executions, response_buffer)
                    }
                    DbArm::NdabiLocal => {
                        process_local_fast(connection, query, envelope, executions)
                    }
                    _ => {
                        let round_trip = process(connection, arm, request, executions)?;
                        Ok(Observation {
                            response_bytes: round_trip.response.len(),
                            semantic_digest: round_trip.receipt.result_digest,
                            view_digest: round_trip.receipt.result_digest,
                            rendered_bytes: 0,
                        })
                    }
                })?;
                batches[arm_index].push(batch);
            }
        }
    }
    let retained_memory = DbArm::ALL
        .iter()
        .map(|arm| {
            let request_capacity_bytes = requests[arm.index()].1.capacity();
            let response_capacity_bytes = response_buffers[arm.index()].capacity();
            let engine_handle_bytes = std::mem::size_of_val(&measurement_connections[arm.index()]);
            RetainedMemoryBreakdown {
                id: arm.id().to_string(),
                label: arm.label().to_string(),
                request_capacity_bytes: request_capacity_bytes as u64,
                response_capacity_bytes: response_capacity_bytes as u64,
                rendered_capacity_bytes: 0,
                receipt_tree_bytes: 0,
                state_bytes: 0,
                engine_handle_bytes: engine_handle_bytes as u64,
                total_bytes: (request_capacity_bytes
                    + response_capacity_bytes
                    + engine_handle_bytes) as u64,
            }
        })
        .collect::<Vec<_>>();
    let measurements = DbArm::ALL
        .iter()
        .map(|arm| {
            let request_bytes = requests[arm.index()].1.len();
            let retained_rust_bytes = requests[arm.index()].1.capacity()
                + response_buffers[arm.index()].capacity()
                + std::mem::size_of_val(&measurement_connections[arm.index()]);
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
        rows,
        &requests,
        query,
        envelope,
        diagnostic_samples,
        (warmup / 4).min(25),
    )?;

    let (refusals_passed, refusals_total, refused_database_executions) =
        refusal_suite(rows, query)?;

    let human_request = String::from_utf8(requests[0].1.clone())
        .map_err(|_| "human database request is not UTF-8".to_string())?;
    let tuned_request = String::from_utf8(requests[1].1.clone())
        .map_err(|_| "tuned database request is not UTF-8".to_string())?;
    let human_result = serde_json::to_string_pretty(
        &exact_rows
            .first()
            .ok_or_else(|| "database exactness result is absent".to_string())?
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>(),
    )
    .map_err(|error| error.to_string())?;

    Ok(DbEvidence {
        arms: measurements,
        semantic_results_equal,
        trusted_envelopes_equal,
        receipts_verified,
        refusals_passed,
        refusals_total,
        refused_database_executions,
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
        examples: DbExamples {
            human_request,
            tuned_request,
            ndabi_hex: hex(&requests[2].1),
            ndabi_disassembly: disassemble_request(&requests[2].1)?,
            human_result,
        },
    })
}

fn profile_stages(
    row_count: usize,
    requests: &[(DbArm, Vec<u8>)],
    query: DbQuery,
    envelope: Envelope,
    iterations: usize,
    warmup: usize,
) -> Result<Vec<PhaseMeasurement>, String> {
    let mut profiles = Vec::new();
    for arm in DbArm::ALL {
        let request = &requests[arm.index()].1;
        let admission = median_operation_timing(iterations, warmup, || {
            let (decoded_query, decoded_envelope) = if arm == DbArm::NdabiLocal {
                (query, envelope)
            } else {
                decode_request(arm, request)?
            };
            validate_envelope(decoded_envelope, usize::from(decoded_query.limit))?;
            std::hint::black_box((decoded_query, decoded_envelope));
            Ok(())
        })?;

        let mut execution_connection = fixture(row_count)?;
        let execution = median_operation_timing(iterations, warmup, || {
            if matches!(
                arm,
                DbArm::PreparedJson | DbArm::NdabiWire | DbArm::NdabiLocal
            ) {
                let count = execute_visit(
                    &mut execution_connection,
                    query,
                    |id, owner, score, updated_at, title| {
                        std::hint::black_box((id, owner, score, updated_at, title));
                        Ok(())
                    },
                )?;
                std::hint::black_box(count);
            } else {
                let rows = execute(&mut execution_connection, query, arm != DbArm::SqlJson)?;
                std::hint::black_box(rows);
            }
            Ok(())
        })?;

        let mut result_connection = fixture(row_count)?;
        let rows = execute(&mut result_connection, query, true)?;
        let receipt = DbReceipt {
            snapshot: envelope.snapshot,
            row_count: u16::try_from(rows.len()).map_err(|_| "row count overflow".to_string())?,
            result_digest: digest_rows(&rows),
        };
        let mut result_response = Vec::with_capacity(1_024);
        let result = median_operation_timing(iterations, warmup, || {
            if arm == DbArm::NdabiLocal {
                std::hint::black_box(digest_rows(&rows));
            } else if arm == DbArm::PreparedJson {
                encode_tuned_rows_into(&mut result_response, &rows, receipt)?;
                std::hint::black_box(inspect_tuned_response(&result_response)?);
            } else if arm == DbArm::NdabiWire {
                encode_wire_rows_into(&mut result_response, &rows, receipt)?;
                std::hint::black_box(inspect_wire_response(&result_response)?);
            } else {
                let response = encode_response(arm, &rows, receipt)?;
                if arm == DbArm::NdabiWire {
                    std::hint::black_box(inspect_wire_response(&response)?);
                } else {
                    std::hint::black_box(decode_response(arm, &response)?);
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

fn fixture(row_count: usize) -> Result<Database, String> {
    let mut database = Database::in_memory()?;
    database.execute_batch(
        "CREATE TABLE records (
                id INTEGER PRIMARY KEY,
                tenant_id INTEGER NOT NULL,
                owner INTEGER NOT NULL,
                active INTEGER NOT NULL,
                score INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                title TEXT NOT NULL
            );
            CREATE INDEX records_query ON records(tenant_id, owner, active, score DESC, id ASC);
            BEGIN;",
    )?;
    let mut insert = database.prepare(
        "INSERT INTO records(id, tenant_id, owner, active, score, updated_at, title)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for id in 0..row_count {
        let id_u32 = u32::try_from(id).map_err(|_| "fixture identifier overflow".to_string())?;
        let tenant = (id_u32 % 3) + 1;
        let owner = id_u32 % 32;
        let active = if id_u32 % 5 == 0 { 0 } else { 1 };
        let score = (id_u32.wrapping_mul(37).wrapping_add(13)) % 1_000;
        let updated_at = 1_700_000_000u64 + u64::from(id_u32) * 17;
        let title = format!("decision-stream-{id_u32:05}");
        database.insert_fixture_row(
            &mut insert,
            [
                i64::from(id_u32),
                i64::from(tenant),
                i64::from(owner),
                i64::from(active),
                i64::from(score),
                i64::try_from(updated_at).map_err(|error| error.to_string())?,
            ],
            &title,
        )?;
    }
    drop(insert);
    database.execute_batch("COMMIT;")?;
    Ok(database)
}

fn encode_request(arm: DbArm, query: DbQuery, envelope: Envelope) -> Result<Vec<u8>, String> {
    match arm {
        DbArm::SqlJson => serde_json::to_vec(&SqlRequest {
            protocol_version: 1,
            operation: "query".to_string(),
            sql: SQL.to_string(),
            parameters: SqlParameters {
                tenant_id: envelope.tenant,
                owner: query.owner,
                minimum_score: query.min_score,
                limit: query.limit,
            },
            authority: envelope,
            output_format: "named-json-rows".to_string(),
        })
        .map_err(|error| error.to_string()),
        DbArm::PreparedJson => serde_json::to_vec(&PreparedRequest {
            version: 1,
            handle: QUERY_HANDLE,
            arguments: (envelope.tenant, query.owner, query.min_score, query.limit),
            envelope,
        })
        .map_err(|error| error.to_string()),
        DbArm::NdabiWire => {
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(DATABASE_MAGIC);
            bytes.push(DATABASE_VERSION);
            bytes.push(EXECUTE_HANDLE);
            push_u16(&mut bytes, QUERY_HANDLE);
            push_envelope(&mut bytes, envelope);
            push_u16(&mut bytes, query.owner);
            push_u16(&mut bytes, query.min_score);
            push_u16(&mut bytes, query.limit);
            append_crc32(&mut bytes);
            Ok(bytes)
        }
        DbArm::NdabiLocal => Ok(Vec::new()),
    }
}

fn decode_request(arm: DbArm, bytes: &[u8]) -> Result<(DbQuery, Envelope), String> {
    match arm {
        DbArm::SqlJson => {
            let request: SqlRequest =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            if request.protocol_version != 1
                || request.operation != "query"
                || request.sql != SQL
                || request.output_format != "named-json-rows"
            {
                return Err("SQL request shape is not authorised".to_string());
            }
            if request.parameters.tenant_id != request.authority.tenant {
                return Err("SQL tenant argument does not match authority".to_string());
            }
            Ok((
                DbQuery {
                    owner: request.parameters.owner,
                    min_score: request.parameters.minimum_score,
                    limit: request.parameters.limit,
                },
                request.authority,
            ))
        }
        DbArm::PreparedJson => {
            let request: PreparedRequest =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            if request.version != 1 || request.handle != QUERY_HANDLE {
                return Err("prepared request handle is not authorised".to_string());
            }
            if request.arguments.0 != request.envelope.tenant {
                return Err("prepared tenant argument does not match authority".to_string());
            }
            Ok((
                DbQuery {
                    owner: request.arguments.1,
                    min_score: request.arguments.2,
                    limit: request.arguments.3,
                },
                request.envelope,
            ))
        }
        DbArm::NdabiWire => {
            let body = verify_crc32(bytes)?;
            let mut reader = Reader::new(body);
            if reader.take(4)? != DATABASE_MAGIC {
                return Err("database frame magic does not match".to_string());
            }
            if reader.u8()? != DATABASE_VERSION || reader.u8()? != EXECUTE_HANDLE {
                return Err("database frame version or opcode is not authorised".to_string());
            }
            if reader.u16()? != QUERY_HANDLE {
                return Err("database frame handle is not authorised".to_string());
            }
            let envelope = reader.envelope()?;
            let query = DbQuery {
                owner: reader.u16()?,
                min_score: reader.u16()?,
                limit: reader.u16()?,
            };
            if reader.remaining() != 0 {
                return Err("database frame has trailing bytes".to_string());
            }
            Ok((query, envelope))
        }
        DbArm::NdabiLocal => Err("NDABI local has no wire request".to_string()),
    }
}

fn process(
    connection: &mut Database,
    arm: DbArm,
    request: &[u8],
    executions: &mut u64,
) -> Result<DbRoundTrip, String> {
    let (query, envelope) = decode_request(arm, request)?;
    validate_envelope(envelope, usize::from(query.limit))?;
    *executions = executions.saturating_add(1);
    let rows = execute(connection, query, arm != DbArm::SqlJson)?;
    let receipt = DbReceipt {
        snapshot: envelope.snapshot,
        row_count: u16::try_from(rows.len()).map_err(|_| "row count overflow".to_string())?,
        result_digest: digest_rows(&rows),
    };
    let response = encode_response(arm, &rows, receipt)?;
    let (decoded_rows, decoded_receipt) = decode_response(arm, &response)?;
    Ok(DbRoundTrip {
        response,
        rows: decoded_rows,
        receipt: decoded_receipt,
        envelope,
    })
}

fn process_local(
    connection: &mut Database,
    query: DbQuery,
    envelope: Envelope,
    executions: &mut u64,
) -> Result<DbRoundTrip, String> {
    validate_envelope(envelope, usize::from(query.limit))?;
    *executions = executions.saturating_add(1);
    let rows = execute(connection, query, true)?;
    let receipt = DbReceipt {
        snapshot: envelope.snapshot,
        row_count: u16::try_from(rows.len()).map_err(|_| "row count overflow".to_string())?,
        result_digest: digest_rows(&rows),
    };
    Ok(DbRoundTrip {
        response: Vec::new(),
        rows,
        receipt,
        envelope,
    })
}

fn process_wire_fast(
    connection: &mut Database,
    request: &[u8],
    executions: &mut u64,
    response: &mut Vec<u8>,
) -> Result<Observation, String> {
    let (query, envelope) = decode_request(DbArm::NdabiWire, request)?;
    validate_envelope(envelope, usize::from(query.limit))?;
    *executions = executions.saturating_add(1);

    response.clear();
    response.extend_from_slice(DATABASE_RESPONSE_MAGIC);
    response.push(DATABASE_VERSION);
    response.push(0);
    push_u16(response, 0);
    push_u64(response, envelope.snapshot);
    push_u64(response, 0);

    let mut digest = Digest64::new();
    let row_count = execute_visit(connection, query, |id, owner, score, updated_at, title| {
        update_row_digest(&mut digest, id, owner, score, updated_at, title);
        push_u32(response, id);
        push_u16(response, owner);
        push_u16(response, score);
        push_u64(response, updated_at);
        let title_length = u8::try_from(title.len())
            .map_err(|_| "database title exceeds binary frame limit".to_string())?;
        response.push(title_length);
        response.extend_from_slice(title.as_bytes());
        Ok(())
    })?;
    let row_count = u16::try_from(row_count).map_err(|_| "row count overflow".to_string())?;
    let result_digest = digest.finish();
    response[6..8].copy_from_slice(&row_count.to_le_bytes());
    response[16..24].copy_from_slice(&result_digest.to_le_bytes());
    append_crc32(response);

    let receipt = inspect_wire_response(response)?;
    Ok(Observation {
        response_bytes: response.len(),
        semantic_digest: receipt.result_digest,
        view_digest: receipt.result_digest,
        rendered_bytes: 0,
    })
}

fn process_tuned_fast(
    connection: &mut Database,
    request: &[u8],
    executions: &mut u64,
    response: &mut Vec<u8>,
) -> Result<Observation, String> {
    let (query, envelope) = decode_request(DbArm::PreparedJson, request)?;
    validate_envelope(envelope, usize::from(query.limit))?;
    *executions = executions.saturating_add(1);

    response.clear();
    response.extend_from_slice(b"{\"r\":[");
    let mut first = true;
    let mut digest = Digest64::new();
    let row_count = execute_visit(connection, query, |id, owner, score, updated_at, title| {
        write_tuned_row(response, &mut first, id, owner, score, updated_at, title)?;
        update_row_digest(&mut digest, id, owner, score, updated_at, title);
        Ok(())
    })?;
    let receipt = DbReceipt {
        snapshot: envelope.snapshot,
        row_count: u16::try_from(row_count).map_err(|_| "row count overflow".to_string())?,
        result_digest: digest.finish(),
    };
    finish_tuned_response(response, receipt)?;

    let receipt = inspect_tuned_response(response)?;
    Ok(Observation {
        response_bytes: response.len(),
        semantic_digest: receipt.result_digest,
        view_digest: receipt.result_digest,
        rendered_bytes: 0,
    })
}

fn process_local_fast(
    connection: &mut Database,
    query: DbQuery,
    envelope: Envelope,
    executions: &mut u64,
) -> Result<Observation, String> {
    validate_envelope(envelope, usize::from(query.limit))?;
    *executions = executions.saturating_add(1);
    let mut digest = Digest64::new();
    let row_count = execute_visit(connection, query, |id, owner, score, updated_at, title| {
        update_row_digest(&mut digest, id, owner, score, updated_at, title);
        Ok(())
    })?;
    let _receipt = DbReceipt {
        snapshot: envelope.snapshot,
        row_count: u16::try_from(row_count).map_err(|_| "row count overflow".to_string())?,
        result_digest: digest.finish(),
    };
    Ok(Observation {
        response_bytes: 0,
        semantic_digest: _receipt.result_digest,
        view_digest: _receipt.result_digest,
        rendered_bytes: 0,
    })
}

fn execute(connection: &mut Database, query: DbQuery, cached: bool) -> Result<Vec<DbRow>, String> {
    connection.query_rows(
        SQL,
        [
            i64::from(crate::wire::EXPECTED_TENANT),
            i64::from(query.owner),
            i64::from(query.min_score),
            i64::from(query.limit),
        ],
        cached,
    )
}

fn execute_visit<F>(connection: &mut Database, query: DbQuery, visitor: F) -> Result<usize, String>
where
    F: FnMut(u32, u16, u16, u64, &str) -> Result<(), String>,
{
    connection.query_rows_visit(
        SQL,
        [
            i64::from(crate::wire::EXPECTED_TENANT),
            i64::from(query.owner),
            i64::from(query.min_score),
            i64::from(query.limit),
        ],
        true,
        visitor,
    )
}

fn digest_rows(rows: &[DbRow]) -> u64 {
    let mut digest = Digest64::new();
    for row in rows {
        update_row_digest(
            &mut digest,
            row.id,
            row.owner,
            row.score,
            row.updated_at,
            &row.title,
        );
    }
    digest.finish()
}

fn update_row_digest(
    digest: &mut Digest64,
    id: u32,
    owner: u16,
    score: u16,
    updated_at: u64,
    title: &str,
) {
    digest.update_u32(id);
    digest.update_u16(owner);
    digest.update_u16(score);
    digest.update_u64(updated_at);
    digest.update_u16(u16::try_from(title.len()).unwrap_or(u16::MAX));
    digest.update(title.as_bytes());
}

fn inspect_wire_response(bytes: &[u8]) -> Result<DbReceipt, String> {
    let body = verify_crc32(bytes)?;
    let mut reader = Reader::new(body);
    if reader.take(4)? != DATABASE_RESPONSE_MAGIC {
        return Err("database response magic does not match".to_string());
    }
    if reader.u8()? != DATABASE_VERSION || reader.u8()? != 0 {
        return Err("database response version or flags do not match".to_string());
    }
    let row_count = reader.u16()?;
    let snapshot = reader.u64()?;
    let result_digest = reader.u64()?;
    let mut digest = Digest64::new();
    for _ in 0..row_count {
        let id = reader.u32()?;
        let owner = reader.u16()?;
        let score = reader.u16()?;
        let updated_at = reader.u64()?;
        let title_length = usize::from(reader.u8()?);
        let title =
            std::str::from_utf8(reader.take(title_length)?).map_err(|error| error.to_string())?;
        update_row_digest(&mut digest, id, owner, score, updated_at, title);
    }
    if reader.remaining() != 0 {
        return Err("database response has trailing bytes".to_string());
    }
    if digest.finish() != result_digest {
        return Err("database response digest does not match".to_string());
    }
    Ok(DbReceipt {
        snapshot,
        row_count,
        result_digest,
    })
}

fn encode_wire_rows_into(
    response: &mut Vec<u8>,
    rows: &[DbRow],
    receipt: DbReceipt,
) -> Result<(), String> {
    response.clear();
    response.extend_from_slice(DATABASE_RESPONSE_MAGIC);
    response.push(DATABASE_VERSION);
    response.push(0);
    push_u16(response, receipt.row_count);
    push_u64(response, receipt.snapshot);
    push_u64(response, receipt.result_digest);
    for row in rows {
        push_u32(response, row.id);
        push_u16(response, row.owner);
        push_u16(response, row.score);
        push_u64(response, row.updated_at);
        let title_length = u8::try_from(row.title.len())
            .map_err(|_| "database title exceeds binary frame limit".to_string())?;
        response.push(title_length);
        response.extend_from_slice(row.title.as_bytes());
    }
    append_crc32(response);
    Ok(())
}

fn encode_tuned_rows_into(
    response: &mut Vec<u8>,
    rows: &[DbRow],
    receipt: DbReceipt,
) -> Result<(), String> {
    response.clear();
    response.extend_from_slice(b"{\"r\":[");
    let mut first = true;
    for row in rows {
        write_tuned_row(
            response,
            &mut first,
            row.id,
            row.owner,
            row.score,
            row.updated_at,
            &row.title,
        )?;
    }
    finish_tuned_response(response, receipt)
}

fn write_tuned_row(
    response: &mut Vec<u8>,
    first: &mut bool,
    id: u32,
    owner: u16,
    score: u16,
    updated_at: u64,
    title: &str,
) -> Result<(), String> {
    if !*first {
        response.push(b',');
    }
    *first = false;
    write!(response, "[{id},{owner},{score},{updated_at},").map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut *response, title).map_err(|error| error.to_string())?;
    response.push(b']');
    Ok(())
}

fn finish_tuned_response(response: &mut Vec<u8>, receipt: DbReceipt) -> Result<(), String> {
    write!(
        response,
        "],\"x\":[{},{},\"{:016x}\"]}}",
        receipt.snapshot, receipt.row_count, receipt.result_digest
    )
    .map_err(|error| error.to_string())
}

fn inspect_tuned_response(bytes: &[u8]) -> Result<DbReceipt, String> {
    let response: CompactResponseScan<'_> =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let result_digest =
        u64::from_str_radix(response.receipt.2, 16).map_err(|error| error.to_string())?;
    if response.rows.row_count != response.receipt.1 {
        return Err("database response row count does not match".to_string());
    }
    if response.rows.result_digest != result_digest {
        return Err("database response digest does not match".to_string());
    }
    Ok(DbReceipt {
        snapshot: response.receipt.0,
        row_count: response.receipt.1,
        result_digest,
    })
}

fn encode_response(arm: DbArm, rows: &[DbRow], receipt: DbReceipt) -> Result<Vec<u8>, String> {
    match arm {
        DbArm::SqlJson => serde_json::to_vec(&VerboseResponse {
            rows: rows.to_vec(),
            receipt: VerboseReceipt {
                snapshot: receipt.snapshot,
                rows_returned: receipt.row_count,
                result_digest: format!("{:016x}", receipt.result_digest),
            },
        })
        .map_err(|error| error.to_string()),
        DbArm::PreparedJson => serde_json::to_vec(&CompactResponse {
            rows: rows
                .iter()
                .map(|row| {
                    (
                        row.id,
                        row.owner,
                        row.score,
                        row.updated_at,
                        row.title.clone(),
                    )
                })
                .collect(),
            receipt: (
                receipt.snapshot,
                receipt.row_count,
                format!("{:016x}", receipt.result_digest),
            ),
        })
        .map_err(|error| error.to_string()),
        DbArm::NdabiWire => {
            let mut bytes = Vec::with_capacity(32 + rows.len() * 32);
            bytes.extend_from_slice(DATABASE_RESPONSE_MAGIC);
            bytes.push(DATABASE_VERSION);
            bytes.push(0);
            push_u16(&mut bytes, receipt.row_count);
            push_u64(&mut bytes, receipt.snapshot);
            push_u64(&mut bytes, receipt.result_digest);
            for row in rows {
                push_u32(&mut bytes, row.id);
                push_u16(&mut bytes, row.owner);
                push_u16(&mut bytes, row.score);
                push_u64(&mut bytes, row.updated_at);
                let title_length = u8::try_from(row.title.len())
                    .map_err(|_| "database title exceeds binary frame limit".to_string())?;
                bytes.push(title_length);
                bytes.extend_from_slice(row.title.as_bytes());
            }
            append_crc32(&mut bytes);
            Ok(bytes)
        }
        DbArm::NdabiLocal => Ok(Vec::new()),
    }
}

fn decode_response(arm: DbArm, bytes: &[u8]) -> Result<(Vec<DbRow>, DbReceipt), String> {
    let (rows, receipt) = match arm {
        DbArm::SqlJson => {
            let response: VerboseResponse =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            (
                response.rows,
                DbReceipt {
                    snapshot: response.receipt.snapshot,
                    row_count: response.receipt.rows_returned,
                    result_digest: u64::from_str_radix(&response.receipt.result_digest, 16)
                        .map_err(|error| error.to_string())?,
                },
            )
        }
        DbArm::PreparedJson => {
            let response: CompactResponse =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            (
                response
                    .rows
                    .into_iter()
                    .map(|row| DbRow {
                        id: row.0,
                        owner: row.1,
                        score: row.2,
                        updated_at: row.3,
                        title: row.4,
                    })
                    .collect(),
                DbReceipt {
                    snapshot: response.receipt.0,
                    row_count: response.receipt.1,
                    result_digest: u64::from_str_radix(&response.receipt.2, 16)
                        .map_err(|error| error.to_string())?,
                },
            )
        }
        DbArm::NdabiWire => {
            let body = verify_crc32(bytes)?;
            let mut reader = Reader::new(body);
            if reader.take(4)? != DATABASE_RESPONSE_MAGIC {
                return Err("database response magic does not match".to_string());
            }
            if reader.u8()? != DATABASE_VERSION || reader.u8()? != 0 {
                return Err("database response version or flags do not match".to_string());
            }
            let row_count = reader.u16()?;
            let snapshot = reader.u64()?;
            let result_digest = reader.u64()?;
            let mut rows = Vec::with_capacity(usize::from(row_count));
            for _ in 0..row_count {
                let id = reader.u32()?;
                let owner = reader.u16()?;
                let score = reader.u16()?;
                let updated_at = reader.u64()?;
                let title_length = usize::from(reader.u8()?);
                let title = std::str::from_utf8(reader.take(title_length)?)
                    .map_err(|error| error.to_string())?
                    .to_string();
                rows.push(DbRow {
                    id,
                    owner,
                    score,
                    updated_at,
                    title,
                });
            }
            if reader.remaining() != 0 {
                return Err("database response has trailing bytes".to_string());
            }
            let receipt = DbReceipt {
                snapshot,
                row_count,
                result_digest,
            };
            (rows, receipt)
        }
        DbArm::NdabiLocal => return Err("NDABI local has no wire response".to_string()),
    };
    if rows.len() != usize::from(receipt.row_count) {
        return Err("database response row count does not match".to_string());
    }
    if digest_rows(&rows) != receipt.result_digest {
        return Err("database response digest does not match".to_string());
    }
    Ok((rows, receipt))
}

fn disassemble_request(bytes: &[u8]) -> Result<String, String> {
    let (query, envelope) = decode_request(DbArm::NdabiWire, bytes)?;
    Ok(format!(
        "v1 EXECUTE_HANDLE handle={QUERY_HANDLE} principal={} purpose={} tenant={} snapshot={} max_rows={} deadline={} nonce={} owner={} min_score={} limit={}",
        envelope.principal,
        envelope.purpose,
        envelope.tenant,
        envelope.snapshot,
        envelope.max_items,
        envelope.deadline,
        envelope.nonce,
        query.owner,
        query.min_score,
        query.limit
    ))
}

fn refusal_suite(row_count: usize, query: DbQuery) -> Result<(u32, u32, u64), String> {
    let mut passed = 0;
    let mut total = 0;
    let mut refused_executions = 0;
    for arm in [DbArm::SqlJson, DbArm::PreparedJson, DbArm::NdabiWire] {
        let mut cases = Vec::new();

        let mut wrong_principal = Envelope::valid(32);
        wrong_principal.principal ^= 1;
        cases.push(encode_request(arm, query, wrong_principal)?);

        let mut expired = Envelope::valid(32);
        expired.deadline = crate::wire::REFERENCE_NOW - 1;
        cases.push(encode_request(arm, query, expired)?);

        let excessive = DbQuery { limit: 33, ..query };
        cases.push(encode_request(arm, excessive, Envelope::valid(32))?);

        cases.push(match arm {
            DbArm::NdabiWire => vec![0x4e, 0x44, 0x41],
            DbArm::NdabiLocal => unreachable!("local commands are tested separately"),
            _ => b"{".to_vec(),
        });

        let mut connection = fixture(row_count)?;
        for case in cases {
            total += 1;
            let before = refused_executions;
            if process(&mut connection, arm, &case, &mut refused_executions).is_err() {
                passed += 1;
            }
            if refused_executions != before {
                return Err("a refused database request reached execution".to_string());
            }
        }
    }
    let local_cases = [
        (query, {
            let mut envelope = Envelope::valid(32);
            envelope.principal ^= 1;
            envelope
        }),
        (query, {
            let mut envelope = Envelope::valid(32);
            envelope.deadline = crate::wire::REFERENCE_NOW - 1;
            envelope
        }),
        (DbQuery { limit: 33, ..query }, Envelope::valid(32)),
    ];
    let mut connection = fixture(row_count)?;
    for (local_query, local_envelope) in local_cases {
        total += 1;
        let before = refused_executions;
        if process_local(
            &mut connection,
            local_query,
            local_envelope,
            &mut refused_executions,
        )
        .is_err()
        {
            passed += 1;
        }
        if refused_executions != before {
            return Err("a refused local database command reached execution".to_string());
        }
    }
    Ok((passed, total, refused_executions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_database_arms_produce_the_same_rows() {
        let evidence = run(1_024, 40, 2).expect("database benchmark");
        assert!(evidence.semantic_results_equal);
        assert!(evidence.trusted_envelopes_equal);
        assert!(evidence.receipts_verified);
        assert_eq!(evidence.refusals_passed, evidence.refusals_total);
        assert_eq!(evidence.refused_database_executions, 0);
    }

    #[test]
    fn binary_database_request_round_trips() {
        let query = DbQuery::fixed();
        let envelope = Envelope::valid(32);
        let encoded = encode_request(DbArm::NdabiWire, query, envelope).expect("encode");
        assert_eq!(
            decode_request(DbArm::NdabiWire, &encoded).expect("decode"),
            (query, envelope)
        );
    }

    #[test]
    fn all_database_response_arms_verify_the_result_digest() {
        let rows = vec![DbRow {
            id: 1,
            owner: 7,
            score: 900,
            updated_at: 1_700_000_017,
            title: "decision-stream-00001".to_string(),
        }];
        let receipt = DbReceipt {
            snapshot: Envelope::valid(32).snapshot,
            row_count: 1,
            result_digest: digest_rows(&rows) ^ 1,
        };
        for arm in [DbArm::SqlJson, DbArm::PreparedJson, DbArm::NdabiWire] {
            let encoded = encode_response(arm, &rows, receipt).expect("encode response");
            assert_eq!(
                decode_response(arm, &encoded).expect_err("wrong digest must refuse"),
                "database response digest does not match"
            );
        }
    }

    #[test]
    fn tuned_database_fast_path_preserves_the_json_contract() {
        let rows = vec![DbRow {
            id: 1,
            owner: 7,
            score: 900,
            updated_at: 1_700_000_017,
            title: "decision \"stream\"".to_string(),
        }];
        let receipt = DbReceipt {
            snapshot: Envelope::valid(32).snapshot,
            row_count: 1,
            result_digest: digest_rows(&rows),
        };
        let expected = encode_response(DbArm::PreparedJson, &rows, receipt).expect("reference");
        let mut actual = Vec::new();
        encode_tuned_rows_into(&mut actual, &rows, receipt).expect("fast encode");
        assert_eq!(actual, expected);
        assert_eq!(
            inspect_tuned_response(&actual).expect("fast inspect"),
            receipt
        );
    }
}
