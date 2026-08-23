//! Generate deterministic NDABI RFC-candidate conformance vectors.
//!
//! Every key and identity in this executable is public test material.

use std::cell::Cell;

use ndabi_protocol::{
    batch_frame_bytes, Authority, AuthorityContext, Backend, BackendIdentity, BatchBackend,
    BatchItem, BatchItems, BatchOperation, BoundedOutput, ClientSession, Clock, ExecutionLimits,
    MemoryReplayStore, Operation, ProtocolError, ServerSession,
};
use serde_json::{json, Value};
use zeroize::Zeroize;

const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 2_000_000;
const EXPIRY: u64 = 4_102_444_800_000_000;
const GENERATION: u64 = 0x0102_0304_0506_0708;
const SESSION: u64 = 0x1112_1314_1516_1718;
const ROOT_KEY: [u8; 32] = sequence::<32>(0x00);
const TENANT: [u8; 16] = sequence::<16>(0x10);
const PRINCIPAL: [u8; 16] = sequence::<16>(0x20);
const CAPABILITY: [u8; 32] = sequence::<32>(0x40);
const SCHEMA: [u8; 32] = sequence::<32>(0x60);
const POLICY: [u8; 32] = sequence::<32>(0x80);
const PLAN: [u8; 32] = sequence::<32>(0xa0);
const PURPOSE: u32 = 0x0102_0304;
const ENGINE: u32 = 0x1122_3344;
const PROFILE: u32 = 0x5566_7788;
const RESULT_BUDGET: u32 = 4_096;
const ROW_BUDGET: u32 = 16;
const FRAME_KEY_DOMAIN: &[u8] = b"ndabi/wire/v1/session-key";
const SINGLE_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v1/frame";
const BATCH_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v1/batch-frame";

const fn sequence<const N: usize>(start: u8) -> [u8; N] {
    let mut output = [0_u8; N];
    let mut index = 0;
    while index < N {
        output[index] = start.wrapping_add(index as u8);
        index += 1;
    }
    output
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let identity = BackendIdentity::new(ENGINE, PROFILE, SCHEMA, POLICY, PLAN)
        .map_err(|error| error.to_string())?;
    let context = AuthorityContext::new(TENANT, PRINCIPAL, PURPOSE, CAPABILITY, identity)
        .map_err(|error| error.to_string())?;
    let context_digest = context.digest();
    let authority = Authority::new_read(ROOT_KEY, GENERATION, SESSION, EXPIRY, context)
        .map_err(|error| error.to_string())?;
    let operation = Operation::new(
        0x1112,
        0x1314_1516,
        0x1718_191a,
        -1_234_567_890,
        987_654_321,
        0x1b1c_1d1e,
    )
    .map_err(|error| error.to_string())?;
    let batch_operation =
        BatchOperation::new(0x2122, 0x2324_2526, 0x2728_292a).map_err(|error| error.to_string())?;
    let batch_items = [
        BatchItem::new(-1, 2, 3),
        BatchItem::new(4, -5, 6),
        BatchItem::new(7, 8, 9),
    ];

    let mut single_client = ClientSession::new(authority.clone());
    let single_frame = single_client
        .encode(operation, RESULT_BUDGET, ROW_BUDGET, DEADLINE)
        .map_err(|error| error.to_string())?;
    let mut batch_client = ClientSession::new(authority.clone());
    let mut batch_frame =
        vec![0; batch_frame_bytes(batch_items.len()).map_err(|error| error.to_string())?];
    batch_client
        .encode_batch_into(
            batch_operation,
            &batch_items,
            RESULT_BUDGET,
            ROW_BUDGET,
            DEADLINE,
            &mut batch_frame,
        )
        .map_err(|error| error.to_string())?;

    let server = ServerSession::new(authority.clone(), RESULT_BUDGET, ROW_BUDGET)
        .map_err(|error| error.to_string())?;
    let mut single_backend = SingleBackend { identity };
    let single_execution = server
        .execute(
            &single_frame,
            &mut single_backend,
            &mut MemoryReplayStore::default(),
            &FixedClock::new(),
        )
        .map_err(|error| error.to_string())?;
    let mut batch_backend = FusedBatchBackend {
        identity,
        expected: batch_items,
    };
    let batch_execution = server
        .execute_batch(
            &batch_frame,
            &mut batch_backend,
            &mut MemoryReplayStore::default(),
            &FixedClock::new(),
        )
        .map_err(|error| error.to_string())?;

    let mut single_tag_changed = single_frame.to_vec();
    single_tag_changed[159] ^= 1;
    let mut batch_operand_changed = batch_frame.clone();
    batch_operand_changed[128] ^= 1;
    let single_truncated = single_frame[..159].to_vec();
    let mut noncanonical_batch = batch_frame.clone();
    noncanonical_batch[76] = 1;
    retag(&mut noncanonical_batch, BATCH_FRAME_DOMAIN, &context_digest)?;
    let mut zero_operation = single_frame.to_vec();
    zero_operation[10..12].fill(0);
    retag(&mut zero_operation, SINGLE_FRAME_DOMAIN, &context_digest)?;
    let mut wrong_context = single_frame.to_vec();
    wrong_context[96] ^= 1;
    retag(&mut wrong_context, SINGLE_FRAME_DOMAIN, &context_digest)?;
    let mut expired = single_frame.to_vec();
    expired[40..48].copy_from_slice(&NOW.to_le_bytes());
    retag(&mut expired, SINGLE_FRAME_DOMAIN, &context_digest)?;

    verify_manifest_cases(
        &server,
        identity,
        &batch_items,
        &single_frame,
        &batch_frame,
        [
            (&single_tag_changed, ProtocolError::AuthenticationFailed),
            (&single_truncated, ProtocolError::LengthMismatch),
            (&zero_operation, ProtocolError::ZeroOperationField),
            (&wrong_context, ProtocolError::AuthorityMismatch),
            (&expired, ProtocolError::Expired),
        ],
        [
            (&batch_operand_changed, ProtocolError::AuthenticationFailed),
            (&noncanonical_batch, ProtocolError::NonCanonicalFrame),
        ],
    )?;

    let manifest = json!({
        "schema": "ndabi-conformance-v0.1",
        "integer_encoding": "decimal-string-for-64-bit",
        "status": "RFC-candidate test vectors",
        "warning": "All keys and identities are public test material.",
        "clock_unix_us": NOW.to_string(),
        "server_limits": {
            "maximum_result_bytes": RESULT_BUDGET,
            "maximum_rows": ROW_BUDGET
        },
        "authority": {
            "root_key_hex": hex(&ROOT_KEY),
            "generation": GENERATION.to_string(),
            "session": SESSION.to_string(),
            "expires_unix_us": EXPIRY.to_string(),
            "tenant_hex": hex(&TENANT),
            "principal_hex": hex(&PRINCIPAL),
            "purpose": PURPOSE,
            "capability_digest_hex": hex(&CAPABILITY),
            "engine": ENGINE,
            "profile": PROFILE,
            "schema_digest_hex": hex(&SCHEMA),
            "policy_digest_hex": hex(&POLICY),
            "plan_digest_hex": hex(&PLAN),
            "context_digest_hex": hex(&context_digest)
        },
        "valid": [
            {
                "id": "execute-handle-read",
                "kind": "execute-handle",
                "frame_hex": hex(&single_frame),
                "decoded": {
                    "nonce": "1",
                    "deadline_unix_us": DEADLINE.to_string(),
                    "result_budget": RESULT_BUDGET,
                    "row_budget": ROW_BUDGET,
                    "operation": {
                        "opcode": operation.opcode,
                        "plan_handle": operation.plan_handle,
                        "result_shape": operation.result_shape,
                        "first": operation.first.to_string(),
                        "second": operation.second.to_string(),
                        "third": operation.third
                    }
                },
                "result_hex": hex(&single_execution.bytes),
                "rows": single_execution.rows,
                "receipt_hex": hex(&single_execution.receipt)
            },
            {
                "id": "execute-batch-handle-read",
                "kind": "execute-batch-handle",
                "frame_hex": hex(&batch_frame),
                "decoded": {
                    "nonce": "1",
                    "deadline_unix_us": DEADLINE.to_string(),
                    "result_budget": RESULT_BUDGET,
                    "row_budget": ROW_BUDGET,
                    "operation": {
                        "opcode": batch_operation.opcode,
                        "plan_handle": batch_operation.plan_handle,
                        "result_shape": batch_operation.result_shape
                    },
                    "items": batch_items.iter().map(|item| json!({
                        "first": item.first.to_string(),
                        "second": item.second.to_string(),
                        "third": item.third
                    })).collect::<Vec<Value>>()
                },
                "result_hex": hex(&batch_execution.bytes),
                "rows": batch_execution.rows,
                "receipt_hex": hex(&batch_execution.receipt)
            }
        ],
        "invalid": [
            {
                "id": "single-tag-changed",
                "frame_hex": hex(&single_tag_changed),
                "expected_error": "AuthenticationFailed"
            },
            {
                "id": "batch-operand-changed",
                "frame_hex": hex(&batch_operand_changed),
                "expected_error": "AuthenticationFailed"
            },
            {
                "id": "single-truncated",
                "frame_hex": hex(&single_truncated),
                "expected_error": "LengthMismatch"
            },
            {
                "id": "batch-reserved-byte-set",
                "frame_hex": hex(&noncanonical_batch),
                "expected_error": "NonCanonicalFrame"
            },
            {
                "id": "single-zero-operation",
                "frame_hex": hex(&zero_operation),
                "expected_error": "ZeroOperationField"
            },
            {
                "id": "single-context-mismatch",
                "frame_hex": hex(&wrong_context),
                "expected_error": "AuthorityMismatch"
            },
            {
                "id": "single-expired",
                "frame_hex": hex(&expired),
                "expected_error": "Expired"
            }
        ],
        "sequences": [
            {
                "id": "single-replay",
                "frame_id": "execute-handle-read",
                "expected": ["Accepted", "Replay"]
            },
            {
                "id": "batch-replay",
                "frame_id": "execute-batch-handle-read",
                "expected": ["Accepted", "Replay"]
            }
        ]
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_manifest_cases<const S: usize, const B: usize>(
    server: &ServerSession,
    identity: BackendIdentity,
    batch_items: &[BatchItem; 3],
    single_frame: &[u8],
    batch_frame: &[u8],
    invalid_single: [(&[u8], ProtocolError); S],
    invalid_batch: [(&[u8], ProtocolError); B],
) -> Result<(), String> {
    for (frame, expected) in invalid_single {
        let mut backend = SingleBackend { identity };
        let actual = server
            .execute(
                frame,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &FixedClock::new(),
            )
            .expect_err("an invalid single vector must refuse");
        if actual != expected {
            return Err(format!(
                "the single vector returned {actual}, expected {expected}"
            ));
        }
    }
    for (frame, expected) in invalid_batch {
        let mut backend = FusedBatchBackend {
            identity,
            expected: *batch_items,
        };
        let actual = server
            .execute_batch(
                frame,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &FixedClock::new(),
            )
            .expect_err("an invalid batch vector must refuse");
        if actual != expected {
            return Err(format!(
                "the batch vector returned {actual}, expected {expected}"
            ));
        }
    }

    let mut single_replay = MemoryReplayStore::default();
    let mut single_backend = SingleBackend { identity };
    server
        .execute(
            single_frame,
            &mut single_backend,
            &mut single_replay,
            &FixedClock::new(),
        )
        .map_err(|error| error.to_string())?;
    let single_error = server
        .execute(
            single_frame,
            &mut single_backend,
            &mut single_replay,
            &FixedClock::new(),
        )
        .expect_err("the committed single nonce must refuse replay");
    if single_error != ProtocolError::Replay {
        return Err(format!("the single replay returned {single_error}"));
    }

    let mut batch_replay = MemoryReplayStore::default();
    let mut batch_backend = FusedBatchBackend {
        identity,
        expected: *batch_items,
    };
    server
        .execute_batch(
            batch_frame,
            &mut batch_backend,
            &mut batch_replay,
            &FixedClock::new(),
        )
        .map_err(|error| error.to_string())?;
    let batch_error = server
        .execute_batch(
            batch_frame,
            &mut batch_backend,
            &mut batch_replay,
            &FixedClock::new(),
        )
        .expect_err("the committed batch nonce must refuse replay");
    if batch_error != ProtocolError::Replay {
        return Err(format!("the batch replay returned {batch_error}"));
    }
    Ok(())
}

fn retag(frame: &mut [u8], domain: &[u8], context_digest: &[u8; 32]) -> Result<(), String> {
    let mut derived = blake3::Hasher::new_keyed(&ROOT_KEY);
    derived.update(FRAME_KEY_DOMAIN);
    derived.update(&GENERATION.to_le_bytes());
    derived.update(&SESSION.to_le_bytes());
    derived.update(&EXPIRY.to_le_bytes());
    derived.update(context_digest);
    let mut frame_key = *derived.finalize().as_bytes();
    derived.zeroize();
    let mut tag = blake3::Hasher::new_keyed(&frame_key);
    tag.update(domain);
    let tag_offset = frame
        .len()
        .checked_sub(32)
        .ok_or_else(|| "the frame is too short".to_string())?;
    tag.update(&frame[..tag_offset]);
    let mut digest = *tag.finalize().as_bytes();
    tag.zeroize();
    frame[tag_offset..].copy_from_slice(&digest);
    frame_key.zeroize();
    digest.zeroize();
    Ok(())
}

struct FixedClock {
    calls: Cell<u32>,
}

impl FixedClock {
    fn new() -> Self {
        Self {
            calls: Cell::new(0),
        }
    }
}

impl Clock for FixedClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        self.calls.set(self.calls.get() + 1);
        Ok(NOW)
    }
}

struct SingleBackend {
    identity: BackendIdentity,
}

impl Backend for SingleBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute(
        &mut self,
        _operation: Operation,
        _limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        output.write(&[0xde, 0xad, 0xbe, 0xef])?;
        output.complete_row()
    }
}

struct FusedBatchBackend {
    identity: BackendIdentity,
    expected: [BatchItem; 3],
}

impl BatchBackend for FusedBatchBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_batch(
        &mut self,
        _operation: BatchOperation,
        items: BatchItems<'_>,
        _limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        if items.collect::<Vec<_>>() != self.expected {
            return Err(ProtocolError::BackendRefused);
        }
        output.write(&[0xba, 0xdc, 0x0f, 0xfe, 0xe0, 0xdd, 0xf0, 0x0d])?;
        for _ in 0..self.expected.len() {
            output.complete_row()?;
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("string writes cannot fail");
    }
    output
}
