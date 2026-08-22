//! Execute a finite NDABI read profile through caller-supplied PostgreSQL plans.
//!
//! Agent frames cannot contain SQL or write opcodes. The profile owner controls trusted prepared SQL.
//! The database connection must enforce the profile owner's read-only authority.
//! The adapter authenticates each frame before it decodes an operation or executes a backend.

use std::fmt;

use postgres::{Client, Row, Statement};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const FRAME_BYTES: usize = 76;
const AUTHENTICATED_BYTES: usize = 60;
const TAG_BYTES: usize = 16;
const MAGIC: [u8; 4] = *b"NDA2";
const VERSION: u8 = 1;
const READ_FLAGS: u16 = 0b0101;
const RECEIPT_DOMAIN: &[u8] = b"ndabi/postgresql/receipt/v2";
const KEY_DOMAIN: &[u8] = b"ndabi/postgresql/session/v2";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub enum ReadOperation {
    Range { start: i64, count: u32 },
    Predicate {
        bucket: i32,
        minimum_score: i32,
        limit: u32,
    },
    Aggregate { minimum_score: i32 },
    Join { owner: i32, limit: u32 },
}

impl ReadOperation {
    pub fn result_limit(self) -> u32 {
        match self {
            Self::Range { count, .. } => count,
            Self::Predicate { limit, .. } | Self::Join { limit, .. } => limit,
            Self::Aggregate { .. } => 1_024,
        }
    }

    fn opcode(self) -> u8 {
        match self {
            Self::Range { .. } => 1,
            Self::Predicate { .. } => 2,
            Self::Aggregate { .. } => 3,
            Self::Join { .. } => 4,
        }
    }

    fn operands(self) -> (i64, i64, u32) {
        match self {
            Self::Range { start, count } => (start, 0, count),
            Self::Predicate {
                bucket,
                minimum_score,
                limit,
            } => (i64::from(bucket), i64::from(minimum_score), limit),
            Self::Aggregate { minimum_score } => (i64::from(minimum_score), 0, 0),
            Self::Join { owner, limit } => (i64::from(owner), 0, limit),
        }
    }
}

#[derive(Clone)]
pub struct Authority {
    generation: u64,
    session: u32,
    expires_unix_us: u64,
    capability: u32,
    schema: u32,
    plan: u32,
    key: Zeroizing<[u8; 32]>,
}

impl Authority {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root_key: [u8; 32],
        generation: u64,
        session: u32,
        expires_unix_us: u64,
        capability: u32,
        schema: u32,
        plan: u32,
    ) -> Result<Self, AdapterError> {
        if generation == 0 || session == 0 || expires_unix_us == 0 {
            return Err(AdapterError::new("the authority contains a zero identity"));
        }
        if capability == 0 || schema == 0 || plan == 0 {
            return Err(AdapterError::new("the authority contains a zero handle"));
        }
        if root_key.ct_eq(&[0; 32]).unwrap_u8() == 1 {
            return Err(AdapterError::new("the root key is zero"));
        }
        let mut derivation = blake3::Hasher::new_keyed(&root_key);
        derivation.update(KEY_DOMAIN);
        derivation.update(&generation.to_le_bytes());
        derivation.update(&session.to_le_bytes());
        derivation.update(&expires_unix_us.to_le_bytes());
        derivation.update(&capability.to_le_bytes());
        derivation.update(&schema.to_le_bytes());
        derivation.update(&plan.to_le_bytes());
        Ok(Self {
            generation,
            session,
            expires_unix_us,
            capability,
            schema,
            plan,
            key: Zeroizing::new(*derivation.finalize().as_bytes()),
        })
    }

    fn tag(&self, authenticated: &[u8]) -> [u8; TAG_BYTES] {
        let digest = blake3::keyed_hash(&self.key, authenticated);
        let mut tag = [0; TAG_BYTES];
        tag.copy_from_slice(&digest.as_bytes()[..TAG_BYTES]);
        tag
    }
}

pub struct ClientSession {
    authority: Authority,
    next_nonce: u64,
}

impl ClientSession {
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            next_nonce: 1,
        }
    }

    pub fn encode(
        &mut self,
        operation: ReadOperation,
        result_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<[u8; FRAME_BYTES], AdapterError> {
        validate_operation(operation)?;
        if result_budget == 0 {
            return Err(AdapterError::new("the result budget is zero"));
        }
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(AdapterError::new("the frame deadline exceeds the authority"));
        }
        let nonce = self.next_nonce;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or_else(|| AdapterError::new("the client nonce space ended"))?;
        let (first, second, third) = operation.operands();
        let mut frame = [0; FRAME_BYTES];
        frame[0..4].copy_from_slice(&MAGIC);
        frame[4] = VERSION;
        frame[5] = operation.opcode();
        frame[6..8].copy_from_slice(&READ_FLAGS.to_le_bytes());
        frame[8..12].copy_from_slice(&self.authority.session.to_le_bytes());
        frame[12..20].copy_from_slice(&self.authority.generation.to_le_bytes());
        frame[20..28].copy_from_slice(&nonce.to_le_bytes());
        frame[28..36].copy_from_slice(&deadline_unix_us.to_le_bytes());
        frame[36..40].copy_from_slice(&result_budget.to_le_bytes());
        frame[40..48].copy_from_slice(&first.to_le_bytes());
        frame[48..56].copy_from_slice(&second.to_le_bytes());
        frame[56..60].copy_from_slice(&third.to_le_bytes());
        let tag = self.authority.tag(&frame[..AUTHENTICATED_BYTES]);
        frame[AUTHENTICATED_BYTES..].copy_from_slice(&tag);
        Ok(frame)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pending {
    nonce: u64,
    operation: ReadOperation,
    result_budget: u32,
    frame_digest: [u8; 32],
}

pub struct ServerSession {
    authority: Authority,
    next_nonce: u64,
    maximum_result_bytes: u32,
}

impl ServerSession {
    pub fn new(authority: Authority, maximum_result_bytes: u32) -> Result<Self, AdapterError> {
        if maximum_result_bytes == 0 {
            return Err(AdapterError::new("the maximum result budget is zero"));
        }
        Ok(Self {
            authority,
            next_nonce: 1,
            maximum_result_bytes,
        })
    }

    pub fn execute<B: Backend>(
        &mut self,
        frame: &[u8],
        now_unix_us: u64,
        backend: &mut B,
    ) -> Result<Execution, AdapterError> {
        let pending = self.verify_pending(frame, now_unix_us)?;
        let bytes = backend.execute(pending.operation)?;
        if bytes.len() > pending.result_budget as usize {
            return Err(AdapterError::new("the result exceeded the authenticated budget"));
        }
        self.commit(pending)?;
        let receipt = receipt(
            &self.authority,
            pending.nonce,
            pending.frame_digest,
            &bytes,
        );
        Ok(Execution {
            operation: pending.operation,
            bytes,
            receipt,
        })
    }

    fn verify_pending(&self, frame: &[u8], now_unix_us: u64) -> Result<Pending, AdapterError> {
        if frame.len() != FRAME_BYTES {
            return Err(AdapterError::new("the frame length is invalid"));
        }
        let expected_tag = self.authority.tag(&frame[..AUTHENTICATED_BYTES]);
        if expected_tag
            .ct_eq(&frame[AUTHENTICATED_BYTES..])
            .unwrap_u8()
            != 1
        {
            return Err(AdapterError::new("the frame authentication failed"));
        }
        if frame[0..4] != MAGIC
            || frame[4] != VERSION
            || get_u16(frame, 6) != READ_FLAGS
            || get_u32(frame, 8) != self.authority.session
            || get_u64(frame, 12) != self.authority.generation
        {
            return Err(AdapterError::new("the frame authority is invalid"));
        }
        let nonce = get_u64(frame, 20);
        let deadline = get_u64(frame, 28);
        let result_budget = get_u32(frame, 36);
        if nonce != self.next_nonce {
            return Err(AdapterError::new("the frame nonce is stale"));
        }
        if now_unix_us >= deadline || deadline > self.authority.expires_unix_us {
            return Err(AdapterError::new("the frame deadline is invalid"));
        }
        if result_budget == 0 || result_budget > self.maximum_result_bytes {
            return Err(AdapterError::new("the frame result budget is invalid"));
        }
        let operation = decode_operation(frame)?;
        validate_operation(operation)?;
        Ok(Pending {
            nonce,
            operation,
            result_budget,
            frame_digest: Sha256::digest(frame).into(),
        })
    }

    fn commit(&mut self, pending: Pending) -> Result<(), AdapterError> {
        if pending.nonce != self.next_nonce {
            return Err(AdapterError::new("the pending execution is stale"));
        }
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or_else(|| AdapterError::new("the server nonce space ended"))?;
        Ok(())
    }
}

fn decode_operation(frame: &[u8]) -> Result<ReadOperation, AdapterError> {
    let first = get_i64(frame, 40);
    let second = get_i64(frame, 48);
    let third = get_u32(frame, 56);
    match frame[5] {
        1 if second == 0 => Ok(ReadOperation::Range {
            start: first,
            count: third,
        }),
        2 => Ok(ReadOperation::Predicate {
            bucket: i32::try_from(first)
                .map_err(|_| AdapterError::new("the predicate bucket is invalid"))?,
            minimum_score: i32::try_from(second)
                .map_err(|_| AdapterError::new("the predicate score is invalid"))?,
            limit: third,
        }),
        3 if second == 0 && third == 0 => Ok(ReadOperation::Aggregate {
            minimum_score: i32::try_from(first)
                .map_err(|_| AdapterError::new("the aggregate score is invalid"))?,
        }),
        4 if second == 0 => Ok(ReadOperation::Join {
            owner: i32::try_from(first)
                .map_err(|_| AdapterError::new("the join owner is invalid"))?,
            limit: third,
        }),
        _ => Err(AdapterError::new("the operation is unsupported")),
    }
}

fn validate_operation(operation: ReadOperation) -> Result<(), AdapterError> {
    match operation {
        ReadOperation::Range { start, count } => {
            let end = start.checked_add(i64::from(count.saturating_sub(1)));
            if start < 0 || count == 0 || count > 4_096 || end.is_none() {
                return Err(AdapterError::new("the range operation exceeds its profile"));
            }
        }
        ReadOperation::Predicate {
            bucket,
            minimum_score,
            limit,
        } => {
            if !(0..1_024).contains(&bucket)
                || !(0..10_000).contains(&minimum_score)
                || limit == 0
                || limit > 256
            {
                return Err(AdapterError::new("the predicate operation exceeds its profile"));
            }
        }
        ReadOperation::Aggregate { minimum_score } => {
            if !(0..10_000).contains(&minimum_score) {
                return Err(AdapterError::new("the aggregate operation exceeds its profile"));
            }
        }
        ReadOperation::Join { owner, limit } => {
            if !(0..4_096).contains(&owner) || limit == 0 || limit > 256 {
                return Err(AdapterError::new("the join operation exceeds its profile"));
            }
        }
    }
    Ok(())
}

pub trait Backend {
    fn execute(&mut self, operation: ReadOperation) -> Result<Vec<u8>, AdapterError>;
}

#[derive(Clone, Copy)]
pub struct ProfileSql {
    pub range: &'static str,
    pub predicate: &'static str,
    pub aggregate: &'static str,
    pub join: &'static str,
}

pub struct PostgresBackend {
    client: Client,
    range: Statement,
    predicate: Statement,
    aggregate: Statement,
    join: Statement,
}

impl PostgresBackend {
    pub fn new(mut client: Client, sql: ProfileSql) -> Result<Self, AdapterError> {
        let range = client
            .prepare(sql.range)
            .map_err(|_| AdapterError::new("the range plan preparation failed"))?;
        let predicate = client
            .prepare(sql.predicate)
            .map_err(|_| AdapterError::new("the predicate plan preparation failed"))?;
        let aggregate = client
            .prepare(sql.aggregate)
            .map_err(|_| AdapterError::new("the aggregate plan preparation failed"))?;
        let join = client
            .prepare(sql.join)
            .map_err(|_| AdapterError::new("the join plan preparation failed"))?;
        Ok(Self {
            client,
            range,
            predicate,
            aggregate,
            join,
        })
    }
}

impl Backend for PostgresBackend {
    fn execute(&mut self, operation: ReadOperation) -> Result<Vec<u8>, AdapterError> {
        match operation {
            ReadOperation::Range { start, count } => {
                let ids: Vec<i64> = (0..i64::from(count)).map(|offset| start + offset).collect();
                let rows = self
                    .client
                    .query(&self.range, &[&ids])
                    .map_err(|_| AdapterError::new("the range execution failed"))?;
                encode_items(operation.opcode(), &rows)
            }
            ReadOperation::Predicate {
                bucket,
                minimum_score,
                limit,
            } => {
                let limit = i64::from(limit);
                let rows = self
                    .client
                    .query(&self.predicate, &[&bucket, &minimum_score, &limit])
                    .map_err(|_| AdapterError::new("the predicate execution failed"))?;
                encode_items(operation.opcode(), &rows)
            }
            ReadOperation::Aggregate { minimum_score } => {
                let rows = self
                    .client
                    .query(&self.aggregate, &[&minimum_score])
                    .map_err(|_| AdapterError::new("the aggregate execution failed"))?;
                encode_aggregates(operation.opcode(), &rows)
            }
            ReadOperation::Join { owner, limit } => {
                let limit = i64::from(limit);
                let rows = self
                    .client
                    .query(&self.join, &[&owner, &limit])
                    .map_err(|_| AdapterError::new("the join execution failed"))?;
                encode_joins(operation.opcode(), &rows)
            }
        }
    }
}

fn output_prefix(opcode: u8, rows: usize) -> Result<Vec<u8>, AdapterError> {
    let rows = u32::try_from(rows).map_err(|_| AdapterError::new("the row count is excessive"))?;
    let mut output = Vec::new();
    output.push(opcode);
    output.extend_from_slice(&rows.to_le_bytes());
    Ok(output)
}

fn encode_items(opcode: u8, rows: &[Row]) -> Result<Vec<u8>, AdapterError> {
    let mut output = output_prefix(opcode, rows.len())?;
    output.reserve(rows.len() * 88);
    for row in rows {
        let id: i64 = row
            .try_get(0)
            .map_err(|_| AdapterError::new("the item identifier type is invalid"))?;
        let bucket: i32 = row
            .try_get(1)
            .map_err(|_| AdapterError::new("the item bucket type is invalid"))?;
        let owner: i32 = row
            .try_get(2)
            .map_err(|_| AdapterError::new("the item owner type is invalid"))?;
        let score: i32 = row
            .try_get(3)
            .map_err(|_| AdapterError::new("the item score type is invalid"))?;
        let payload: Vec<u8> = row
            .try_get(4)
            .map_err(|_| AdapterError::new("the item payload type is invalid"))?;
        if payload.len() != 64 {
            return Err(AdapterError::new("the item payload length is invalid"));
        }
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&bucket.to_le_bytes());
        output.extend_from_slice(&owner.to_le_bytes());
        output.extend_from_slice(&score.to_le_bytes());
        output.extend_from_slice(&payload);
    }
    Ok(output)
}

fn encode_aggregates(opcode: u8, rows: &[Row]) -> Result<Vec<u8>, AdapterError> {
    let mut output = output_prefix(opcode, rows.len())?;
    output.reserve(rows.len() * 20);
    for row in rows {
        let bucket: i32 = row
            .try_get(0)
            .map_err(|_| AdapterError::new("the aggregate bucket type is invalid"))?;
        let count: i64 = row
            .try_get(1)
            .map_err(|_| AdapterError::new("the aggregate count type is invalid"))?;
        let total: i64 = row
            .try_get(2)
            .map_err(|_| AdapterError::new("the aggregate total type is invalid"))?;
        output.extend_from_slice(&bucket.to_le_bytes());
        output.extend_from_slice(&count.to_le_bytes());
        output.extend_from_slice(&total.to_le_bytes());
    }
    Ok(output)
}

fn encode_joins(opcode: u8, rows: &[Row]) -> Result<Vec<u8>, AdapterError> {
    let mut output = output_prefix(opcode, rows.len())?;
    for row in rows {
        let id: i64 = row
            .try_get(0)
            .map_err(|_| AdapterError::new("the joined identifier type is invalid"))?;
        let owner: i32 = row
            .try_get(1)
            .map_err(|_| AdapterError::new("the joined owner type is invalid"))?;
        let name: String = row
            .try_get(2)
            .map_err(|_| AdapterError::new("the joined name type is invalid"))?;
        let score: i32 = row
            .try_get(3)
            .map_err(|_| AdapterError::new("the joined score type is invalid"))?;
        let payload: Vec<u8> = row
            .try_get(4)
            .map_err(|_| AdapterError::new("the joined payload type is invalid"))?;
        let name_length = u16::try_from(name.len())
            .map_err(|_| AdapterError::new("the owner name is excessive"))?;
        if payload.len() != 64 {
            return Err(AdapterError::new("the join payload length is invalid"));
        }
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&owner.to_le_bytes());
        output.extend_from_slice(&name_length.to_le_bytes());
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(&score.to_le_bytes());
        output.extend_from_slice(&payload);
    }
    Ok(output)
}

pub struct Execution {
    pub operation: ReadOperation,
    pub bytes: Vec<u8>,
    pub receipt: [u8; 32],
}

fn receipt(
    authority: &Authority,
    nonce: u64,
    frame_digest: [u8; 32],
    bytes: &[u8],
) -> [u8; 32] {
    let mut receipt = Sha256::new();
    receipt.update(RECEIPT_DOMAIN);
    receipt.update(authority.generation.to_le_bytes());
    receipt.update(authority.session.to_le_bytes());
    receipt.update(authority.capability.to_le_bytes());
    receipt.update(authority.schema.to_le_bytes());
    receipt.update(authority.plan.to_le_bytes());
    receipt.update(nonce.to_le_bytes());
    receipt.update(frame_digest);
    receipt.update(Sha256::digest(bytes));
    receipt.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterError {
    message: &'static str,
}

impl AdapterError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub fn backend_refused() -> Self {
        Self::new("the backend refused the operation")
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for AdapterError {}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("a fixed field"))
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("a fixed field"))
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("a fixed field"))
}

fn get_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("a fixed field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn authority(session: u32) -> Authority {
        Authority::new([7; 32], 11, session, NOW + 1_000_000, 21, 22, 23)
            .expect("authority")
    }

    struct FakeBackend {
        fail: bool,
        bytes: Vec<u8>,
    }

    impl Backend for FakeBackend {
        fn execute(&mut self, _operation: ReadOperation) -> Result<Vec<u8>, AdapterError> {
            if self.fail {
                Err(AdapterError::new("the fake backend failed"))
            } else {
                Ok(self.bytes.clone())
            }
        }
    }

    fn frame() -> [u8; FRAME_BYTES] {
        ClientSession::new(authority(31))
            .encode(
                ReadOperation::Range {
                    start: 10,
                    count: 32,
                },
                4_096,
                NOW + 10_000,
            )
            .expect("frame")
    }

    #[test]
    fn a_frame_round_trip_preserves_the_operation_and_bytes() {
        let mut server = ServerSession::new(authority(31), 8_192).expect("server");
        let mut backend = FakeBackend {
            fail: false,
            bytes: vec![1, 2, 3],
        };
        let result = server
            .execute(&frame(), NOW, &mut backend)
            .expect("execute");
        assert_eq!(
            result.operation,
            ReadOperation::Range {
                start: 10,
                count: 32
            }
        );
        assert_eq!(result.bytes, [1, 2, 3]);
    }

    #[test]
    fn every_changed_frame_bit_refuses_before_execution() {
        let original = frame();
        for bit in 0..FRAME_BYTES * 8 {
            let mut changed = original;
            changed[bit / 8] ^= 1 << (bit % 8);
            let mut server = ServerSession::new(authority(31), 8_192).expect("server");
            let mut backend = FakeBackend {
                fail: false,
                bytes: vec![1],
            };
            assert!(server.execute(&changed, NOW, &mut backend).is_err());
        }
    }

    #[test]
    fn replay_refuses() {
        let mut server = ServerSession::new(authority(31), 8_192).expect("server");
        let mut backend = FakeBackend {
            fail: false,
            bytes: vec![1],
        };
        server.execute(&frame(), NOW, &mut backend).expect("first");
        assert!(server.execute(&frame(), NOW, &mut backend).is_err());
    }

    #[test]
    fn a_backend_failure_does_not_commit_the_nonce() {
        let mut server = ServerSession::new(authority(31), 8_192).expect("server");
        let mut backend = FakeBackend {
            fail: true,
            bytes: vec![1],
        };
        assert!(server.execute(&frame(), NOW, &mut backend).is_err());
        backend.fail = false;
        assert!(server.execute(&frame(), NOW, &mut backend).is_ok());
    }

    #[test]
    fn cross_session_and_expired_frames_refuse() {
        let mut other = ServerSession::new(authority(32), 8_192).expect("server");
        let mut backend = FakeBackend {
            fail: false,
            bytes: vec![1],
        };
        assert!(other.execute(&frame(), NOW, &mut backend).is_err());
        let mut expected = ServerSession::new(authority(31), 8_192).expect("server");
        assert!(expected
            .execute(&frame(), NOW + 20_000, &mut backend)
            .is_err());
    }

    #[test]
    fn a_frame_refuses_at_its_exact_deadline() {
        let binding = authority(31);
        let mut client = ClientSession::new(binding.clone());
        let mut server = ServerSession::new(binding, 8_192).expect("server");
        let exact_deadline = NOW + 10;
        let frame = client
            .encode(
                ReadOperation::Range { start: 1, count: 1 },
                256,
                exact_deadline,
            )
            .expect("frame");
        let mut backend = FakeBackend {
            fail: false,
            bytes: vec![1],
        };
        assert!(server
            .execute(&frame, exact_deadline, &mut backend)
            .is_err());
    }

    #[test]
    fn an_overflowing_range_refuses_before_encoding() {
        let result = ClientSession::new(authority(31)).encode(
            ReadOperation::Range {
                start: i64::MAX,
                count: 2,
            },
            256,
            NOW + 10,
        );
        assert!(result.is_err());
    }

    #[test]
    fn an_excessive_result_refuses_without_committing() {
        let mut server = ServerSession::new(authority(31), 8_192).expect("server");
        let mut backend = FakeBackend {
            fail: false,
            bytes: vec![1; 4_097],
        };
        assert!(server.execute(&frame(), NOW, &mut backend).is_err());
        backend.bytes.truncate(4_096);
        assert!(server.execute(&frame(), NOW, &mut backend).is_ok());
    }

    #[test]
    fn unsafe_operations_have_no_encoder_representation() {
        assert_eq!(ReadOperation::Aggregate { minimum_score: 10 }.opcode(), 3);
        assert_eq!(FRAME_BYTES, 76);
    }
}
