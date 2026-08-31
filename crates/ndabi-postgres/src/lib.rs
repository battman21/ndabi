//! Execute a finite NDABI read profile through caller-supplied PostgreSQL plans.
//!
//! Agent frames cannot contain SQL or write opcodes. The profile owner controls trusted prepared SQL.
//! The database connection must enforce the profile owner's read-only authority.
//! The shared session crate authenticates each frame before this profile interprets its operands.

use ndabi_session::{Backend as SessionBackend, RawOperation};
use postgres::{Client, Row, Statement};
use serde::{Deserialize, Serialize};

pub mod isa;

pub use ndabi_session::{Authority, SessionError as AdapterError, FRAME_BYTES};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub enum ReadOperation {
    Range {
        start: i64,
        count: u32,
    },
    Predicate {
        bucket: i32,
        minimum_score: i32,
        limit: u32,
    },
    Aggregate {
        minimum_score: i32,
    },
    Join {
        owner: i32,
        limit: u32,
    },
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

    fn into_raw(self) -> Result<RawOperation, AdapterError> {
        validate_operation(self)?;
        let (first, second, third) = match self {
            Self::Range { start, count } => (start, 0, count),
            Self::Predicate {
                bucket,
                minimum_score,
                limit,
            } => (i64::from(bucket), i64::from(minimum_score), limit),
            Self::Aggregate { minimum_score } => (i64::from(minimum_score), 0, 0),
            Self::Join { owner, limit } => (i64::from(owner), 0, limit),
        };
        RawOperation::new(self.opcode(), first, second, third)
    }

    fn from_raw(raw: RawOperation) -> Result<Self, AdapterError> {
        let operation = match raw.opcode {
            1 if raw.second == 0 => Self::Range {
                start: raw.first,
                count: raw.third,
            },
            2 => Self::Predicate {
                bucket: i32::try_from(raw.first)
                    .map_err(|_| profile_error("the predicate bucket is invalid"))?,
                minimum_score: i32::try_from(raw.second)
                    .map_err(|_| profile_error("the predicate score is invalid"))?,
                limit: raw.third,
            },
            3 if raw.second == 0 && raw.third == 0 => Self::Aggregate {
                minimum_score: i32::try_from(raw.first)
                    .map_err(|_| profile_error("the aggregate score is invalid"))?,
            },
            4 if raw.second == 0 => Self::Join {
                owner: i32::try_from(raw.first)
                    .map_err(|_| profile_error("the join owner is invalid"))?,
                limit: raw.third,
            },
            _ => return Err(profile_error("the PostgreSQL operation is unsupported")),
        };
        validate_operation(operation)?;
        Ok(operation)
    }
}

fn profile_error(message: &'static str) -> AdapterError {
    AdapterError::profile_refused(message)
}

fn validate_operation(operation: ReadOperation) -> Result<(), AdapterError> {
    match operation {
        ReadOperation::Range { start, count } => {
            let end = start.checked_add(i64::from(count.saturating_sub(1)));
            if start < 0 || count == 0 || count > 4_096 || end.is_none() {
                return Err(profile_error("the range operation exceeds its profile"));
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
                return Err(profile_error("the predicate operation exceeds its profile"));
            }
        }
        ReadOperation::Aggregate { minimum_score } => {
            if !(0..10_000).contains(&minimum_score) {
                return Err(profile_error("the aggregate operation exceeds its profile"));
            }
        }
        ReadOperation::Join { owner, limit } => {
            if !(0..4_096).contains(&owner) || limit == 0 || limit > 256 {
                return Err(profile_error("the join operation exceeds its profile"));
            }
        }
    }
    Ok(())
}

pub struct ClientSession {
    inner: ndabi_session::ClientSession,
}

impl ClientSession {
    pub fn new(authority: Authority) -> Self {
        Self {
            inner: ndabi_session::ClientSession::new(authority),
        }
    }

    pub fn encode(
        &mut self,
        operation: ReadOperation,
        result_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<[u8; FRAME_BYTES], AdapterError> {
        self.inner
            .encode(operation.into_raw()?, result_budget, deadline_unix_us)
    }
}

pub struct ServerSession {
    inner: ndabi_session::ServerSession,
}

impl ServerSession {
    pub fn new(authority: Authority, maximum_result_bytes: u32) -> Result<Self, AdapterError> {
        Ok(Self {
            inner: ndabi_session::ServerSession::new(authority, maximum_result_bytes)?,
        })
    }

    pub fn execute<B: Backend>(
        &mut self,
        frame: &[u8],
        now_unix_us: u64,
        backend: &mut B,
    ) -> Result<Execution, AdapterError> {
        let mut bridge = ProfileBridge { backend };
        let result = self.inner.execute(frame, now_unix_us, &mut bridge)?;
        Ok(Execution {
            operation: ReadOperation::from_raw(result.operation)?,
            bytes: result.bytes,
            receipt: result.receipt,
        })
    }
}

struct ProfileBridge<'a, B> {
    backend: &'a mut B,
}

impl<B: Backend> SessionBackend for ProfileBridge<'_, B> {
    fn execute(&mut self, operation: RawOperation) -> Result<Vec<u8>, AdapterError> {
        self.backend.execute(ReadOperation::from_raw(operation)?)
    }
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
            .map_err(|_| profile_error("the range plan preparation failed"))?;
        let predicate = client
            .prepare(sql.predicate)
            .map_err(|_| profile_error("the predicate plan preparation failed"))?;
        let aggregate = client
            .prepare(sql.aggregate)
            .map_err(|_| profile_error("the aggregate plan preparation failed"))?;
        let join = client
            .prepare(sql.join)
            .map_err(|_| profile_error("the join plan preparation failed"))?;
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
                    .map_err(|_| profile_error("the range execution failed"))?;
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
                    .map_err(|_| profile_error("the predicate execution failed"))?;
                encode_items(operation.opcode(), &rows)
            }
            ReadOperation::Aggregate { minimum_score } => {
                let rows = self
                    .client
                    .query(&self.aggregate, &[&minimum_score])
                    .map_err(|_| profile_error("the aggregate execution failed"))?;
                encode_aggregates(operation.opcode(), &rows)
            }
            ReadOperation::Join { owner, limit } => {
                let limit = i64::from(limit);
                let rows = self
                    .client
                    .query(&self.join, &[&owner, &limit])
                    .map_err(|_| profile_error("the join execution failed"))?;
                encode_joins(operation.opcode(), &rows)
            }
        }
    }
}

fn output_prefix(opcode: u8, rows: usize) -> Result<Vec<u8>, AdapterError> {
    let rows = u32::try_from(rows).map_err(|_| profile_error("the row count is excessive"))?;
    let mut output = Vec::new();
    output.push(opcode);
    output.extend_from_slice(&rows.to_le_bytes());
    Ok(output)
}

fn encode_items(opcode: u8, rows: &[Row]) -> Result<Vec<u8>, AdapterError> {
    let mut output = output_prefix(opcode, rows.len())?;
    output.reserve(rows.len() * 84);
    for row in rows {
        let id: i64 = row
            .try_get(0)
            .map_err(|_| profile_error("the item identifier type is invalid"))?;
        let bucket: i32 = row
            .try_get(1)
            .map_err(|_| profile_error("the item bucket type is invalid"))?;
        let owner: i32 = row
            .try_get(2)
            .map_err(|_| profile_error("the item owner type is invalid"))?;
        let score: i32 = row
            .try_get(3)
            .map_err(|_| profile_error("the item score type is invalid"))?;
        let payload: Vec<u8> = row
            .try_get(4)
            .map_err(|_| profile_error("the item payload type is invalid"))?;
        if payload.len() != 64 {
            return Err(profile_error("the item payload length is invalid"));
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
            .map_err(|_| profile_error("the aggregate bucket type is invalid"))?;
        let count: i64 = row
            .try_get(1)
            .map_err(|_| profile_error("the aggregate count type is invalid"))?;
        let total: i64 = row
            .try_get(2)
            .map_err(|_| profile_error("the aggregate total type is invalid"))?;
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
            .map_err(|_| profile_error("the joined identifier type is invalid"))?;
        let owner: i32 = row
            .try_get(1)
            .map_err(|_| profile_error("the joined owner type is invalid"))?;
        let name: String = row
            .try_get(2)
            .map_err(|_| profile_error("the joined name type is invalid"))?;
        let score: i32 = row
            .try_get(3)
            .map_err(|_| profile_error("the joined score type is invalid"))?;
        let payload: Vec<u8> = row
            .try_get(4)
            .map_err(|_| profile_error("the joined payload type is invalid"))?;
        let name_length =
            u16::try_from(name.len()).map_err(|_| profile_error("the owner name is excessive"))?;
        if payload.len() != 64 {
            return Err(profile_error("the join payload length is invalid"));
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

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn authority(session: u32) -> Authority {
        Authority::new([7; 32], 11, session, NOW + 1_000_000, 21, 22, 23).expect("authority")
    }

    struct FakeBackend {
        fail: bool,
        bytes: Vec<u8>,
    }

    impl Backend for FakeBackend {
        fn execute(&mut self, _operation: ReadOperation) -> Result<Vec<u8>, AdapterError> {
            if self.fail {
                Err(AdapterError::backend_refused())
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
    fn a_frame_round_trip_preserves_the_profile_operation() {
        let mut server = ServerSession::new(authority(31), 8_192).expect("server");
        let result = server
            .execute(
                &frame(),
                NOW,
                &mut FakeBackend {
                    fail: false,
                    bytes: vec![1, 2, 3],
                },
            )
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
    fn profile_validation_precedes_session_encoding() {
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
    fn a_backend_failure_preserves_the_shared_nonce() {
        let mut server = ServerSession::new(authority(31), 8_192).expect("server");
        let mut backend = FakeBackend {
            fail: true,
            bytes: vec![1],
        };
        assert!(server.execute(&frame(), NOW, &mut backend).is_err());
        backend.fail = false;
        assert!(server.execute(&frame(), NOW, &mut backend).is_ok());
    }
}
