//! Execute one compare-and-swap write profile behind write-class NDABI authority.
//!
//! The profile cannot represent arbitrary SQL or a multi-row transaction.

use ndabi_session::{AccessClass, Backend, RawOperation, SessionError};
use postgres::{Client, Statement};

pub const COMPARE_AND_SWAP: u8 = 0x81;
pub const RESULT_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CasOperation {
    pub record_id: i64,
    pub expected_version: i64,
    pub new_value: u32,
}

impl CasOperation {
    pub fn new(
        record_id: i64,
        expected_version: i64,
        new_value: u32,
    ) -> Result<Self, SessionError> {
        if record_id <= 0 || expected_version < 0 {
            return Err(SessionError::profile_refused(
                "the write operation exceeds its profile",
            ));
        }
        Ok(Self {
            record_id,
            expected_version,
            new_value,
        })
    }

    pub fn into_raw(self) -> Result<RawOperation, SessionError> {
        RawOperation::new(
            COMPARE_AND_SWAP,
            self.record_id,
            self.expected_version,
            self.new_value,
        )
    }

    fn from_raw(raw: RawOperation) -> Result<Self, SessionError> {
        if raw.opcode != COMPARE_AND_SWAP {
            return Err(SessionError::profile_refused(
                "the write operation is unsupported",
            ));
        }
        Self::new(raw.first, raw.second, raw.third)
    }
}

pub struct PostgresCasBackend {
    client: Client,
    update: Statement,
}

impl PostgresCasBackend {
    pub fn new(mut client: Client, prepared_sql: &str) -> Result<Self, SessionError> {
        let update = client
            .prepare(prepared_sql)
            .map_err(|_| SessionError::profile_refused("the write plan preparation failed"))?;
        Ok(Self { client, update })
    }

    pub fn current(&mut self, record_id: i64) -> Result<(i64, i64), SessionError> {
        let row = self
            .client
            .query_one(
                "SELECT version,value FROM ndabi_write_records WHERE id=$1",
                &[&record_id],
            )
            .map_err(|_| SessionError::profile_refused("the write state read failed"))?;
        let version = row
            .try_get(0)
            .map_err(|_| SessionError::profile_refused("the write version type is invalid"))?;
        let value = row
            .try_get(1)
            .map_err(|_| SessionError::profile_refused("the write value type is invalid"))?;
        Ok((version, value))
    }
}

impl Backend for PostgresCasBackend {
    fn access_class(&self) -> AccessClass {
        AccessClass::Write
    }

    fn execute(&mut self, raw: RawOperation) -> Result<Vec<u8>, SessionError> {
        let operation = CasOperation::from_raw(raw)?;
        let value = i64::from(operation.new_value);
        let row = self
            .client
            .query_opt(
                &self.update,
                &[&operation.record_id, &operation.expected_version, &value],
            )
            .map_err(|_| SessionError::profile_refused("the compare-and-swap execution failed"))?
            .ok_or_else(|| {
                SessionError::profile_refused("the compare-and-swap conflict refused")
            })?;
        let version: i64 = row
            .try_get(0)
            .map_err(|_| SessionError::profile_refused("the committed version type is invalid"))?;
        let committed_value: i64 = row
            .try_get(1)
            .map_err(|_| SessionError::profile_refused("the committed value type is invalid"))?;
        let mut output = Vec::with_capacity(RESULT_BYTES);
        output.extend_from_slice(&operation.record_id.to_le_bytes());
        output.extend_from_slice(&version.to_le_bytes());
        output.extend_from_slice(&committed_value.to_le_bytes());
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_operation_has_one_finite_representation() {
        let operation = CasOperation::new(1, 2, 3).expect("operation");
        assert_eq!(
            operation.into_raw().expect("raw"),
            RawOperation::new(COMPARE_AND_SWAP, 1, 2, 3).expect("expected")
        );
        assert!(CasOperation::new(0, 0, 1).is_err());
        assert!(CasOperation::new(1, -1, 1).is_err());
    }
}
