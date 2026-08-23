//! Execute one admitted user profile through PostgreSQL row-level security.

use ndabi_postgres_v1::RangeProfile;
use ndabi_protocol::{
    Backend, BackendIdentity, BoundedOutput, ExecutionLimits, Operation, ProtocolError,
};
use postgres::{Client, Row, Statement};

use crate::AdmittedIdentity;

pub struct UserRangeBackend {
    client: Client,
    context_statement: Statement,
    data_statement: Statement,
    profile: RangeProfile,
    identity: BackendIdentity,
    claims: String,
    data_queries: u64,
}

impl UserRangeBackend {
    pub fn new(
        mut client: Client,
        profile: RangeProfile,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
        user: &AdmittedIdentity,
    ) -> Result<Self, ProtocolError> {
        if user.role() != "authenticated" {
            return Err(ProtocolError::BackendRefused);
        }
        let context_statement = client
            .prepare(
                "SELECT set_config('request.jwt.claims',$1,true),set_config('statement_timeout',$2,true)",
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let data_statement = client
            .prepare(profile.sql())
            .map_err(|_| ProtocolError::BackendRefused)?;
        let identity = profile.identity(schema_digest, policy_digest)?;
        Ok(Self {
            client,
            context_statement,
            data_statement,
            profile,
            identity,
            claims: user.canonical_claims().to_string(),
            data_queries: 0,
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }

    fn execute_range(
        &mut self,
        operation: Operation,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        let expected = self.profile.operation(operation.first, operation.third)?;
        if operation != expected || operation.third > limits.maximum_rows {
            return Err(ProtocolError::BackendRefused);
        }
        let required_bytes = 6_u64
            .checked_add(u64::from(operation.third) * 84)
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        if required_bytes > u64::from(limits.maximum_result_bytes) {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        let remaining_us = limits
            .deadline_unix_us
            .checked_sub(limits.admitted_unix_us)
            .ok_or(ProtocolError::Expired)?;
        let timeout = format!("{}ms", remaining_us.div_ceil(1_000).max(1));
        let ids = (0..i64::from(operation.third))
            .map(|offset| operation.first + offset)
            .collect::<Vec<_>>();
        let mut transaction = self
            .client
            .build_transaction()
            .read_only(true)
            .start()
            .map_err(|_| ProtocolError::BackendRefused)?;
        transaction
            .batch_execute("SET LOCAL ROLE authenticated")
            .map_err(|_| ProtocolError::BackendRefused)?;
        transaction
            .query_one(&self.context_statement, &[&self.claims, &timeout])
            .map_err(|_| ProtocolError::BackendRefused)?;
        let rows = transaction
            .query(&self.data_statement, &[&ids])
            .map_err(|_| ProtocolError::BackendRefused)?;
        self.data_queries = self.data_queries.saturating_add(1);
        if rows.len() != ids.len() {
            return Err(ProtocolError::BackendRefused);
        }
        output.write(&operation.opcode.to_le_bytes())?;
        output.write(&0_u32.to_le_bytes())?;
        for (row, expected_id) in rows.iter().zip(ids) {
            encode_row(row, expected_id, output)?;
        }
        output.patch_u32(2, output.rows())?;
        transaction
            .commit()
            .map_err(|_| ProtocolError::BackendRefused)
    }
}

impl Backend for UserRangeBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute(
        &mut self,
        operation: Operation,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        self.execute_range(operation, limits, output)
    }
}

fn encode_row(
    row: &Row,
    expected_id: i64,
    output: &mut BoundedOutput,
) -> Result<(), ProtocolError> {
    let id: i64 = row.try_get(0).map_err(|_| ProtocolError::BackendRefused)?;
    let bucket: i32 = row.try_get(1).map_err(|_| ProtocolError::BackendRefused)?;
    let owner: i32 = row.try_get(2).map_err(|_| ProtocolError::BackendRefused)?;
    let score: i32 = row.try_get(3).map_err(|_| ProtocolError::BackendRefused)?;
    let payload: Vec<u8> = row.try_get(4).map_err(|_| ProtocolError::BackendRefused)?;
    if id != expected_id || payload.len() != 64 {
        return Err(ProtocolError::BackendRefused);
    }
    output.write(&id.to_le_bytes())?;
    output.write(&bucket.to_le_bytes())?;
    output.write(&owner.to_le_bytes())?;
    output.write(&score.to_le_bytes())?;
    output.write(&payload)?;
    output.complete_row()
}
