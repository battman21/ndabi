//! Bind one admitted Supabase user to one dedicated PostgreSQL session.
//!
//! The session applies the role, claims, read-only state, and maximum timeout once.
//! Do not return this connection to a generic pool or share it between user identities.
//! Use direct PostgreSQL or Supavisor session mode because transaction mode can change connections.

use ndabi_postgres_v1::RangeProfile;
use ndabi_protocol::{
    Backend, BackendIdentity, BoundedOutput, ExecutionLimits, Operation, ProtocolError,
};
use ndabi_supabase_v1::AdmittedIdentity;
use postgres::{Client, Row, Statement};

pub struct SessionUserRangeBackend {
    client: Client,
    data_statement: Statement,
    profile: RangeProfile,
    identity: BackendIdentity,
    data_queries: u64,
}

impl SessionUserRangeBackend {
    pub fn new(
        mut client: Client,
        profile: RangeProfile,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
        user: &AdmittedIdentity,
        maximum_statement_ms: u32,
    ) -> Result<Self, ProtocolError> {
        if user.role() != "authenticated" || maximum_statement_ms == 0 {
            return Err(ProtocolError::BackendRefused);
        }
        client
            .batch_execute(
                "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY; SET ROLE authenticated",
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let context_statement = client
            .prepare(
                "SELECT set_config('request.jwt.claims',$1,false),set_config('statement_timeout',$2,false)",
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let timeout = format!("{maximum_statement_ms}ms");
        client
            .query_one(&context_statement, &[&user.canonical_claims(), &timeout])
            .map_err(|_| ProtocolError::BackendRefused)?;
        let state = client
            .query_one(
                "SELECT current_user,current_setting('transaction_read_only'),current_setting('request.jwt.claims')",
                &[],
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        let current_user: String = state
            .try_get(0)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let read_only: String = state
            .try_get(1)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let claims: String = state
            .try_get(2)
            .map_err(|_| ProtocolError::BackendRefused)?;
        if current_user != "authenticated" || read_only != "on" || claims != user.canonical_claims()
        {
            return Err(ProtocolError::BackendRefused);
        }
        let data_statement = client
            .prepare(profile.sql())
            .map_err(|_| ProtocolError::BackendRefused)?;
        let identity = profile.identity(schema_digest, policy_digest)?;
        Ok(Self {
            client,
            data_statement,
            profile,
            identity,
            data_queries: 0,
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }
}

impl Backend for SessionUserRangeBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute(
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
        let ids = (0..i64::from(operation.third))
            .map(|offset| operation.first + offset)
            .collect::<Vec<_>>();
        let rows = self
            .client
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
        output.patch_u32(2, output.rows())
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
