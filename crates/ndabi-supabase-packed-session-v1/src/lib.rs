//! Execute one packed binary range plan through one admitted Supabase PostgreSQL session.
//!
//! The session applies the role, claims, read-only state, and maximum timeout once.
//! Do not return this connection to a generic pool or share it between user identities.
//! Use direct PostgreSQL or Supavisor session mode because transaction mode can change connections.

use ndabi_postgres_v1::RangeProfile;
use ndabi_protocol::{
    Backend, BackendIdentity, BoundedOutput, ExecutionLimits, Operation, ProtocolError,
};
use ndabi_supabase_v1::AdmittedIdentity;
use postgres::{Client, Statement};

pub struct PackedRangeSessionBackend {
    client: Client,
    data_statement: Statement,
    profile: RangeProfile,
    identity: BackendIdentity,
    data_queries: u64,
    database_result_rows: u64,
}

impl PackedRangeSessionBackend {
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
            database_result_rows: 0,
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }

    pub fn database_result_rows(&self) -> u64 {
        self.database_result_rows
    }
}

impl Backend for PackedRangeSessionBackend {
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
        let required_bytes =
            usize::try_from(required_bytes).map_err(|_| ProtocolError::ResultBudgetExceeded)?;
        output.reserve_total(required_bytes)?;
        let end = operation
            .first
            .checked_add(i64::from(operation.third))
            .ok_or(ProtocolError::BackendRefused)?;
        let row = self
            .client
            .query_one(&self.data_statement, &[&operation.first, &end])
            .map_err(|_| ProtocolError::BackendRefused)?;
        self.data_queries = self.data_queries.saturating_add(1);
        self.database_result_rows = self.database_result_rows.saturating_add(1);
        let packed: &[u8] = row.try_get(0).map_err(|_| ProtocolError::BackendRefused)?;
        if packed.len() != required_bytes {
            return Err(ProtocolError::BackendRefused);
        }
        let opcode = u16::from_be_bytes(
            packed[0..2]
                .try_into()
                .map_err(|_| ProtocolError::BackendRefused)?,
        );
        let rows = u32::from_be_bytes(
            packed[2..6]
                .try_into()
                .map_err(|_| ProtocolError::BackendRefused)?,
        );
        if opcode != operation.opcode || rows != operation.third {
            return Err(ProtocolError::BackendRefused);
        }
        output.write(packed)?;
        output.complete_rows(rows)
    }
}
