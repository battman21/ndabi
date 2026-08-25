//! Lower the canonical NDABI execute-handle frame into one prepared PostgreSQL range plan.
//!
//! The frame cannot contain SQL, table names, column names, or connection details.
//! The profile binds exact SQL and result shape before a client can create an authority.
//! PostgreSQL must enforce a read-only, least-privilege database role.

use ndabi_protocol::{
    Authority, Backend, BackendIdentity, BatchBackend, BatchItems, BatchOperation, BoundedOutput,
    CapabilityManifest, Clock, Execution, ExecutionLimits, MemoryReplayStore, Operation,
    PlanRegistry, ProtocolError, RegisteredPlan, ReplayStore, CAPABILITY_BATCH, CAPABILITY_QUERY,
};
use postgres::{Client, Row, Statement};

pub use ndabi_protocol::{
    digest_label, AuthorityContext, ClientSession as WireClientSession, FRAME_BYTES,
};

pub const POSTGRESQL_ENGINE_ID: u32 = 0x5047_0001;
pub const POSTGRESQL_RANGE_PROFILE_ID: u32 = 0x5047_1001;
pub const POSTGRESQL_RANGE_REGISTRY_PROFILE_ID: u32 = 0x5047_1002;
pub const RANGE_OPCODE: u16 = 1;
const PLAN_DOMAIN: &[u8] = b"ndabi/postgresql/range-profile/v1";
const PARAMETER_SCHEMA_DOMAIN: &[u8] = b"ndabi/postgresql/range-parameters/v1";
const MAXIMUM_RANGE_ROWS: u32 = 4_096;
const MAXIMUM_RANGE_RESULT_BYTES: u32 = 6 + MAXIMUM_RANGE_ROWS * 84;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationBinding {
    pub plan_handle: u32,
    pub result_shape: u32,
}

impl OperationBinding {
    pub fn new(plan_handle: u32, result_shape: u32) -> Result<Self, ProtocolError> {
        if plan_handle == 0 || result_shape == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        Ok(Self {
            plan_handle,
            result_shape,
        })
    }
}

#[derive(Clone, Copy)]
pub struct RangeProfile {
    sql: &'static str,
    binding: OperationBinding,
}

impl RangeProfile {
    pub fn new(sql: &'static str, binding: OperationBinding) -> Result<Self, ProtocolError> {
        if sql.trim().is_empty() {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(Self { sql, binding })
    }

    pub fn identity(
        self,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<BackendIdentity, ProtocolError> {
        BackendIdentity::new(
            POSTGRESQL_ENGINE_ID,
            POSTGRESQL_RANGE_PROFILE_ID,
            schema_digest,
            policy_digest,
            self.implementation_digest(),
        )
    }

    pub fn registered_plan(self) -> Result<RegisteredPlan, ProtocolError> {
        RegisteredPlan::new_read(
            RANGE_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
            MAXIMUM_RANGE_ROWS,
            MAXIMUM_RANGE_RESULT_BYTES,
            MAXIMUM_RANGE_ROWS,
            CAPABILITY_QUERY | CAPABILITY_BATCH,
            digest_label(PARAMETER_SCHEMA_DOMAIN, b"start:i64,second:zero,count:u32"),
            self.implementation_digest(),
        )
    }

    pub fn plan_registry(
        self,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<PlanRegistry, ProtocolError> {
        PlanRegistry::new(
            POSTGRESQL_ENGINE_ID,
            POSTGRESQL_RANGE_REGISTRY_PROFILE_ID,
            schema_digest,
            policy_digest,
            CapabilityManifest::new(CAPABILITY_QUERY | CAPABILITY_BATCH)?,
            [self.registered_plan()?],
        )
    }

    pub fn operation(self, start: i64, count: u32) -> Result<Operation, ProtocolError> {
        validate_range(start, count)?;
        Operation::new(
            RANGE_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
            start,
            0,
            count,
        )
    }

    pub fn batch_operation(self) -> Result<BatchOperation, ProtocolError> {
        BatchOperation::new(
            RANGE_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
        )
    }

    pub fn sql(self) -> &'static str {
        self.sql
    }

    fn implementation_digest(self) -> [u8; 32] {
        let mut plan = blake3::Hasher::new();
        plan.update(PLAN_DOMAIN);
        plan.update(self.sql.as_bytes());
        plan.update(&self.binding.plan_handle.to_le_bytes());
        plan.update(&self.binding.result_shape.to_le_bytes());
        *plan.finalize().as_bytes()
    }
}

pub struct RangeBackend {
    client: Client,
    deadline_statement: Statement,
    statement: Statement,
    profile: RangeProfile,
    identity: BackendIdentity,
    batch_ids: Vec<i64>,
    data_queries: u64,
}

impl RangeBackend {
    pub fn new(
        client: Client,
        profile: RangeProfile,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        let identity = profile.identity(schema_digest, policy_digest)?;
        Self::initialise(client, profile, identity)
    }

    pub fn new_registered(
        client: Client,
        profile: RangeProfile,
        registry: &PlanRegistry,
    ) -> Result<Self, ProtocolError> {
        if registry.identity().engine() != POSTGRESQL_ENGINE_ID
            || registry.identity().profile() != POSTGRESQL_RANGE_REGISTRY_PROFILE_ID
            || registry.plans() != [profile.registered_plan()?]
        {
            return Err(ProtocolError::PlanRegistryMismatch);
        }
        Self::initialise(client, profile, registry.identity())
    }

    fn initialise(
        mut client: Client,
        profile: RangeProfile,
        identity: BackendIdentity,
    ) -> Result<Self, ProtocolError> {
        client
            .batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            .map_err(|_| ProtocolError::BackendRefused)?;
        let statement = client
            .prepare(profile.sql)
            .map_err(|_| ProtocolError::BackendRefused)?;
        let deadline_statement = client
            .prepare("SELECT set_config('statement_timeout', $1, false)")
            .map_err(|_| ProtocolError::BackendRefused)?;
        Ok(Self {
            client,
            deadline_statement,
            statement,
            profile,
            identity,
            batch_ids: Vec::with_capacity(4_096),
            data_queries: 0,
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }

    fn apply_deadline(&mut self, limits: ExecutionLimits) -> Result<(), ProtocolError> {
        let remaining_us = limits
            .deadline_unix_us
            .checked_sub(limits.admitted_unix_us)
            .ok_or(ProtocolError::Expired)?;
        let remaining_ms = remaining_us.div_ceil(1_000).max(1);
        let timeout = format!("{remaining_ms}ms");
        self.client
            .query_one(&self.deadline_statement, &[&timeout])
            .map_err(|_| ProtocolError::BackendRefused)?;
        Ok(())
    }

    fn execute_range(
        &mut self,
        start: i64,
        count: u32,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        validate_range(start, count)?;
        if count > limits.maximum_rows {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        let required_bytes = 6_u64
            .checked_add(u64::from(count) * 84)
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        if required_bytes > u64::from(limits.maximum_result_bytes) {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        self.apply_deadline(limits)?;
        let ids: Vec<i64> = (0..i64::from(count)).map(|offset| start + offset).collect();
        let rows = self
            .client
            .query(&self.statement, &[&ids])
            .map_err(|_| ProtocolError::BackendRefused)?;
        self.data_queries = self.data_queries.saturating_add(1);
        if rows.len() != count as usize {
            return Err(ProtocolError::BackendRefused);
        }
        output.write(&RANGE_OPCODE.to_le_bytes())?;
        output.write(&0_u32.to_le_bytes())?;
        for (index, row) in rows.iter().enumerate() {
            encode_row(row, start, index, output)?;
        }
        output.patch_u32(2, output.rows())?;
        Ok(())
    }
}

impl BatchBackend for RangeBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_batch(
        &mut self,
        operation: BatchOperation,
        items: BatchItems<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        if operation != self.profile.batch_operation()? {
            return Err(ProtocolError::BackendRefused);
        }
        let count = u32::try_from(items.len()).map_err(|_| ProtocolError::BatchLimitExceeded)?;
        if count > limits.maximum_rows {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        let required_bytes = 6_u64
            .checked_add(u64::from(count) * 84)
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        if required_bytes > u64::from(limits.maximum_result_bytes) {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        self.batch_ids.clear();
        for item in items {
            validate_range(item.first, 1)?;
            if item.second != 0 || item.third != 1 {
                return Err(ProtocolError::BackendRefused);
            }
            if self
                .batch_ids
                .last()
                .is_some_and(|last| *last >= item.first)
            {
                return Err(ProtocolError::BackendRefused);
            }
            self.batch_ids.push(item.first);
        }
        self.apply_deadline(limits)?;
        let rows = self
            .client
            .query(&self.statement, &[&self.batch_ids])
            .map_err(|_| ProtocolError::BackendRefused)?;
        self.data_queries = self.data_queries.saturating_add(1);
        if rows.len() != self.batch_ids.len() {
            return Err(ProtocolError::BackendRefused);
        }
        output.write(&RANGE_OPCODE.to_le_bytes())?;
        output.write(&0_u32.to_le_bytes())?;
        for (row, expected_id) in rows.iter().zip(&self.batch_ids) {
            encode_expected_row(row, *expected_id, output)?;
        }
        output.patch_u32(2, output.rows())?;
        Ok(())
    }
}

impl Backend for RangeBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute(
        &mut self,
        operation: Operation,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        if operation.opcode != RANGE_OPCODE
            || operation.plan_handle != self.profile.binding.plan_handle
            || operation.result_shape != self.profile.binding.result_shape
            || operation.second != 0
        {
            return Err(ProtocolError::BackendRefused);
        }
        self.execute_range(operation.first, operation.third, limits, output)
    }
}

fn validate_range(start: i64, count: u32) -> Result<(), ProtocolError> {
    if start <= 0 || count == 0 || count > 4_096 {
        return Err(ProtocolError::BackendRefused);
    }
    start
        .checked_add(i64::from(count - 1))
        .ok_or(ProtocolError::BackendRefused)?;
    Ok(())
}

fn encode_row(
    row: &Row,
    expected_start: i64,
    index: usize,
    output: &mut BoundedOutput,
) -> Result<(), ProtocolError> {
    let index = i64::try_from(index).map_err(|_| ProtocolError::BackendRefused)?;
    let expected_id = expected_start
        .checked_add(index)
        .ok_or(ProtocolError::BackendRefused)?;
    encode_expected_row(row, expected_id, output)
}

fn encode_expected_row(
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

pub struct ServerSession {
    inner: ndabi_protocol::ServerSession,
}

impl ServerSession {
    pub fn new(
        authority: Authority,
        maximum_result_bytes: u32,
        maximum_rows: u32,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            inner: ndabi_protocol::ServerSession::new(
                authority,
                maximum_result_bytes,
                maximum_rows,
            )?,
        })
    }

    pub fn execute<R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut RangeBackend,
        replay: &mut R,
        clock: &C,
    ) -> Result<Execution, ProtocolError> {
        self.inner.execute(frame, backend, replay, clock)
    }
}

pub fn memory_replay_store() -> MemoryReplayStore {
    MemoryReplayStore::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SQL: &str =
        "SELECT id,bucket,owner,score,payload FROM items WHERE id = ANY($1) ORDER BY id";

    fn profile() -> RangeProfile {
        RangeProfile::new(SQL, OperationBinding::new(40, 41).expect("binding")).expect("profile")
    }

    #[test]
    fn the_profile_identity_changes_with_schema_and_policy() {
        let first = profile().identity([1; 32], [2; 32]).expect("identity");
        let schema_changed = profile().identity([3; 32], [2; 32]).expect("identity");
        let policy_changed = profile().identity([1; 32], [4; 32]).expect("identity");
        assert_ne!(first, schema_changed);
        assert_ne!(first, policy_changed);
    }

    #[test]
    fn the_registered_profile_seals_the_existing_plan() {
        let profile = profile();
        let registry = profile.plan_registry([1; 32], [2; 32]).expect("registry");
        assert_eq!(registry.plans(), [profile.registered_plan().expect("plan")]);
        assert_eq!(registry.identity().engine(), POSTGRESQL_ENGINE_ID);
        assert_eq!(
            registry.identity().profile(),
            POSTGRESQL_RANGE_REGISTRY_PROFILE_ID
        );
        assert_ne!(
            registry.identity(),
            profile.identity([1; 32], [2; 32]).expect("legacy identity")
        );
    }

    #[test]
    fn the_range_profile_refuses_invalid_bounds() {
        assert!(profile().operation(0, 1).is_err());
        assert!(profile().operation(1, 0).is_err());
        assert!(profile().operation(1, 4_097).is_err());
        assert!(profile().operation(i64::MAX, 2).is_err());
    }
}
