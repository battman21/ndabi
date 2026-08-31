//! Lower the canonical NDABI execute-handle frame into one prepared PostgreSQL range plan.
//!
//! The frame cannot contain SQL, table names, column names, or connection details.
//! The profile binds exact SQL and result shape before a client can create an authority.
//! PostgreSQL must enforce a read-only, least-privilege database role.

use ndabi_protocol::{
    Authority, Backend, BackendIdentity, BatchBackend, BatchItems, BatchOperation,
    BorrowedBundledGraphExecution, BorrowedGraphExecution, BoundedOutput, BundleAccepted,
    BundleRemoved, BundledGraphBackend, BundledGraphExecution, CapabilityManifest, Clock,
    Execution, ExecutionLimits, GraphBackend, GraphExecution, GraphNode, GraphOperation,
    GraphRegistry, MemoryReplayStore, OperandBundleStore, OperandLayout, Operation, PlanRegistry,
    ProtocolError, RegisteredGraph, RegisteredPlan, ReplayStore, SingleSessionReplayStore,
    CAPABILITY_AGGREGATE, CAPABILITY_BATCH, CAPABILITY_GRAPH, CAPABILITY_QUERY,
};
use postgres::{Client, Row, Statement};

mod operand_bundle;

pub use operand_bundle::{
    ReviewBatchBundle, ReviewBatchThresholds, ReviewOperandBundleBackend,
    ReviewOperandBundleProfile, POSTGRESQL_REVIEW_OPERAND_BUNDLE_PROFILE_ID,
    REVIEW_OPERAND_BUNDLE_OPCODE,
};

pub use ndabi_protocol::{
    digest_label, AuthorityContext, ClientSession as WireClientSession, PreparedBundledGraphFrame,
    PreparedGraphFrame, FRAME_BYTES,
};

pub const POSTGRESQL_ENGINE_ID: u32 = 0x5047_0001;
pub const POSTGRESQL_RANGE_PROFILE_ID: u32 = 0x5047_1001;
pub const POSTGRESQL_RANGE_REGISTRY_PROFILE_ID: u32 = 0x5047_1002;
pub const POSTGRESQL_REVIEW_GRAPH_PROFILE_ID: u32 = 0x5047_1003;
pub const POSTGRESQL_REVIEW_BATCH_GRAPH_PROFILE_ID: u32 = 0x5047_1004;
pub const RANGE_OPCODE: u16 = 1;
pub const REVIEW_GRAPH_OPCODE: u16 = 2;
pub const REVIEW_BATCH_GRAPH_OPCODE: u16 = 3;
const PLAN_DOMAIN: &[u8] = b"ndabi/postgresql/range-profile/v1";
const REVIEW_GRAPH_DOMAIN: &[u8] = b"ndabi/postgresql/review-graph/v1";
const REVIEW_BATCH_GRAPH_DOMAIN: &[u8] = b"ndabi/postgresql/review-batch-graph/v1";
const PARAMETER_SCHEMA_DOMAIN: &[u8] = b"ndabi/postgresql/range-parameters/v1";
const REVIEW_PARAMETER_SCHEMA_DOMAIN: &[u8] = b"ndabi/postgresql/review-parameters/v1";
const REVIEW_BATCH_PARAMETER_SCHEMA_DOMAIN: &[u8] = b"ndabi/postgresql/review-batch-parameters/v1";
const MAXIMUM_RANGE_ROWS: u32 = 4_096;
const MAXIMUM_RANGE_RESULT_BYTES: u32 = 6 + MAXIMUM_RANGE_ROWS * 84;
const REVIEW_PARAMETER_BYTES: u32 = 16;
const MAXIMUM_REVIEW_RESULT_BYTES: u32 = 14 + MAXIMUM_RANGE_ROWS * 84;
const REVIEW_BATCH_HEADER_BYTES: u32 = 4;
const REVIEW_BATCH_ITEM_BYTES: u32 = 16;
const REVIEW_BATCH_RESULT_HEADER_BYTES: u32 = 6;
const REVIEW_BATCH_RESULT_ITEM_BYTES: u32 = 16;
const MAXIMUM_REVIEW_BATCH_ITEMS: u32 = 1_024;
const MAXIMUM_REVIEW_BATCH_SOURCE_ROWS: u32 = 65_536;
const MAXIMUM_REVIEW_BATCH_PARAMETER_BYTES: u32 =
    REVIEW_BATCH_HEADER_BYTES + MAXIMUM_REVIEW_BATCH_ITEMS * REVIEW_BATCH_ITEM_BYTES;
const MAXIMUM_REVIEW_BATCH_RESULT_BYTES: u32 =
    REVIEW_BATCH_RESULT_HEADER_BYTES + MAXIMUM_REVIEW_BATCH_ITEMS * REVIEW_BATCH_RESULT_ITEM_BYTES;
const REVIEW_SELECT_PLAN: u32 = 0x5047_2001;
const REVIEW_FILTER_PLAN: u32 = 0x5047_2002;
const REVIEW_AGGREGATE_PLAN: u32 = 0x5047_2003;
const REVIEW_SELECT_SHAPE: u32 = 0x5047_3001;
const REVIEW_FILTER_SHAPE: u32 = 0x5047_3002;
const REVIEW_AGGREGATE_SHAPE: u32 = 0x5047_3003;
const REVIEW_BATCH_INPUT_PLAN: u32 = 0x5047_2101;
const REVIEW_BATCH_SELECT_PLAN: u32 = 0x5047_2102;
const REVIEW_BATCH_FILTER_PLAN: u32 = 0x5047_2103;
const REVIEW_BATCH_AGGREGATE_PLAN: u32 = 0x5047_2104;
const REVIEW_BATCH_INPUT_SHAPE: u32 = 0x5047_3101;
const REVIEW_BATCH_SELECT_SHAPE: u32 = 0x5047_3102;
const REVIEW_BATCH_FILTER_SHAPE: u32 = 0x5047_3103;
const REVIEW_BATCH_AGGREGATE_SHAPE: u32 = 0x5047_3104;

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

#[derive(Clone, Copy)]
pub struct ReviewGraphProfile {
    sql: &'static str,
    binding: OperationBinding,
}

impl ReviewGraphProfile {
    pub fn new(sql: &'static str, binding: OperationBinding) -> Result<Self, ProtocolError> {
        if sql.trim().is_empty() {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(Self { sql, binding })
    }

    pub fn registered_graph(self) -> Result<RegisteredGraph, ProtocolError> {
        RegisteredGraph::new_read(
            REVIEW_GRAPH_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
            REVIEW_PARAMETER_BYTES,
            MAXIMUM_REVIEW_RESULT_BYTES,
            MAXIMUM_RANGE_ROWS,
            CAPABILITY_QUERY | CAPABILITY_GRAPH | CAPABILITY_AGGREGATE,
            digest_label(
                REVIEW_PARAMETER_SCHEMA_DOMAIN,
                b"start:i64,count:u32,minimum_score:i32",
            ),
            self.implementation_digest(),
            [
                GraphNode::new(REVIEW_SELECT_PLAN, REVIEW_SELECT_SHAPE, [])?,
                GraphNode::new(REVIEW_FILTER_PLAN, REVIEW_FILTER_SHAPE, [0])?,
                GraphNode::new(REVIEW_AGGREGATE_PLAN, REVIEW_AGGREGATE_SHAPE, [0, 1])?,
            ],
        )
    }

    pub fn graph_registry(
        self,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<GraphRegistry, ProtocolError> {
        GraphRegistry::new(
            POSTGRESQL_ENGINE_ID,
            POSTGRESQL_REVIEW_GRAPH_PROFILE_ID,
            schema_digest,
            policy_digest,
            CapabilityManifest::new(CAPABILITY_QUERY | CAPABILITY_GRAPH | CAPABILITY_AGGREGATE)?,
            [self.registered_graph()?],
        )
    }

    pub fn operation(self) -> Result<GraphOperation, ProtocolError> {
        GraphOperation::new(
            REVIEW_GRAPH_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
        )
    }

    pub fn parameters(
        self,
        start: i64,
        count: u32,
        minimum_score: i32,
    ) -> Result<[u8; REVIEW_PARAMETER_BYTES as usize], ProtocolError> {
        validate_review(start, count, minimum_score)?;
        let mut parameters = [0_u8; REVIEW_PARAMETER_BYTES as usize];
        parameters[0..8].copy_from_slice(&start.to_le_bytes());
        parameters[8..12].copy_from_slice(&count.to_le_bytes());
        parameters[12..16].copy_from_slice(&minimum_score.to_le_bytes());
        Ok(parameters)
    }

    pub fn sql(self) -> &'static str {
        self.sql
    }

    fn implementation_digest(self) -> [u8; 32] {
        let mut graph = blake3::Hasher::new();
        graph.update(REVIEW_GRAPH_DOMAIN);
        graph.update(self.sql.as_bytes());
        graph.update(&self.binding.plan_handle.to_le_bytes());
        graph.update(&self.binding.result_shape.to_le_bytes());
        *graph.finalize().as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewBatchItem {
    start: i64,
    count: u32,
    minimum_score: i32,
}

impl ReviewBatchItem {
    pub fn new(start: i64, count: u32, minimum_score: i32) -> Result<Self, ProtocolError> {
        validate_review(start, count, minimum_score)?;
        Ok(Self {
            start,
            count,
            minimum_score,
        })
    }
}

#[derive(Clone, Copy)]
pub struct ReviewBatchGraphProfile {
    sql: &'static str,
    binding: OperationBinding,
}

impl ReviewBatchGraphProfile {
    pub fn new(sql: &'static str, binding: OperationBinding) -> Result<Self, ProtocolError> {
        if sql.trim().is_empty() {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(Self { sql, binding })
    }

    pub fn registered_graph(self) -> Result<RegisteredGraph, ProtocolError> {
        RegisteredGraph::new_read(
            REVIEW_BATCH_GRAPH_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
            MAXIMUM_REVIEW_BATCH_PARAMETER_BYTES,
            MAXIMUM_REVIEW_BATCH_RESULT_BYTES,
            MAXIMUM_REVIEW_BATCH_ITEMS,
            CAPABILITY_QUERY | CAPABILITY_GRAPH | CAPABILITY_AGGREGATE | CAPABILITY_BATCH,
            digest_label(
                REVIEW_BATCH_PARAMETER_SCHEMA_DOMAIN,
                b"item_count:u32,items:[start:i64,count:u32,minimum_score:i32]",
            ),
            self.implementation_digest(),
            [
                GraphNode::new(REVIEW_BATCH_INPUT_PLAN, REVIEW_BATCH_INPUT_SHAPE, [])?,
                GraphNode::new(REVIEW_BATCH_SELECT_PLAN, REVIEW_BATCH_SELECT_SHAPE, [0])?,
                GraphNode::new(REVIEW_BATCH_FILTER_PLAN, REVIEW_BATCH_FILTER_SHAPE, [0, 1])?,
                GraphNode::new(
                    REVIEW_BATCH_AGGREGATE_PLAN,
                    REVIEW_BATCH_AGGREGATE_SHAPE,
                    [0, 1, 2],
                )?,
            ],
        )
    }

    pub fn graph_registry(
        self,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<GraphRegistry, ProtocolError> {
        GraphRegistry::new(
            POSTGRESQL_ENGINE_ID,
            POSTGRESQL_REVIEW_BATCH_GRAPH_PROFILE_ID,
            schema_digest,
            policy_digest,
            CapabilityManifest::new(
                CAPABILITY_QUERY | CAPABILITY_GRAPH | CAPABILITY_AGGREGATE | CAPABILITY_BATCH,
            )?,
            [self.registered_graph()?],
        )
    }

    pub fn operation(self) -> Result<GraphOperation, ProtocolError> {
        GraphOperation::new(
            REVIEW_BATCH_GRAPH_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
        )
    }

    pub fn parameters(self, items: &[ReviewBatchItem]) -> Result<Vec<u8>, ProtocolError> {
        let item_count = validate_review_batch(items)?;
        let parameter_bytes = REVIEW_BATCH_HEADER_BYTES
            .checked_add(
                item_count
                    .checked_mul(REVIEW_BATCH_ITEM_BYTES)
                    .ok_or(ProtocolError::ParameterLimitExceeded)?,
            )
            .ok_or(ProtocolError::ParameterLimitExceeded)?;
        let mut parameters = Vec::with_capacity(parameter_bytes as usize);
        parameters.extend_from_slice(&item_count.to_le_bytes());
        for item in items {
            parameters.extend_from_slice(&item.start.to_le_bytes());
            parameters.extend_from_slice(&item.count.to_le_bytes());
            parameters.extend_from_slice(&item.minimum_score.to_le_bytes());
        }
        Ok(parameters)
    }

    pub fn maximum_result_bytes(item_count: u32) -> Result<u32, ProtocolError> {
        if item_count == 0 || item_count > MAXIMUM_REVIEW_BATCH_ITEMS {
            return Err(ProtocolError::BatchLimitExceeded);
        }
        REVIEW_BATCH_RESULT_HEADER_BYTES
            .checked_add(
                item_count
                    .checked_mul(REVIEW_BATCH_RESULT_ITEM_BYTES)
                    .ok_or(ProtocolError::ResultBudgetExceeded)?,
            )
            .ok_or(ProtocolError::ResultBudgetExceeded)
    }

    pub fn sql(self) -> &'static str {
        self.sql
    }

    fn implementation_digest(self) -> [u8; 32] {
        let mut graph = blake3::Hasher::new();
        graph.update(REVIEW_BATCH_GRAPH_DOMAIN);
        graph.update(self.sql.as_bytes());
        graph.update(&self.binding.plan_handle.to_le_bytes());
        graph.update(&self.binding.result_shape.to_le_bytes());
        *graph.finalize().as_bytes()
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

pub struct ReviewGraphBackend {
    client: Client,
    statement: Statement,
    profile: ReviewGraphProfile,
    identity: BackendIdentity,
    data_queries: u64,
}

pub struct ReviewBatchGraphBackend {
    client: Client,
    statement: Statement,
    profile: ReviewBatchGraphProfile,
    identity: BackendIdentity,
    starts: Vec<i64>,
    counts: Vec<i64>,
    minimum_scores: Vec<i32>,
    data_queries: u64,
}

pub trait GraphSessionAdmission {
    fn configure_and_verify(
        &self,
        client: &mut Client,
        maximum_statement_timeout_ms: u32,
    ) -> Result<(), ProtocolError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ServiceReadOnlyAdmission;

impl GraphSessionAdmission for ServiceReadOnlyAdmission {
    fn configure_and_verify(
        &self,
        client: &mut Client,
        maximum_statement_timeout_ms: u32,
    ) -> Result<(), ProtocolError> {
        configure_read_only_graph_session(client, maximum_statement_timeout_ms)
    }
}

impl ReviewBatchGraphBackend {
    pub fn new_registered(
        client: Client,
        profile: ReviewBatchGraphProfile,
        registry: &GraphRegistry,
        maximum_statement_timeout_ms: u32,
    ) -> Result<Self, ProtocolError> {
        Self::new_registered_with_admission(
            client,
            profile,
            registry,
            maximum_statement_timeout_ms,
            &ServiceReadOnlyAdmission,
        )
    }

    pub fn new_registered_with_admission<A: GraphSessionAdmission>(
        mut client: Client,
        profile: ReviewBatchGraphProfile,
        registry: &GraphRegistry,
        maximum_statement_timeout_ms: u32,
        admission: &A,
    ) -> Result<Self, ProtocolError> {
        if registry.identity().engine() != POSTGRESQL_ENGINE_ID
            || registry.identity().profile() != POSTGRESQL_REVIEW_BATCH_GRAPH_PROFILE_ID
            || registry.graphs() != [profile.registered_graph()?]
        {
            return Err(ProtocolError::PlanRegistryMismatch);
        }
        if maximum_statement_timeout_ms == 0 || maximum_statement_timeout_ms > 3_600_000 {
            return Err(ProtocolError::BudgetExceeded);
        }
        admission.configure_and_verify(&mut client, maximum_statement_timeout_ms)?;
        let statement = client
            .prepare(profile.sql())
            .map_err(|_| ProtocolError::BackendRefused)?;
        Ok(Self {
            client,
            statement,
            profile,
            identity: registry.identity(),
            starts: Vec::with_capacity(MAXIMUM_REVIEW_BATCH_ITEMS as usize),
            counts: Vec::with_capacity(MAXIMUM_REVIEW_BATCH_ITEMS as usize),
            minimum_scores: Vec::with_capacity(MAXIMUM_REVIEW_BATCH_ITEMS as usize),
            data_queries: 0,
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }
}

impl GraphBackend for ReviewBatchGraphBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_graph(
        &mut self,
        operation: GraphOperation,
        parameters: &[u8],
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        if operation != self.profile.operation()? || parameters.len() < 4 {
            return Err(ProtocolError::BackendRefused);
        }
        let item_count = u32::from_le_bytes(
            parameters[0..4]
                .try_into()
                .map_err(|_| ProtocolError::BackendRefused)?,
        );
        let expected_parameter_bytes = REVIEW_BATCH_HEADER_BYTES
            .checked_add(
                item_count
                    .checked_mul(REVIEW_BATCH_ITEM_BYTES)
                    .ok_or(ProtocolError::ParameterLimitExceeded)?,
            )
            .ok_or(ProtocolError::ParameterLimitExceeded)?;
        if parameters.len() != expected_parameter_bytes as usize
            || item_count == 0
            || item_count > MAXIMUM_REVIEW_BATCH_ITEMS
        {
            return Err(ProtocolError::BatchLimitExceeded);
        }
        if item_count > limits.maximum_rows {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        let required_bytes = ReviewBatchGraphProfile::maximum_result_bytes(item_count)?;
        if required_bytes > limits.maximum_result_bytes {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        output.reserve_total(required_bytes as usize)?;

        self.starts.clear();
        self.counts.clear();
        self.minimum_scores.clear();
        let mut source_rows = 0_u32;
        for item_index in 0..item_count as usize {
            let offset =
                REVIEW_BATCH_HEADER_BYTES as usize + item_index * REVIEW_BATCH_ITEM_BYTES as usize;
            let start = i64::from_le_bytes(
                parameters[offset..offset + 8]
                    .try_into()
                    .map_err(|_| ProtocolError::BackendRefused)?,
            );
            let count = u32::from_le_bytes(
                parameters[offset + 8..offset + 12]
                    .try_into()
                    .map_err(|_| ProtocolError::BackendRefused)?,
            );
            let minimum_score = i32::from_le_bytes(
                parameters[offset + 12..offset + 16]
                    .try_into()
                    .map_err(|_| ProtocolError::BackendRefused)?,
            );
            validate_review(start, count, minimum_score)?;
            source_rows = source_rows
                .checked_add(count)
                .ok_or(ProtocolError::RowBudgetExceeded)?;
            if source_rows > MAXIMUM_REVIEW_BATCH_SOURCE_ROWS {
                return Err(ProtocolError::RowBudgetExceeded);
            }
            self.starts.push(start);
            self.counts.push(i64::from(count));
            self.minimum_scores.push(minimum_score);
        }

        let rows = self
            .client
            .query(
                &self.statement,
                &[&self.starts, &self.counts, &self.minimum_scores],
            )
            .map_err(|_| ProtocolError::BackendRefused)?;
        self.data_queries = self.data_queries.saturating_add(1);
        if rows.len() != item_count as usize {
            return Err(ProtocolError::BackendRefused);
        }

        output.write_exact_reusing(required_bytes as usize, item_count, |bytes| {
            bytes[0..2].copy_from_slice(&REVIEW_BATCH_GRAPH_OPCODE.to_le_bytes());
            bytes[2..6].copy_from_slice(&item_count.to_le_bytes());
            for (index, row) in rows.iter().enumerate() {
                let ordinal: i64 = row.try_get(0).map_err(|_| ProtocolError::BackendRefused)?;
                let row_count: i64 = row.try_get(1).map_err(|_| ProtocolError::BackendRefused)?;
                let score_sum: i64 = row.try_get(2).map_err(|_| ProtocolError::BackendRefused)?;
                let expected_ordinal =
                    i64::try_from(index + 1).map_err(|_| ProtocolError::BackendRefused)?;
                let row_count =
                    u32::try_from(row_count).map_err(|_| ProtocolError::BackendRefused)?;
                if ordinal != expected_ordinal || row_count > self.counts[index] as u32 {
                    return Err(ProtocolError::BackendRefused);
                }
                let offset = REVIEW_BATCH_RESULT_HEADER_BYTES as usize
                    + index * REVIEW_BATCH_RESULT_ITEM_BYTES as usize;
                bytes[offset..offset + 4].copy_from_slice(
                    &u32::try_from(ordinal)
                        .map_err(|_| ProtocolError::BackendRefused)?
                        .to_le_bytes(),
                );
                bytes[offset + 4..offset + 8].copy_from_slice(&row_count.to_le_bytes());
                bytes[offset + 8..offset + 16].copy_from_slice(&score_sum.to_le_bytes());
            }
            Ok(())
        })
    }
}

impl ReviewGraphBackend {
    pub fn new_registered(
        mut client: Client,
        profile: ReviewGraphProfile,
        registry: &GraphRegistry,
        maximum_statement_timeout_ms: u32,
    ) -> Result<Self, ProtocolError> {
        if registry.identity().engine() != POSTGRESQL_ENGINE_ID
            || registry.identity().profile() != POSTGRESQL_REVIEW_GRAPH_PROFILE_ID
            || registry.graphs() != [profile.registered_graph()?]
        {
            return Err(ProtocolError::PlanRegistryMismatch);
        }
        configure_read_only_graph_session(&mut client, maximum_statement_timeout_ms)?;
        let statement = client
            .prepare(profile.sql())
            .map_err(|_| ProtocolError::BackendRefused)?;
        Ok(Self {
            client,
            statement,
            profile,
            identity: registry.identity(),
            data_queries: 0,
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }
}

fn configure_read_only_graph_session(
    client: &mut Client,
    maximum_statement_timeout_ms: u32,
) -> Result<(), ProtocolError> {
    if maximum_statement_timeout_ms == 0 || maximum_statement_timeout_ms > 3_600_000 {
        return Err(ProtocolError::BudgetExceeded);
    }
    client
        .batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        .map_err(|_| ProtocolError::BackendRefused)?;
    // Apply the database safety ceiling during session admission.
    // A per-request SET adds a second hot-path database exchange.
    // The protocol still checks each shorter frame deadline before and after execution.
    let timeout = format!("{maximum_statement_timeout_ms}ms");
    client
        .query_one(
            "SELECT set_config('statement_timeout', $1, false)",
            &[&timeout],
        )
        .map_err(|_| ProtocolError::BackendRefused)?;
    Ok(())
}

impl GraphBackend for ReviewGraphBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_graph(
        &mut self,
        operation: GraphOperation,
        parameters: &[u8],
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        if operation != self.profile.operation()?
            || parameters.len() != REVIEW_PARAMETER_BYTES as usize
        {
            return Err(ProtocolError::BackendRefused);
        }
        let start = i64::from_le_bytes(
            parameters[0..8]
                .try_into()
                .map_err(|_| ProtocolError::BackendRefused)?,
        );
        let count = u32::from_le_bytes(
            parameters[8..12]
                .try_into()
                .map_err(|_| ProtocolError::BackendRefused)?,
        );
        let minimum_score = i32::from_le_bytes(
            parameters[12..16]
                .try_into()
                .map_err(|_| ProtocolError::BackendRefused)?,
        );
        validate_review(start, count, minimum_score)?;
        if count > limits.maximum_rows {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        let maximum_bytes = 14_u64
            .checked_add(u64::from(count) * 84)
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        if maximum_bytes > u64::from(limits.maximum_result_bytes) {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        let count_i64 = i64::from(count);
        let rows = self
            .client
            .query(&self.statement, &[&start, &count_i64, &minimum_score])
            .map_err(|_| ProtocolError::BackendRefused)?;
        self.data_queries = self.data_queries.saturating_add(1);
        if rows.len() > count as usize {
            return Err(ProtocolError::BackendRefused);
        }
        let row_count = u32::try_from(rows.len()).map_err(|_| ProtocolError::RowBudgetExceeded)?;
        let score_sum = rows.first().map_or(Ok(0_i64), |row| {
            row.try_get(5).map_err(|_| ProtocolError::BackendRefused)
        })?;
        output.write(&REVIEW_GRAPH_OPCODE.to_le_bytes())?;
        output.write(&row_count.to_le_bytes())?;
        output.write(&score_sum.to_le_bytes())?;
        let end = start
            .checked_add(count_i64)
            .ok_or(ProtocolError::BackendRefused)?;
        let mut previous_id = None;
        for row in &rows {
            let id: i64 = row.try_get(0).map_err(|_| ProtocolError::BackendRefused)?;
            let score: i32 = row.try_get(3).map_err(|_| ProtocolError::BackendRefused)?;
            let row_sum: i64 = row.try_get(5).map_err(|_| ProtocolError::BackendRefused)?;
            if id < start
                || id >= end
                || score < minimum_score
                || row_sum != score_sum
                || previous_id.is_some_and(|previous| previous >= id)
            {
                return Err(ProtocolError::BackendRefused);
            }
            encode_expected_row(row, id, output)?;
            previous_id = Some(id);
        }
        Ok(())
    }
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
        .checked_add(i64::from(count))
        .ok_or(ProtocolError::BackendRefused)?;
    Ok(())
}

fn validate_review(start: i64, count: u32, minimum_score: i32) -> Result<(), ProtocolError> {
    validate_range(start, count)?;
    if !(0..10_000).contains(&minimum_score) {
        return Err(ProtocolError::BackendRefused);
    }
    Ok(())
}

fn validate_review_batch(items: &[ReviewBatchItem]) -> Result<u32, ProtocolError> {
    let item_count = u32::try_from(items.len()).map_err(|_| ProtocolError::BatchLimitExceeded)?;
    if item_count == 0 || item_count > MAXIMUM_REVIEW_BATCH_ITEMS {
        return Err(ProtocolError::BatchLimitExceeded);
    }
    let mut source_rows = 0_u32;
    for item in items {
        validate_review(item.start, item.count, item.minimum_score)?;
        source_rows = source_rows
            .checked_add(item.count)
            .ok_or(ProtocolError::RowBudgetExceeded)?;
    }
    if source_rows > MAXIMUM_REVIEW_BATCH_SOURCE_ROWS {
        return Err(ProtocolError::RowBudgetExceeded);
    }
    Ok(item_count)
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

    pub fn execute_graph<R: ReplayStore, C: Clock, B: GraphBackend>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<GraphExecution, ProtocolError> {
        self.inner.execute_graph(frame, backend, replay, clock)
    }

    pub fn execute_graph_reusing<'a, R: ReplayStore, C: Clock, B: GraphBackend>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
        result_buffer: &'a mut Vec<u8>,
    ) -> Result<BorrowedGraphExecution<'a>, ProtocolError> {
        self.inner
            .execute_graph_reusing(frame, backend, replay, clock, result_buffer)
    }

    pub fn register_operand_bundle<R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        registry: &GraphRegistry,
        layout: &OperandLayout,
        store: &mut OperandBundleStore,
        replay: &mut R,
        clock: &C,
    ) -> Result<BundleAccepted, ProtocolError> {
        self.inner
            .register_operand_bundle(frame, registry, layout, store, replay, clock)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_bundled_graph<B: BundledGraphBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        registry: &GraphRegistry,
        layout: &OperandLayout,
        store: &mut OperandBundleStore,
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<BundledGraphExecution, ProtocolError> {
        self.inner
            .execute_bundled_graph(frame, registry, layout, store, backend, replay, clock)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_bundled_graph_reusing<'a, B: BundledGraphBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        registry: &GraphRegistry,
        layout: &OperandLayout,
        store: &mut OperandBundleStore,
        backend: &mut B,
        replay: &mut R,
        clock: &C,
        result_buffer: &'a mut Vec<u8>,
    ) -> Result<BorrowedBundledGraphExecution<'a>, ProtocolError> {
        self.inner.execute_bundled_graph_reusing(
            frame,
            registry,
            layout,
            store,
            backend,
            replay,
            clock,
            result_buffer,
        )
    }

    pub fn remove_operand_bundle<R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        registry: &GraphRegistry,
        store: &mut OperandBundleStore,
        replay: &mut R,
        clock: &C,
    ) -> Result<BundleRemoved, ProtocolError> {
        self.inner
            .remove_operand_bundle(frame, registry, store, replay, clock)
    }
}

pub fn memory_replay_store() -> MemoryReplayStore {
    MemoryReplayStore::default()
}

pub fn single_session_replay_store() -> SingleSessionReplayStore {
    SingleSessionReplayStore::default()
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

    #[test]
    fn the_review_graph_binds_three_nodes_and_typed_parameters() {
        const REVIEW_SQL: &str = "WITH selected AS (SELECT id,bucket,owner,score,payload FROM items WHERE id >= $1 AND id < $1 + $2 AND score >= $3 ORDER BY id LIMIT $2) SELECT id,bucket,owner,score,payload,SUM(score) OVER ()::bigint FROM selected ORDER BY id";
        let profile =
            ReviewGraphProfile::new(REVIEW_SQL, OperationBinding::new(50, 51).expect("binding"))
                .expect("profile");
        let registry = profile.graph_registry([1; 32], [2; 32]).expect("registry");
        let graph = registry.graph(50).expect("graph");
        assert_eq!(graph.nodes().len(), 3);
        assert_eq!(graph.nodes()[1].dependencies(), [0]);
        assert_eq!(graph.nodes()[2].dependencies(), [0, 1]);
        assert_eq!(
            profile.parameters(10, 20, 30).expect("parameters"),
            [10, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 30, 0, 0, 0]
        );
    }

    #[test]
    fn the_review_graph_refuses_invalid_operands() {
        let profile =
            ReviewGraphProfile::new("SELECT 1", OperationBinding::new(50, 51).expect("binding"))
                .expect("profile");
        assert!(profile.parameters(0, 1, 0).is_err());
        assert!(profile.parameters(1, 0, 0).is_err());
        assert!(profile.parameters(i64::MAX, 1, 0).is_err());
        assert!(profile.parameters(1, 1, -1).is_err());
        assert!(profile.parameters(1, 1, 10_000).is_err());
    }

    #[test]
    fn the_review_batch_graph_binds_four_nodes_and_canonical_items() {
        let profile = ReviewBatchGraphProfile::new(
            "SELECT 1",
            OperationBinding::new(60, 61).expect("binding"),
        )
        .expect("profile");
        let registry = profile.graph_registry([1; 32], [2; 32]).expect("registry");
        let graph = registry.graph(60).expect("graph");
        assert_eq!(graph.nodes().len(), 4);
        assert_eq!(graph.nodes()[3].dependencies(), [0, 1, 2]);
        let items = [
            ReviewBatchItem::new(10, 100, 50).expect("first item"),
            ReviewBatchItem::new(200, 50, 225).expect("second item"),
        ];
        let parameters = profile.parameters(&items).expect("parameters");
        assert_eq!(parameters.len(), 4 + 2 * 16);
        assert_eq!(&parameters[0..4], &2_u32.to_le_bytes());
        assert_eq!(&parameters[4..12], &10_i64.to_le_bytes());
        assert_eq!(&parameters[12..16], &100_u32.to_le_bytes());
        assert_eq!(&parameters[16..20], &50_i32.to_le_bytes());
        assert_eq!(
            ReviewBatchGraphProfile::maximum_result_bytes(2).expect("result budget"),
            38
        );
    }

    #[test]
    fn the_review_batch_graph_refuses_empty_and_excessive_work() {
        let profile = ReviewBatchGraphProfile::new(
            "SELECT 1",
            OperationBinding::new(60, 61).expect("binding"),
        )
        .expect("profile");
        assert!(profile.parameters(&[]).is_err());
        let maximum = ReviewBatchItem::new(1, 64, 0).expect("maximum item");
        assert!(profile
            .parameters(&vec![maximum; MAXIMUM_REVIEW_BATCH_ITEMS as usize])
            .is_ok());
        let excessive = ReviewBatchItem::new(1, 65, 0).expect("excessive item");
        assert!(profile
            .parameters(&vec![excessive; MAXIMUM_REVIEW_BATCH_ITEMS as usize])
            .is_err());
        assert!(profile
            .parameters(&vec![maximum; MAXIMUM_REVIEW_BATCH_ITEMS as usize + 1])
            .is_err());
    }
}
