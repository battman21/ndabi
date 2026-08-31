//! Execute one registered PostgreSQL graph with immutable ranges and changing thresholds.
//!
//! Bundle registration retains the range arrays outside the execution hot path.
//! Each execution sends only the score thresholds and one authenticated bundle handle.

use ndabi_protocol::{
    BackendIdentity, BoundedOutput, BundledGraphBackend, BundledOperandContext, CapabilityManifest,
    ExecutionLimits, GraphNode, GraphOperation, GraphRegistry, OperandLayout, OperandSlot,
    OperandStorage, OperandType, OperandValue, OperandValues, ProtocolError, RegisteredGraph,
    CAPABILITY_AGGREGATE, CAPABILITY_BATCH, CAPABILITY_GRAPH, CAPABILITY_QUERY,
};
use postgres::{Client, Statement};
use zeroize::{Zeroize, Zeroizing};

use super::{
    validate_range, validate_review_batch, GraphSessionAdmission, OperationBinding,
    ReviewBatchGraphProfile, ReviewBatchItem, ServiceReadOnlyAdmission, POSTGRESQL_ENGINE_ID,
    REVIEW_BATCH_GRAPH_OPCODE,
};

pub const POSTGRESQL_REVIEW_OPERAND_BUNDLE_PROFILE_ID: u32 = 0x5047_1005;
pub const REVIEW_OPERAND_BUNDLE_OPCODE: u16 = 4;

const MAXIMUM_ITEMS: u32 = 1_024;
const MAXIMUM_SOURCE_ROWS: u32 = 65_536;
const START_SLOT: u16 = 1;
const COUNT_SLOT: u16 = 2;
const THRESHOLD_SLOT: u16 = 3;
const IMPLEMENTATION_DOMAIN: &[u8] = b"ndabi/postgresql/review-operand-bundle/v1";
const START_BYTES: u32 = MAXIMUM_ITEMS * 8;
const COUNT_BYTES: u32 = MAXIMUM_ITEMS * 4;
const THRESHOLD_BYTES: u32 = MAXIMUM_ITEMS * 4;
const INPUT_PLAN: u32 = 0x5047_2201;
const SELECT_PLAN: u32 = 0x5047_2202;
const FILTER_PLAN: u32 = 0x5047_2203;
const AGGREGATE_PLAN: u32 = 0x5047_2204;
const INPUT_SHAPE: u32 = 0x5047_3201;
const SELECT_SHAPE: u32 = 0x5047_3202;
const FILTER_SHAPE: u32 = 0x5047_3203;
const AGGREGATE_SHAPE: u32 = 0x5047_3204;

#[derive(Clone, Copy)]
pub struct ReviewOperandBundleProfile {
    sql: &'static str,
    binding: OperationBinding,
}

impl ReviewOperandBundleProfile {
    pub fn new(sql: &'static str, binding: OperationBinding) -> Result<Self, ProtocolError> {
        if sql.trim().is_empty() {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(Self { sql, binding })
    }

    pub fn operand_layout(self) -> Result<OperandLayout, ProtocolError> {
        OperandLayout::new([
            OperandSlot::new(
                START_SLOT,
                OperandStorage::Bundle,
                OperandType::Bytes,
                false,
                START_BYTES,
            )?,
            OperandSlot::new(
                COUNT_SLOT,
                OperandStorage::Bundle,
                OperandType::Bytes,
                false,
                COUNT_BYTES,
            )?,
            OperandSlot::new(
                THRESHOLD_SLOT,
                OperandStorage::Execution,
                OperandType::Bytes,
                false,
                THRESHOLD_BYTES,
            )?,
        ])
    }

    pub fn registered_graph(self) -> Result<RegisteredGraph, ProtocolError> {
        let layout = self.operand_layout()?;
        RegisteredGraph::new_read(
            REVIEW_OPERAND_BUNDLE_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
            layout.maximum_record_bytes(),
            ReviewBatchGraphProfile::maximum_result_bytes(MAXIMUM_ITEMS)?,
            MAXIMUM_ITEMS,
            CAPABILITY_QUERY | CAPABILITY_GRAPH | CAPABILITY_AGGREGATE | CAPABILITY_BATCH,
            layout.digest(),
            self.implementation_digest(),
            [
                GraphNode::new(INPUT_PLAN, INPUT_SHAPE, [])?,
                GraphNode::new(SELECT_PLAN, SELECT_SHAPE, [0])?,
                GraphNode::new(FILTER_PLAN, FILTER_SHAPE, [0, 1])?,
                GraphNode::new(AGGREGATE_PLAN, AGGREGATE_SHAPE, [0, 1, 2])?,
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
            POSTGRESQL_REVIEW_OPERAND_BUNDLE_PROFILE_ID,
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
            REVIEW_OPERAND_BUNDLE_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
        )
    }

    pub fn operands(
        self,
        items: &[ReviewBatchItem],
    ) -> Result<(ReviewBatchBundle, ReviewBatchThresholds), ProtocolError> {
        Ok((
            self.bundle(items)?,
            ReviewBatchThresholds::from_items(items)?,
        ))
    }

    pub fn bundle(self, items: &[ReviewBatchItem]) -> Result<ReviewBatchBundle, ProtocolError> {
        let _ = self;
        ReviewBatchBundle::new(items)
    }

    pub fn thresholds(
        self,
        minimum_scores: &[i32],
    ) -> Result<ReviewBatchThresholds, ProtocolError> {
        let _ = self;
        ReviewBatchThresholds::new(minimum_scores)
    }

    pub fn maximum_result_bytes(item_count: u32) -> Result<u32, ProtocolError> {
        ReviewBatchGraphProfile::maximum_result_bytes(item_count)
    }

    pub fn sql(self) -> &'static str {
        self.sql
    }

    fn implementation_digest(self) -> [u8; 32] {
        let mut graph = blake3::Hasher::new();
        graph.update(IMPLEMENTATION_DOMAIN);
        graph.update(self.sql.as_bytes());
        graph.update(&self.binding.plan_handle.to_le_bytes());
        graph.update(&self.binding.result_shape.to_le_bytes());
        *graph.finalize().as_bytes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewBatchBundle {
    starts: Zeroizing<Vec<u8>>,
    counts: Zeroizing<Vec<u8>>,
    item_count: u32,
}

impl ReviewBatchBundle {
    fn new(items: &[ReviewBatchItem]) -> Result<Self, ProtocolError> {
        let item_count = validate_review_batch(items)?;
        let mut starts = Vec::with_capacity(item_count as usize * 8);
        let mut counts = Vec::with_capacity(item_count as usize * 4);
        for item in items {
            starts.extend_from_slice(&item.start.to_le_bytes());
            counts.extend_from_slice(&item.count.to_le_bytes());
        }
        Ok(Self {
            starts: Zeroizing::new(starts),
            counts: Zeroizing::new(counts),
            item_count,
        })
    }

    pub fn item_count(&self) -> u32 {
        self.item_count
    }

    pub fn operand_values(&self) -> [OperandValue<'_>; 2] {
        [
            OperandValue {
                slot_id: START_SLOT,
                value: Some(self.starts.as_slice()),
            },
            OperandValue {
                slot_id: COUNT_SLOT,
                value: Some(self.counts.as_slice()),
            },
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewBatchThresholds {
    values: Zeroizing<Vec<u8>>,
    item_count: u32,
}

impl ReviewBatchThresholds {
    fn from_items(items: &[ReviewBatchItem]) -> Result<Self, ProtocolError> {
        validate_review_batch(items)?;
        let mut values = Vec::with_capacity(items.len() * 4);
        for item in items {
            values.extend_from_slice(&item.minimum_score.to_le_bytes());
        }
        Ok(Self {
            values: Zeroizing::new(values),
            item_count: items.len() as u32,
        })
    }

    fn new(minimum_scores: &[i32]) -> Result<Self, ProtocolError> {
        let item_count =
            u32::try_from(minimum_scores.len()).map_err(|_| ProtocolError::BatchLimitExceeded)?;
        if item_count == 0
            || item_count > MAXIMUM_ITEMS
            || minimum_scores
                .iter()
                .any(|score| !(0..10_000).contains(score))
        {
            return Err(ProtocolError::BackendRefused);
        }
        let mut values = Vec::with_capacity(item_count as usize * 4);
        for minimum_score in minimum_scores {
            values.extend_from_slice(&minimum_score.to_le_bytes());
        }
        Ok(Self {
            values: Zeroizing::new(values),
            item_count,
        })
    }

    pub fn item_count(&self) -> u32 {
        self.item_count
    }

    pub fn operand_values(&self) -> [OperandValue<'_>; 1] {
        [OperandValue {
            slot_id: THRESHOLD_SLOT,
            value: Some(self.values.as_slice()),
        }]
    }
}

pub struct ReviewOperandBundleBackend {
    client: Client,
    statement: Statement,
    profile: ReviewOperandBundleProfile,
    identity: BackendIdentity,
    starts: Vec<i64>,
    counts: Vec<i64>,
    minimum_scores: Vec<i32>,
    cached_bundle_digest: Option<[u8; 32]>,
    bundle_decodes: u64,
    data_queries: u64,
}

impl Drop for ReviewOperandBundleBackend {
    fn drop(&mut self) {
        self.starts.zeroize();
        self.counts.zeroize();
        self.minimum_scores.zeroize();
        if let Some(digest) = &mut self.cached_bundle_digest {
            digest.zeroize();
        }
    }
}

impl ReviewOperandBundleBackend {
    pub fn new_registered(
        client: Client,
        profile: ReviewOperandBundleProfile,
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
        profile: ReviewOperandBundleProfile,
        registry: &GraphRegistry,
        maximum_statement_timeout_ms: u32,
        admission: &A,
    ) -> Result<Self, ProtocolError> {
        if registry.identity().engine() != POSTGRESQL_ENGINE_ID
            || registry.identity().profile() != POSTGRESQL_REVIEW_OPERAND_BUNDLE_PROFILE_ID
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
            starts: Vec::with_capacity(MAXIMUM_ITEMS as usize),
            counts: Vec::with_capacity(MAXIMUM_ITEMS as usize),
            minimum_scores: Vec::with_capacity(MAXIMUM_ITEMS as usize),
            cached_bundle_digest: None,
            bundle_decodes: 0,
            data_queries: 0,
        })
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }

    pub fn bundle_decodes(&self) -> u64 {
        self.bundle_decodes
    }
}

impl BundledGraphBackend for ReviewOperandBundleBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute_bundled_graph(
        &mut self,
        operation: GraphOperation,
        bundle_context: BundledOperandContext,
        bundle_values: OperandValues<'_>,
        execution_values: OperandValues<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        if operation != self.profile.operation()? {
            return Err(ProtocolError::BackendRefused);
        }
        if self.cached_bundle_digest != Some(bundle_context.bundle_digest) {
            // Clear the key before decoding.
            // A partial refusal must not label modified arrays as the earlier bundle.
            self.cached_bundle_digest = None;
            decode_bundle_operands(bundle_values, &mut self.starts, &mut self.counts)?;
            self.cached_bundle_digest = Some(bundle_context.bundle_digest);
            self.bundle_decodes = self.bundle_decodes.saturating_add(1);
        }
        decode_thresholds(
            execution_values,
            self.starts.len(),
            &mut self.minimum_scores,
        )?;
        let item_count =
            u32::try_from(self.starts.len()).map_err(|_| ProtocolError::BatchLimitExceeded)?;
        if item_count > limits.maximum_rows {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        let required_bytes = ReviewOperandBundleProfile::maximum_result_bytes(item_count)?;
        if required_bytes > limits.maximum_result_bytes {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        output.reserve_total(required_bytes as usize)?;
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
            // Reuse the registered review result encoding across both request profiles.
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
                let offset = 6 + index * 16;
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

fn decode_bundle_operands(
    bundle_values: OperandValues<'_>,
    starts: &mut Vec<i64>,
    counts: &mut Vec<i64>,
) -> Result<(), ProtocolError> {
    let mut bundle = bundle_values.iter();
    let start_bytes = exact_bytes(bundle.next(), START_SLOT)?;
    let count_bytes = exact_bytes(bundle.next(), COUNT_SLOT)?;
    if bundle.next().is_some() {
        return Err(ProtocolError::OperandValueInvalid);
    }
    if start_bytes.is_empty()
        || !start_bytes.len().is_multiple_of(8)
        || !count_bytes.len().is_multiple_of(4)
        || start_bytes.len() / 8 != count_bytes.len() / 4
        || start_bytes.len() / 8 > MAXIMUM_ITEMS as usize
    {
        return Err(ProtocolError::OperandValueInvalid);
    }

    starts.clear();
    counts.clear();
    let mut source_rows = 0_u32;
    for index in 0..start_bytes.len() / 8 {
        let start_offset = index * 8;
        let value_offset = index * 4;
        let start = i64::from_le_bytes(
            start_bytes[start_offset..start_offset + 8]
                .try_into()
                .map_err(|_| ProtocolError::OperandValueInvalid)?,
        );
        let count = u32::from_le_bytes(
            count_bytes[value_offset..value_offset + 4]
                .try_into()
                .map_err(|_| ProtocolError::OperandValueInvalid)?,
        );
        validate_range(start, count)?;
        source_rows = source_rows
            .checked_add(count)
            .ok_or(ProtocolError::RowBudgetExceeded)?;
        if source_rows > MAXIMUM_SOURCE_ROWS {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        starts.push(start);
        counts.push(i64::from(count));
    }
    Ok(())
}

fn decode_thresholds(
    execution_values: OperandValues<'_>,
    expected_items: usize,
    minimum_scores: &mut Vec<i32>,
) -> Result<(), ProtocolError> {
    let mut execution = execution_values.iter();
    let threshold_bytes = exact_bytes(execution.next(), THRESHOLD_SLOT)?;
    if execution.next().is_some()
        || !threshold_bytes.len().is_multiple_of(4)
        || threshold_bytes.len() / 4 != expected_items
    {
        return Err(ProtocolError::OperandValueInvalid);
    }
    minimum_scores.clear();
    for value in threshold_bytes.chunks_exact(4) {
        let minimum_score = i32::from_le_bytes(
            value
                .try_into()
                .map_err(|_| ProtocolError::OperandValueInvalid)?,
        );
        if !(0..10_000).contains(&minimum_score) {
            return Err(ProtocolError::BackendRefused);
        }
        minimum_scores.push(minimum_score);
    }
    Ok(())
}

fn exact_bytes<'a>(
    value: Option<ndabi_protocol::OperandValueRef<'a>>,
    slot_id: u16,
) -> Result<&'a [u8], ProtocolError> {
    let value = value.ok_or(ProtocolError::OperandValueInvalid)?;
    if value.slot_id != slot_id || value.value_type != OperandType::Bytes {
        return Err(ProtocolError::OperandValueInvalid);
    }
    value.value.ok_or(ProtocolError::OperandValueInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ReviewOperandBundleProfile {
        ReviewOperandBundleProfile::new("SELECT 1", OperationBinding::new(71, 73).expect("binding"))
            .expect("profile")
    }

    #[test]
    fn the_profile_binds_the_operand_layout_and_splits_static_values() {
        let profile = profile();
        let layout = profile.operand_layout().expect("layout");
        let graph = profile.registered_graph().expect("graph");
        assert_eq!(graph.parameter_schema_digest(), layout.digest());
        assert_eq!(layout.slot_count(OperandStorage::Bundle), 2);
        assert_eq!(layout.slot_count(OperandStorage::Execution), 1);

        let items = [
            ReviewBatchItem::new(10, 20, 30).expect("first"),
            ReviewBatchItem::new(40, 50, 60).expect("second"),
        ];
        let (bundle, thresholds) = profile.operands(&items).expect("operands");
        assert_eq!(bundle.item_count(), 2);
        assert_eq!(thresholds.item_count(), 2);
        let encoded_bundle = layout
            .encode_values(OperandStorage::Bundle, &bundle.operand_values())
            .expect("bundle values");
        let encoded_thresholds = layout
            .encode_values(OperandStorage::Execution, &thresholds.operand_values())
            .expect("execution values");
        assert!(encoded_bundle.len() > encoded_thresholds.len());
    }

    #[test]
    fn the_backend_decoder_refuses_mismatched_dynamic_operands() {
        let profile = profile();
        let layout = profile.operand_layout().expect("layout");
        let items = [
            ReviewBatchItem::new(10, 20, 30).expect("first"),
            ReviewBatchItem::new(40, 50, 60).expect("second"),
        ];
        let (bundle, thresholds) = profile.operands(&items).expect("operands");
        let encoded_bundle = layout
            .encode_values(OperandStorage::Bundle, &bundle.operand_values())
            .expect("bundle values");
        let encoded_thresholds = layout
            .encode_values(OperandStorage::Execution, &thresholds.operand_values())
            .expect("execution values");
        let bundle_values = layout
            .validate_values(OperandStorage::Bundle, &encoded_bundle)
            .expect("validated bundle");
        let execution_values = layout
            .validate_values(OperandStorage::Execution, &encoded_thresholds)
            .expect("validated execution");
        let mut starts = Vec::new();
        let mut counts = Vec::new();
        let mut minimum_scores = Vec::new();
        decode_bundle_operands(bundle_values, &mut starts, &mut counts)
            .expect("decoded bundle operands");
        decode_thresholds(bundle_values, starts.len(), &mut minimum_scores)
            .expect_err("bundle values cannot replace thresholds");
        decode_thresholds(execution_values, starts.len(), &mut minimum_scores)
            .expect("decoded thresholds");
        assert_eq!(starts, [10, 40]);
        assert_eq!(counts, [20, 50]);
        assert_eq!(minimum_scores, [30, 60]);

        let one_threshold = 30_i32.to_le_bytes();
        let invalid = layout
            .encode_values(
                OperandStorage::Execution,
                &[OperandValue {
                    slot_id: THRESHOLD_SLOT,
                    value: Some(&one_threshold),
                }],
            )
            .expect("valid wire value");
        assert_eq!(
            decode_thresholds(
                layout
                    .validate_values(OperandStorage::Execution, &invalid)
                    .expect("validated mismatch"),
                starts.len(),
                &mut minimum_scores,
            ),
            Err(ProtocolError::OperandValueInvalid)
        );
    }
}
