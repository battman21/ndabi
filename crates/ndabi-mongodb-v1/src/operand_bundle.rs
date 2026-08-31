//! Lower one registered identifier bundle into one bounded MongoDB find operation.
//!
//! Registration retains immutable identifiers. Execution supplies only one changing score threshold.
//! The profile fixes the database, collection, filter, projection, order, batch size, and deadline.

use std::time::Duration;

use mongodb::bson::doc;
use mongodb::sync::{Client, Collection};
use ndabi_protocol::{
    BackendIdentity, BoundedOutput, BundledGraphBackend, BundledOperandContext, CapabilityManifest,
    ExecutionLimits, GraphNode, GraphOperation, GraphRegistry, OperandLayout, OperandSlot,
    OperandStorage, OperandType, OperandValue, OperandValueRef, OperandValues, ProtocolError,
    RegisteredGraph, CAPABILITY_BATCH, CAPABILITY_GRAPH, CAPABILITY_QUERY,
};
use zeroize::{Zeroize, Zeroizing};

use super::{encode_item, MongoItem, OperationBinding, MONGODB_ENGINE_ID, ROW_BYTES};

pub const MONGODB_ID_SET_BUNDLE_PROFILE_ID: u32 = 0x4d47_1003;
const FIND_ID_SET_OPCODE: u16 = 0x23;
const MAXIMUM_ITEMS: u32 = 1_024;
const IDENTIFIER_SLOT: u16 = 1;
const SCORE_SLOT: u16 = 2;
const IDENTIFIER_BYTES: u32 = MAXIMUM_ITEMS * 8;
const INPUT_PLAN: u32 = 0x4d47_2201;
const FIND_PLAN: u32 = 0x4d47_2202;
const FILTER_PLAN: u32 = 0x4d47_2203;
const INPUT_SHAPE: u32 = 0x4d47_3201;
const FIND_SHAPE: u32 = 0x4d47_3202;
const FILTER_SHAPE: u32 = 0x4d47_3203;
const IMPLEMENTATION_DOMAIN: &[u8] = b"ndabi/mongodb/id-set-operand-bundle/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdSetBundle {
    identifiers: Zeroizing<Vec<u8>>,
    item_count: u32,
}

impl IdSetBundle {
    pub fn new(identifiers: &[i64]) -> Result<Self, ProtocolError> {
        let item_count = validate_identifiers(identifiers)?;
        let mut bytes = Vec::with_capacity(identifiers.len() * 8);
        for identifier in identifiers {
            bytes.extend_from_slice(&identifier.to_le_bytes());
        }
        Ok(Self {
            identifiers: Zeroizing::new(bytes),
            item_count,
        })
    }

    pub fn item_count(&self) -> u32 {
        self.item_count
    }

    pub fn operand_values(&self) -> [OperandValue<'_>; 1] {
        [OperandValue {
            slot_id: IDENTIFIER_SLOT,
            value: Some(self.identifiers.as_slice()),
        }]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScoreThreshold(Zeroizing<Vec<u8>>);

impl ScoreThreshold {
    pub fn new(minimum_score: i32) -> Result<Self, ProtocolError> {
        if !(0..10_000).contains(&minimum_score) {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(Self(Zeroizing::new(
            i64::from(minimum_score).to_le_bytes().to_vec(),
        )))
    }

    pub fn operand_values(&self) -> [OperandValue<'_>; 1] {
        [OperandValue {
            slot_id: SCORE_SLOT,
            value: Some(self.0.as_slice()),
        }]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdSetBundleProfile {
    database: String,
    collection: String,
    binding: OperationBinding,
}

impl IdSetBundleProfile {
    pub fn new(
        database: impl Into<String>,
        collection: impl Into<String>,
        binding: OperationBinding,
    ) -> Result<Self, ProtocolError> {
        let database = database.into();
        let collection = collection.into();
        if database.is_empty() || collection.is_empty() {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(Self {
            database,
            collection,
            binding,
        })
    }

    pub fn operand_layout(&self) -> Result<OperandLayout, ProtocolError> {
        OperandLayout::new([
            OperandSlot::new(
                IDENTIFIER_SLOT,
                OperandStorage::Bundle,
                OperandType::Bytes,
                false,
                IDENTIFIER_BYTES,
            )?,
            OperandSlot::new(
                SCORE_SLOT,
                OperandStorage::Execution,
                OperandType::I64,
                false,
                8,
            )?,
        ])
    }

    pub fn registered_graph(&self) -> Result<RegisteredGraph, ProtocolError> {
        let layout = self.operand_layout()?;
        RegisteredGraph::new_read(
            FIND_ID_SET_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
            layout.maximum_record_bytes(),
            MAXIMUM_ITEMS * ROW_BYTES as u32,
            MAXIMUM_ITEMS,
            CAPABILITY_QUERY | CAPABILITY_GRAPH | CAPABILITY_BATCH,
            layout.digest(),
            self.implementation_digest(),
            [
                GraphNode::new(INPUT_PLAN, INPUT_SHAPE, [])?,
                GraphNode::new(FIND_PLAN, FIND_SHAPE, [0])?,
                GraphNode::new(FILTER_PLAN, FILTER_SHAPE, [0, 1])?,
            ],
        )
    }

    pub fn graph_registry(
        &self,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<GraphRegistry, ProtocolError> {
        GraphRegistry::new(
            MONGODB_ENGINE_ID,
            MONGODB_ID_SET_BUNDLE_PROFILE_ID,
            schema_digest,
            policy_digest,
            CapabilityManifest::new(CAPABILITY_QUERY | CAPABILITY_GRAPH | CAPABILITY_BATCH)?,
            [self.registered_graph()?],
        )
    }

    pub fn operation(&self) -> Result<GraphOperation, ProtocolError> {
        GraphOperation::new(
            FIND_ID_SET_OPCODE,
            self.binding.plan_handle,
            self.binding.result_shape,
        )
    }

    fn implementation_digest(&self) -> [u8; 32] {
        let mut digest = blake3::Hasher::new();
        digest.update(IMPLEMENTATION_DOMAIN);
        digest.update(self.database.as_bytes());
        digest.update(self.collection.as_bytes());
        digest.update(b"find:_id-in-and-score-gte;project:registered-fields;sort:_id-asc");
        digest.update(&self.binding.plan_handle.to_le_bytes());
        digest.update(&self.binding.result_shape.to_le_bytes());
        *digest.finalize().as_bytes()
    }
}

pub struct IdSetBundleBackend {
    collection: Collection<MongoItem>,
    profile: IdSetBundleProfile,
    identity: BackendIdentity,
    identifiers: Vec<i64>,
    cached_bundle_digest: Option<[u8; 32]>,
    bundle_decodes: u64,
    data_queries: u64,
}

impl Drop for IdSetBundleBackend {
    fn drop(&mut self) {
        self.identifiers.zeroize();
        if let Some(digest) = &mut self.cached_bundle_digest {
            digest.zeroize();
        }
    }
}

impl IdSetBundleBackend {
    pub fn from_client_registered(
        client: Client,
        profile: IdSetBundleProfile,
        registry: &GraphRegistry,
    ) -> Result<Self, ProtocolError> {
        if registry.identity().engine() != MONGODB_ENGINE_ID
            || registry.identity().profile() != MONGODB_ID_SET_BUNDLE_PROFILE_ID
            || registry.graphs() != [profile.registered_graph()?]
        {
            return Err(ProtocolError::PlanRegistryMismatch);
        }
        let collection = client
            .database(&profile.database)
            .collection(&profile.collection);
        Ok(Self {
            collection,
            profile,
            identity: registry.identity(),
            identifiers: Vec::with_capacity(MAXIMUM_ITEMS as usize),
            cached_bundle_digest: None,
            bundle_decodes: 0,
            data_queries: 0,
        })
    }

    pub fn bundle_decodes(&self) -> u64 {
        self.bundle_decodes
    }

    pub fn data_queries(&self) -> u64 {
        self.data_queries
    }
}

impl BundledGraphBackend for IdSetBundleBackend {
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
            self.cached_bundle_digest = None;
            decode_identifiers(bundle_values, &mut self.identifiers)?;
            self.cached_bundle_digest = Some(bundle_context.bundle_digest);
            self.bundle_decodes = self.bundle_decodes.saturating_add(1);
        }
        let minimum_score = decode_threshold(execution_values)?;
        let item_count =
            u32::try_from(self.identifiers.len()).map_err(|_| ProtocolError::BatchLimitExceeded)?;
        if item_count > limits.maximum_rows {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        let required_bytes = item_count
            .checked_mul(ROW_BYTES as u32)
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        if required_bytes > limits.maximum_result_bytes {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        let remaining_us = limits
            .deadline_unix_us
            .checked_sub(limits.admitted_unix_us)
            .ok_or(ProtocolError::Expired)?;
        let mut cursor = self
            .collection
            .find(doc! {
                "_id": { "$in": &self.identifiers },
                "score": { "$gte": minimum_score },
            })
            .projection(doc! {
                "_id": 1,
                "bucket": 1,
                "owner": 1,
                "score": 1,
                "payload": 1,
            })
            .sort(doc! { "_id": 1 })
            .batch_size(item_count)
            .limit(-i64::from(item_count))
            .max_time(Duration::from_micros(remaining_us.max(1)))
            .run()
            .map_err(|_| ProtocolError::BackendRefused)?;
        self.data_queries = self.data_queries.saturating_add(1);
        let mut previous = None;
        for result in &mut cursor {
            let item = result.map_err(|_| ProtocolError::BackendRefused)?;
            if item.score < minimum_score
                || self.identifiers.binary_search(&item.id).is_err()
                || previous.is_some_and(|identifier| item.id <= identifier)
            {
                return Err(ProtocolError::BackendRefused);
            }
            encode_item(&item, output)?;
            previous = Some(item.id);
        }
        Ok(())
    }
}

fn validate_identifiers(identifiers: &[i64]) -> Result<u32, ProtocolError> {
    let item_count =
        u32::try_from(identifiers.len()).map_err(|_| ProtocolError::BatchLimitExceeded)?;
    if item_count == 0
        || item_count > MAXIMUM_ITEMS
        || identifiers.iter().any(|identifier| *identifier < 0)
        || identifiers.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ProtocolError::BackendRefused);
    }
    Ok(item_count)
}

fn decode_identifiers(
    values: OperandValues<'_>,
    identifiers: &mut Vec<i64>,
) -> Result<(), ProtocolError> {
    let mut values = values.iter();
    let bytes = exact_value(values.next(), IDENTIFIER_SLOT, OperandType::Bytes)?;
    if values.next().is_some() || bytes.is_empty() || !bytes.len().is_multiple_of(8) {
        return Err(ProtocolError::OperandValueInvalid);
    }
    identifiers.clear();
    for bytes in bytes.chunks_exact(8) {
        identifiers.push(i64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| ProtocolError::OperandValueInvalid)?,
        ));
    }
    validate_identifiers(identifiers)?;
    Ok(())
}

fn decode_threshold(values: OperandValues<'_>) -> Result<i32, ProtocolError> {
    let mut values = values.iter();
    let bytes = exact_value(values.next(), SCORE_SLOT, OperandType::I64)?;
    if values.next().is_some() || bytes.len() != 8 {
        return Err(ProtocolError::OperandValueInvalid);
    }
    let value = i32::try_from(i64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| ProtocolError::OperandValueInvalid)?,
    ))
    .map_err(|_| ProtocolError::OperandValueInvalid)?;
    if !(0..10_000).contains(&value) {
        return Err(ProtocolError::OperandValueInvalid);
    }
    Ok(value)
}

fn exact_value(
    value: Option<OperandValueRef<'_>>,
    slot_id: u16,
    value_type: OperandType,
) -> Result<&[u8], ProtocolError> {
    let value = value.ok_or(ProtocolError::OperandValueInvalid)?;
    if value.slot_id != slot_id || value.value_type != value_type {
        return Err(ProtocolError::OperandValueInvalid);
    }
    value.value.ok_or(ProtocolError::OperandValueInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> IdSetBundleProfile {
        IdSetBundleProfile::new(
            "ndabi",
            "items",
            OperationBinding::new(71, 73).expect("binding"),
        )
        .expect("profile")
    }

    #[test]
    fn the_bundle_requires_sorted_unique_identifiers() {
        assert!(IdSetBundle::new(&[1, 3, 8]).is_ok());
        assert!(IdSetBundle::new(&[]).is_err());
        assert!(IdSetBundle::new(&[1, 1]).is_err());
        assert!(IdSetBundle::new(&[3, 1]).is_err());
        assert!(IdSetBundle::new(&[-1]).is_err());
        assert!(ScoreThreshold::new(9_999).is_ok());
        assert!(ScoreThreshold::new(10_000).is_err());
    }

    #[test]
    fn the_registry_seals_the_layout_and_lowering() {
        let profile = profile();
        let registry = profile.graph_registry([1; 32], [2; 32]).expect("registry");
        assert_eq!(
            registry.graphs(),
            [profile.registered_graph().expect("graph")]
        );
        assert_eq!(registry.identity().engine(), MONGODB_ENGINE_ID);
        assert_eq!(
            registry.identity().profile(),
            MONGODB_ID_SET_BUNDLE_PROFILE_ID
        );
    }
}
