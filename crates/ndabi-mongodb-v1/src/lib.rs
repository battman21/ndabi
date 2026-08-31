//! Lower the canonical NDABI execute-handle frame into one finite MongoDB set query.
//!
//! The frame cannot contain collection names, field names, commands, pipelines, or writes.
//! The adapter applies a fixed projection, order, batch size, negative limit, and server deadline.

use std::time::Duration;

use mongodb::bson::{doc, spec::BinarySubtype, Binary};
use mongodb::sync::{Client, Collection};
use ndabi_protocol::{
    digest_label, Backend, BackendIdentity, BoundedOutput, CapabilityManifest, ExecutionLimits,
    Operation, PlanRegistry, ProtocolError, RegisteredPlan, CAPABILITY_QUERY,
};
use serde::Deserialize;

mod operand_bundle;

pub use operand_bundle::{
    IdSetBundle, IdSetBundleBackend, IdSetBundleProfile, ScoreThreshold,
    MONGODB_ID_SET_BUNDLE_PROFILE_ID,
};

pub const MONGODB_ENGINE_ID: u32 = 0x4d47_0001;
pub const MONGODB_ID_WINDOW_PROFILE_ID: u32 = 0x4d47_1001;
pub const MONGODB_ID_WINDOW_REGISTRY_PROFILE_ID: u32 = 0x4d47_1002;
pub const FIND_ID_WINDOW: u16 = 0x22;
pub const ROW_BYTES: usize = 84;
pub const MAX_BATCH_ITEMS: usize = 128;
pub const DATASET_ROWS: i64 = 1_000_000;
const PLAN_DOMAIN: &[u8] = b"ndabi/mongodb/id-window/v1";
const PARAMETER_SCHEMA_DOMAIN: &[u8] = b"ndabi/mongodb/id-window-parameters/v1";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdWindow {
    pub first: i64,
    pub count: u32,
    pub stride: u32,
}

impl IdWindow {
    pub fn identifiers(self) -> Result<Vec<i64>, ProtocolError> {
        if self.first < 0
            || self.count == 0
            || self.count as usize > MAX_BATCH_ITEMS
            || self.stride == 0
        {
            return Err(ProtocolError::BackendRefused);
        }
        let mut identifiers = Vec::with_capacity(self.count as usize);
        for offset in 0..self.count {
            let scaled = i64::from(offset)
                .checked_mul(i64::from(self.stride))
                .ok_or(ProtocolError::BackendRefused)?;
            let identifier = self
                .first
                .checked_add(scaled)
                .ok_or(ProtocolError::BackendRefused)?;
            if identifier >= DATASET_ROWS {
                return Err(ProtocolError::BackendRefused);
            }
            identifiers.push(identifier);
        }
        Ok(identifiers)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdWindowProfile {
    database: String,
    collection: String,
    binding: OperationBinding,
}

impl IdWindowProfile {
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

    pub fn identity(
        &self,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<BackendIdentity, ProtocolError> {
        BackendIdentity::new(
            MONGODB_ENGINE_ID,
            MONGODB_ID_WINDOW_PROFILE_ID,
            schema_digest,
            policy_digest,
            self.implementation_digest(),
        )
    }

    pub fn registered_plan(&self) -> Result<RegisteredPlan, ProtocolError> {
        RegisteredPlan::new_read(
            FIND_ID_WINDOW,
            self.binding.plan_handle,
            self.binding.result_shape,
            1,
            (MAX_BATCH_ITEMS * ROW_BYTES) as u32,
            MAX_BATCH_ITEMS as u32,
            CAPABILITY_QUERY,
            digest_label(PARAMETER_SCHEMA_DOMAIN, b"first:i64,count:i64,stride:u32"),
            self.implementation_digest(),
        )
    }

    pub fn plan_registry(
        &self,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<PlanRegistry, ProtocolError> {
        PlanRegistry::new(
            MONGODB_ENGINE_ID,
            MONGODB_ID_WINDOW_REGISTRY_PROFILE_ID,
            schema_digest,
            policy_digest,
            CapabilityManifest::new(CAPABILITY_QUERY)?,
            [self.registered_plan()?],
        )
    }

    pub fn operation(
        &self,
        first: i64,
        count: u32,
        stride: u32,
    ) -> Result<Operation, ProtocolError> {
        let window = IdWindow {
            first,
            count,
            stride,
        };
        window.identifiers()?;
        Operation::new(
            FIND_ID_WINDOW,
            self.binding.plan_handle,
            self.binding.result_shape,
            first,
            i64::from(count),
            stride,
        )
    }

    fn decode(&self, operation: Operation) -> Result<IdWindow, ProtocolError> {
        if operation.opcode != FIND_ID_WINDOW
            || operation.plan_handle != self.binding.plan_handle
            || operation.result_shape != self.binding.result_shape
        {
            return Err(ProtocolError::BackendRefused);
        }
        let count = u32::try_from(operation.second).map_err(|_| ProtocolError::BackendRefused)?;
        let window = IdWindow {
            first: operation.first,
            count,
            stride: operation.third,
        };
        window.identifiers()?;
        Ok(window)
    }

    fn implementation_digest(&self) -> [u8; 32] {
        let mut plan = blake3::Hasher::new();
        plan.update(PLAN_DOMAIN);
        plan.update(self.database.as_bytes());
        plan.update(self.collection.as_bytes());
        plan.update(b"find:_id-in;project:registered-fields;sort:_id-asc;single-batch");
        plan.update(&self.binding.plan_handle.to_le_bytes());
        plan.update(&self.binding.result_shape.to_le_bytes());
        *plan.finalize().as_bytes()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct MongoItem {
    #[serde(rename = "_id")]
    pub(crate) id: i64,
    pub(crate) bucket: i32,
    pub(crate) owner: i32,
    pub(crate) score: i32,
    pub(crate) payload: Binary,
}

pub struct IdWindowBackend {
    collection: Collection<MongoItem>,
    profile: IdWindowProfile,
    identity: BackendIdentity,
    executions: u64,
}

impl IdWindowBackend {
    pub fn connect(
        uri: &str,
        profile: IdWindowProfile,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        let client = Client::with_uri_str(uri).map_err(|_| ProtocolError::BackendRefused)?;
        Self::from_client(client, profile, schema_digest, policy_digest)
    }

    pub fn from_client(
        client: Client,
        profile: IdWindowProfile,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        let collection = client
            .database(&profile.database)
            .collection(&profile.collection);
        let identity = profile.identity(schema_digest, policy_digest)?;
        Ok(Self {
            collection,
            profile,
            identity,
            executions: 0,
        })
    }

    pub fn from_client_registered(
        client: Client,
        profile: IdWindowProfile,
        registry: &PlanRegistry,
    ) -> Result<Self, ProtocolError> {
        if registry.identity().engine() != MONGODB_ENGINE_ID
            || registry.identity().profile() != MONGODB_ID_WINDOW_REGISTRY_PROFILE_ID
            || registry.plans() != [profile.registered_plan()?]
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
            executions: 0,
        })
    }

    pub fn executions(&self) -> u64 {
        self.executions
    }

    fn find_window(
        &mut self,
        window: IdWindow,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        let required_bytes = u64::from(window.count)
            .checked_mul(ROW_BYTES as u64)
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        if window.count > limits.maximum_rows
            || required_bytes > u64::from(limits.maximum_result_bytes)
        {
            return Err(ProtocolError::BudgetExceeded);
        }
        let remaining_us = limits
            .deadline_unix_us
            .checked_sub(limits.admitted_unix_us)
            .ok_or(ProtocolError::Expired)?;
        let identifiers = window.identifiers()?;
        let single_batch_limit = -i64::from(window.count);
        self.executions += 1;
        let mut cursor = self
            .collection
            .find(doc! { "_id": { "$in": &identifiers } })
            .projection(doc! {
                "_id": 1,
                "bucket": 1,
                "owner": 1,
                "score": 1,
                "payload": 1,
            })
            .sort(doc! { "_id": 1 })
            .batch_size(window.count)
            .limit(single_batch_limit)
            .max_time(Duration::from_micros(remaining_us.max(1)))
            .run()
            .map_err(|_| ProtocolError::BackendRefused)?;
        for expected in identifiers {
            let item = cursor
                .next()
                .ok_or(ProtocolError::BackendRefused)?
                .map_err(|_| ProtocolError::BackendRefused)?;
            if item.id != expected {
                return Err(ProtocolError::BackendRefused);
            }
            encode_item(&item, output)?;
        }
        if cursor.next().is_some() {
            return Err(ProtocolError::BackendRefused);
        }
        Ok(())
    }
}

impl Backend for IdWindowBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity
    }

    fn execute(
        &mut self,
        operation: Operation,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        let window = self.profile.decode(operation)?;
        self.find_window(window, limits, output)
    }
}

pub(crate) fn encode_item(
    item: &MongoItem,
    output: &mut BoundedOutput,
) -> Result<(), ProtocolError> {
    if item.payload.subtype != BinarySubtype::Generic || item.payload.bytes.len() != 64 {
        return Err(ProtocolError::BackendRefused);
    }
    output.write(&item.id.to_le_bytes())?;
    output.write(&item.bucket.to_le_bytes())?;
    output.write(&item.owner.to_le_bytes())?;
    output.write(&item.score.to_le_bytes())?;
    output.write(&item.payload.bytes)?;
    output.complete_row()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> IdWindowProfile {
        IdWindowProfile::new(
            "ndabi",
            "items",
            OperationBinding::new(60, 61).expect("binding"),
        )
        .expect("profile")
    }

    #[test]
    fn the_profile_is_finite_and_bounded() {
        let operation = profile().operation(10, 8, 3).expect("operation");
        assert_eq!(
            profile().decode(operation).expect("window"),
            IdWindow {
                first: 10,
                count: 8,
                stride: 3,
            }
        );
        assert!(profile().operation(0, 0, 1).is_err());
        assert!(profile().operation(0, 129, 1).is_err());
        assert!(profile().operation(0, 1, 0).is_err());
        assert!(profile().operation(DATASET_ROWS - 1, 2, 1).is_err());
        assert!(profile().operation(i64::MAX, 2, u32::MAX).is_err());
    }

    #[test]
    fn the_registered_profile_seals_the_existing_plan() {
        let profile = profile();
        let registry = profile.plan_registry([1; 32], [2; 32]).expect("registry");
        assert_eq!(
            registry.plans(),
            [profile.registered_plan().expect("registered plan")]
        );
        assert_eq!(registry.identity().engine(), MONGODB_ENGINE_ID);
        assert_eq!(
            registry.identity().profile(),
            MONGODB_ID_WINDOW_REGISTRY_PROFILE_ID
        );
        assert_ne!(
            registry.identity(),
            profile.identity([1; 32], [2; 32]).expect("legacy identity")
        );
    }

    #[test]
    fn the_identity_changes_with_schema_and_policy() {
        let first = profile().identity([1; 32], [2; 32]).expect("identity");
        assert_ne!(first, profile().identity([3; 32], [2; 32]).expect("schema"));
        assert_ne!(first, profile().identity([1; 32], [4; 32]).expect("policy"));
    }
}
