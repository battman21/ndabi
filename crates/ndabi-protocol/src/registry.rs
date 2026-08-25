//! Seal backend capabilities and registered plans before session execution.
//!
//! The hot path accepts compact handles only after the registry binds their complete meaning.
//! The registry refuses runtime plan creation and does not contain readable query text.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{
    get_u16, get_u32, get_u64, is_zero, put_u16, put_u32, put_u64, Authority, Backend,
    BackendIdentity, BatchBackend, BatchItems, BatchOperation, BoundedOutput, ExecutionLimits,
    Operation, ProtocolError,
};

const REGISTRY_DOMAIN: &[u8] = b"ndabi/wire/v1/plan-registry";
const DISCOVERY_DOMAIN: &[u8] = b"ndabi/wire/v1/registry-discovery";
const DISCOVERY_MAGIC: &[u8; 4] = b"NDRG";
const DISCOVERY_HEADER_BYTES: usize = 120;
const DISCOVERY_PLAN_BYTES: usize = 96;
const DISCOVERY_TAG_BYTES: usize = 32;
const DISCOVERY_BASE_BYTES: usize = DISCOVERY_HEADER_BYTES + DISCOVERY_TAG_BYTES;
pub const PLAN_REGISTRY_VERSION_MAJOR: u16 = 1;
pub const PLAN_REGISTRY_VERSION_MINOR: u16 = 0;
pub const MAX_REGISTERED_PLANS: usize = 4_096;

pub const CAPABILITY_QUERY: u64 = 1 << 0;
pub const CAPABILITY_BATCH: u64 = 1 << 1;
pub const CAPABILITY_AGGREGATE: u64 = 1 << 2;
pub const CAPABILITY_RELATIONSHIP: u64 = 1 << 3;
pub const CAPABILITY_MUTATION: u64 = 1 << 4;
pub const CAPABILITY_TRANSACTION: u64 = 1 << 5;
pub const CAPABILITY_STREAMING: u64 = 1 << 6;
pub const CAPABILITY_CANCELLATION: u64 = 1 << 7;
pub const CAPABILITY_EXPLAIN: u64 = 1 << 8;
pub const KNOWN_CAPABILITIES: u64 = CAPABILITY_QUERY
    | CAPABILITY_BATCH
    | CAPABILITY_AGGREGATE
    | CAPABILITY_RELATIONSHIP
    | CAPABILITY_MUTATION
    | CAPABILITY_TRANSACTION
    | CAPABILITY_STREAMING
    | CAPABILITY_CANCELLATION
    | CAPABILITY_EXPLAIN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityManifest {
    bits: u64,
}

impl CapabilityManifest {
    pub fn new(bits: u64) -> Result<Self, ProtocolError> {
        if bits == 0 || bits & !KNOWN_CAPABILITIES != 0 {
            return Err(ProtocolError::CapabilityMismatch);
        }
        Ok(Self { bits })
    }

    pub fn bits(self) -> u64 {
        self.bits
    }

    pub fn supports(self, capability: u64) -> bool {
        capability != 0
            && capability & !KNOWN_CAPABILITIES == 0
            && self.bits & capability == capability
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredPlan {
    opcode: u16,
    handle: u32,
    result_shape: u32,
    maximum_batch_operations: u32,
    maximum_result_bytes: u32,
    maximum_rows: u32,
    required_capabilities: u64,
    parameter_schema_digest: [u8; 32],
    implementation_digest: [u8; 32],
}

impl RegisteredPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new_read(
        opcode: u16,
        handle: u32,
        result_shape: u32,
        maximum_batch_operations: u32,
        maximum_result_bytes: u32,
        maximum_rows: u32,
        required_capabilities: u64,
        parameter_schema_digest: [u8; 32],
        implementation_digest: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        if opcode == 0 || handle == 0 || result_shape == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        if maximum_batch_operations == 0
            || maximum_batch_operations > super::MAX_BATCH_OPERATIONS as u32
            || maximum_result_bytes == 0
            || maximum_rows == 0
        {
            return Err(ProtocolError::PlanLimitExceeded);
        }
        if required_capabilities & !KNOWN_CAPABILITIES != 0
            || required_capabilities & CAPABILITY_QUERY == 0
            || (maximum_batch_operations > 1 && required_capabilities & CAPABILITY_BATCH == 0)
            || required_capabilities & (CAPABILITY_MUTATION | CAPABILITY_TRANSACTION) != 0
        {
            return Err(ProtocolError::CapabilityMismatch);
        }
        if is_zero(&parameter_schema_digest) || is_zero(&implementation_digest) {
            return Err(ProtocolError::ZeroDigest);
        }
        Ok(Self {
            opcode,
            handle,
            result_shape,
            maximum_batch_operations,
            maximum_result_bytes,
            maximum_rows,
            required_capabilities,
            parameter_schema_digest,
            implementation_digest,
        })
    }

    pub fn handle(self) -> u32 {
        self.handle
    }

    pub fn opcode(self) -> u16 {
        self.opcode
    }

    pub fn result_shape(self) -> u32 {
        self.result_shape
    }

    pub fn maximum_batch_operations(self) -> u32 {
        self.maximum_batch_operations
    }

    pub fn maximum_result_bytes(self) -> u32 {
        self.maximum_result_bytes
    }

    pub fn maximum_rows(self) -> u32 {
        self.maximum_rows
    }

    pub fn required_capabilities(self) -> u64 {
        self.required_capabilities
    }

    pub fn parameter_schema_digest(self) -> [u8; 32] {
        self.parameter_schema_digest
    }

    pub fn implementation_digest(self) -> [u8; 32] {
        self.implementation_digest
    }
}

#[derive(Clone, Debug)]
pub struct PlanRegistry {
    manifest: CapabilityManifest,
    plans: Vec<RegisteredPlan>,
    identity: BackendIdentity,
}

#[derive(Clone, Debug)]
pub struct DiscoveredRegistry {
    generation: u64,
    expires_unix_us: u64,
    registry: PlanRegistry,
}

impl DiscoveredRegistry {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn expires_unix_us(&self) -> u64 {
        self.expires_unix_us
    }

    pub fn registry(&self) -> &PlanRegistry {
        &self.registry
    }
}

impl PlanRegistry {
    pub fn new(
        engine: u32,
        profile: u32,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
        manifest: CapabilityManifest,
        plans: impl IntoIterator<Item = RegisteredPlan>,
    ) -> Result<Self, ProtocolError> {
        if engine == 0 || profile == 0 {
            return Err(ProtocolError::ZeroIdentity);
        }
        if is_zero(&schema_digest) || is_zero(&policy_digest) {
            return Err(ProtocolError::ZeroDigest);
        }
        let mut plans = plans.into_iter().collect::<Vec<_>>();
        if plans.is_empty() {
            return Err(ProtocolError::PlanRegistryEmpty);
        }
        if plans.len() > MAX_REGISTERED_PLANS {
            return Err(ProtocolError::PlanLimitExceeded);
        }
        plans.sort_unstable_by_key(|plan| plan.handle);
        if plans
            .windows(2)
            .any(|pair| pair[0].handle == pair[1].handle)
        {
            return Err(ProtocolError::DuplicatePlan);
        }
        if plans
            .iter()
            .any(|plan| !manifest.supports(plan.required_capabilities))
        {
            return Err(ProtocolError::CapabilityMismatch);
        }
        let digest = registry_digest(
            engine,
            profile,
            schema_digest,
            policy_digest,
            manifest,
            &plans,
        );
        let identity = BackendIdentity::new(engine, profile, schema_digest, policy_digest, digest)?;
        Ok(Self {
            manifest,
            plans,
            identity,
        })
    }

    pub fn manifest(&self) -> CapabilityManifest {
        self.manifest
    }

    pub fn identity(&self) -> BackendIdentity {
        self.identity
    }

    pub fn digest(&self) -> [u8; 32] {
        self.identity.plan_digest
    }

    pub fn plans(&self) -> &[RegisteredPlan] {
        &self.plans
    }

    pub fn plan(&self, handle: u32) -> Option<RegisteredPlan> {
        if let [plan] = self.plans.as_slice() {
            return (plan.handle == handle).then_some(*plan);
        }
        self.plans
            .binary_search_by_key(&handle, |plan| plan.handle)
            .ok()
            .map(|index| self.plans[index])
    }

    fn validate_operation(
        &self,
        operation: Operation,
        limits: ExecutionLimits,
    ) -> Result<(), ProtocolError> {
        let plan = self
            .plan(operation.plan_handle)
            .ok_or(ProtocolError::PlanNotRegistered)?;
        self.validate_common(plan, operation.opcode, operation.result_shape, 1, limits)
    }

    fn validate_batch(
        &self,
        operation: BatchOperation,
        operation_count: usize,
        limits: ExecutionLimits,
    ) -> Result<(), ProtocolError> {
        let plan = self
            .plan(operation.plan_handle)
            .ok_or(ProtocolError::PlanNotRegistered)?;
        let operation_count =
            u32::try_from(operation_count).map_err(|_| ProtocolError::PlanLimitExceeded)?;
        self.validate_common(
            plan,
            operation.opcode,
            operation.result_shape,
            operation_count,
            limits,
        )
    }

    fn validate_common(
        &self,
        plan: RegisteredPlan,
        opcode: u16,
        result_shape: u32,
        operation_count: u32,
        limits: ExecutionLimits,
    ) -> Result<(), ProtocolError> {
        if opcode != plan.opcode || result_shape != plan.result_shape {
            return Err(ProtocolError::PlanShapeMismatch);
        }
        if operation_count == 0
            || operation_count > plan.maximum_batch_operations
            || limits.maximum_result_bytes > plan.maximum_result_bytes
            || limits.maximum_rows > plan.maximum_rows
        {
            return Err(ProtocolError::PlanLimitExceeded);
        }
        if operation_count > 1 && !self.manifest.supports(CAPABILITY_BATCH) {
            return Err(ProtocolError::CapabilityMismatch);
        }
        Ok(())
    }
}

fn registry_digest(
    engine: u32,
    profile: u32,
    schema_digest: [u8; 32],
    policy_digest: [u8; 32],
    manifest: CapabilityManifest,
    plans: &[RegisteredPlan],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(REGISTRY_DOMAIN);
    digest.update(&PLAN_REGISTRY_VERSION_MAJOR.to_le_bytes());
    digest.update(&PLAN_REGISTRY_VERSION_MINOR.to_le_bytes());
    digest.update(&engine.to_le_bytes());
    digest.update(&profile.to_le_bytes());
    digest.update(&schema_digest);
    digest.update(&policy_digest);
    digest.update(&manifest.bits.to_le_bytes());
    digest.update(&(plans.len() as u32).to_le_bytes());
    for plan in plans {
        digest.update(&plan.opcode.to_le_bytes());
        digest.update(&plan.handle.to_le_bytes());
        digest.update(&plan.result_shape.to_le_bytes());
        digest.update(&plan.maximum_batch_operations.to_le_bytes());
        digest.update(&plan.maximum_result_bytes.to_le_bytes());
        digest.update(&plan.maximum_rows.to_le_bytes());
        digest.update(&plan.required_capabilities.to_le_bytes());
        digest.update(&plan.parameter_schema_digest);
        digest.update(&plan.implementation_digest);
    }
    *digest.finalize().as_bytes()
}

pub fn registry_discovery_bytes(plan_count: usize) -> Result<usize, ProtocolError> {
    if plan_count == 0 || plan_count > MAX_REGISTERED_PLANS {
        return Err(ProtocolError::PlanLimitExceeded);
    }
    DISCOVERY_BASE_BYTES
        .checked_add(
            plan_count
                .checked_mul(DISCOVERY_PLAN_BYTES)
                .ok_or(ProtocolError::PlanLimitExceeded)?,
        )
        .ok_or(ProtocolError::PlanLimitExceeded)
}

/// Authenticate one bounded registry snapshot for remote agent discovery.
pub fn encode_registry_discovery(
    authority: &Authority,
    registry: &PlanRegistry,
    generation: u64,
    expires_unix_us: u64,
) -> Result<Vec<u8>, ProtocolError> {
    if registry.identity != authority.context.backend {
        return Err(ProtocolError::PlanRegistryMismatch);
    }
    if generation == 0 || expires_unix_us == 0 || expires_unix_us > authority.expires_unix_us {
        return Err(ProtocolError::Expired);
    }
    let total_bytes = registry_discovery_bytes(registry.plans.len())?;
    let mut bytes = vec![0_u8; total_bytes];
    bytes[0..4].copy_from_slice(DISCOVERY_MAGIC);
    put_u16(&mut bytes, 4, PLAN_REGISTRY_VERSION_MAJOR);
    put_u16(&mut bytes, 6, PLAN_REGISTRY_VERSION_MINOR);
    put_u64(&mut bytes, 8, generation);
    put_u64(&mut bytes, 16, expires_unix_us);
    put_u32(&mut bytes, 24, registry.identity.engine);
    put_u32(&mut bytes, 28, registry.identity.profile);
    put_u64(&mut bytes, 32, registry.manifest.bits);
    put_u32(
        &mut bytes,
        40,
        u32::try_from(registry.plans.len()).map_err(|_| ProtocolError::PlanLimitExceeded)?,
    );
    put_u32(&mut bytes, 44, DISCOVERY_PLAN_BYTES as u32);
    put_u32(
        &mut bytes,
        48,
        u32::try_from(total_bytes).map_err(|_| ProtocolError::PlanLimitExceeded)?,
    );
    bytes[56..88].copy_from_slice(&authority.context_digest);
    bytes[88..120].copy_from_slice(&registry.digest());
    for (index, plan) in registry.plans.iter().enumerate() {
        let offset = DISCOVERY_HEADER_BYTES + index * DISCOVERY_PLAN_BYTES;
        put_u16(&mut bytes, offset, plan.opcode);
        put_u32(&mut bytes, offset + 4, plan.handle);
        put_u32(&mut bytes, offset + 8, plan.result_shape);
        put_u32(&mut bytes, offset + 12, plan.maximum_batch_operations);
        put_u32(&mut bytes, offset + 16, plan.maximum_result_bytes);
        put_u32(&mut bytes, offset + 20, plan.maximum_rows);
        put_u64(&mut bytes, offset + 24, plan.required_capabilities);
        bytes[offset + 32..offset + 64].copy_from_slice(&plan.parameter_schema_digest);
        bytes[offset + 64..offset + 96].copy_from_slice(&plan.implementation_digest);
    }
    let tag_offset = total_bytes - DISCOVERY_TAG_BYTES;
    let tag = discovery_tag(authority, &bytes[..tag_offset]);
    bytes[tag_offset..].copy_from_slice(&tag);
    Ok(bytes)
}

/// Verify and reconstruct one remote registry snapshot before using its handles.
pub fn decode_registry_discovery(
    authority: &Authority,
    bytes: &[u8],
    now_unix_us: u64,
) -> Result<DiscoveredRegistry, ProtocolError> {
    if bytes.len() < DISCOVERY_BASE_BYTES {
        return Err(ProtocolError::LengthMismatch);
    }
    let tag_offset = bytes.len() - DISCOVERY_TAG_BYTES;
    let expected_tag = discovery_tag(authority, &bytes[..tag_offset]);
    if expected_tag.ct_eq(&bytes[tag_offset..]).unwrap_u8() != 1 {
        return Err(ProtocolError::AuthenticationFailed);
    }
    let plan_count = get_u32(bytes, 40) as usize;
    let expected_bytes = registry_discovery_bytes(plan_count)?;
    if bytes.len() != expected_bytes
        || &bytes[0..4] != DISCOVERY_MAGIC
        || get_u16(bytes, 4) != PLAN_REGISTRY_VERSION_MAJOR
        || get_u16(bytes, 6) != PLAN_REGISTRY_VERSION_MINOR
        || get_u32(bytes, 44) != DISCOVERY_PLAN_BYTES as u32
        || get_u32(bytes, 48) as usize != bytes.len()
        || bytes[52..56] != [0; 4]
        || bytes[56..88] != authority.context_digest
        || bytes[88..120] != authority.context.backend.plan_digest
        || get_u32(bytes, 24) != authority.context.backend.engine
        || get_u32(bytes, 28) != authority.context.backend.profile
    {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    let generation = get_u64(bytes, 8);
    let expires_unix_us = get_u64(bytes, 16);
    if generation == 0
        || expires_unix_us == 0
        || expires_unix_us > authority.expires_unix_us
        || now_unix_us > expires_unix_us
    {
        return Err(ProtocolError::Expired);
    }
    let manifest = CapabilityManifest::new(get_u64(bytes, 32))?;
    let mut plans = Vec::with_capacity(plan_count);
    for index in 0..plan_count {
        let offset = DISCOVERY_HEADER_BYTES + index * DISCOVERY_PLAN_BYTES;
        if bytes[offset + 2..offset + 4] != [0; 2] {
            return Err(ProtocolError::NonCanonicalFrame);
        }
        let parameter_schema_digest = digest_at(bytes, offset + 32)?;
        let implementation_digest = digest_at(bytes, offset + 64)?;
        plans.push(RegisteredPlan::new_read(
            get_u16(bytes, offset),
            get_u32(bytes, offset + 4),
            get_u32(bytes, offset + 8),
            get_u32(bytes, offset + 12),
            get_u32(bytes, offset + 16),
            get_u32(bytes, offset + 20),
            get_u64(bytes, offset + 24),
            parameter_schema_digest,
            implementation_digest,
        )?);
    }
    let backend = authority.context.backend;
    let registry = PlanRegistry::new(
        backend.engine,
        backend.profile,
        backend.schema_digest,
        backend.policy_digest,
        manifest,
        plans,
    )?;
    if registry.identity != backend {
        return Err(ProtocolError::PlanRegistryMismatch);
    }
    Ok(DiscoveredRegistry {
        generation,
        expires_unix_us,
        registry,
    })
}

fn discovery_tag(authority: &Authority, bytes: &[u8]) -> [u8; DISCOVERY_TAG_BYTES] {
    let mut digest = blake3::Hasher::new_keyed(&authority.transport_key);
    digest.update(DISCOVERY_DOMAIN);
    digest.update(bytes);
    let tag = *digest.finalize().as_bytes();
    digest.zeroize();
    tag
}

fn digest_at(bytes: &[u8], offset: usize) -> Result<[u8; 32], ProtocolError> {
    bytes
        .get(offset..offset + 32)
        .ok_or(ProtocolError::LengthMismatch)?
        .try_into()
        .map_err(|_| ProtocolError::LengthMismatch)
}

/// Enforce one sealed registry before a backend interprets compact handles.
pub struct RegisteredBackend<'a, B> {
    registry: &'a PlanRegistry,
    backend: B,
}

impl<'a, B> RegisteredBackend<'a, B>
where
    B: Backend,
{
    pub fn new(registry: &'a PlanRegistry, backend: B) -> Result<Self, ProtocolError> {
        if registry.identity() != backend.identity() {
            return Err(ProtocolError::PlanRegistryMismatch);
        }
        Ok(Self { registry, backend })
    }
}

impl<B> Backend for RegisteredBackend<'_, B>
where
    B: Backend,
{
    fn identity(&self) -> BackendIdentity {
        self.backend.identity()
    }

    fn execute(
        &mut self,
        operation: Operation,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        self.registry.validate_operation(operation, limits)?;
        self.backend.execute(operation, limits, output)
    }
}

/// Enforce one sealed registry before a batch backend interprets compact handles.
pub struct RegisteredBatchBackend<'a, B> {
    registry: &'a PlanRegistry,
    backend: B,
}

impl<'a, B> RegisteredBatchBackend<'a, B>
where
    B: BatchBackend,
{
    pub fn new(registry: &'a PlanRegistry, backend: B) -> Result<Self, ProtocolError> {
        if registry.identity() != backend.identity() {
            return Err(ProtocolError::PlanRegistryMismatch);
        }
        Ok(Self { registry, backend })
    }
}

impl<B> BatchBackend for RegisteredBatchBackend<'_, B>
where
    B: BatchBackend,
{
    fn identity(&self) -> BackendIdentity {
        self.backend.identity()
    }

    fn execute_batch(
        &mut self,
        operation: BatchOperation,
        items: BatchItems<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        self.registry
            .validate_batch(operation, items.len(), limits)?;
        self.backend.execute_batch(operation, items, limits, output)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::{
        batch_frame_bytes, digest_label, Authority, AuthorityContext, BatchItem, ClientSession,
        MemoryReplayStore, ServerSession,
    };

    const NOW: u64 = 1_000_000;
    const DEADLINE: u64 = 2_000_000;

    fn plan(handle: u32, implementation: u8) -> RegisteredPlan {
        RegisteredPlan::new_read(
            11,
            handle,
            13,
            16,
            4_096,
            128,
            CAPABILITY_QUERY | CAPABILITY_BATCH,
            digest_label(b"parameters", &[1]),
            digest_label(b"implementation", &[implementation]),
        )
        .expect("plan")
    }

    fn registry(plans: impl IntoIterator<Item = RegisteredPlan>) -> PlanRegistry {
        PlanRegistry::new(
            21,
            22,
            digest_label(b"schema", &[2]),
            digest_label(b"policy", &[3]),
            CapabilityManifest::new(CAPABILITY_QUERY | CAPABILITY_BATCH).expect("manifest"),
            plans,
        )
        .expect("registry")
    }

    fn authority(registry: &PlanRegistry) -> Authority {
        let context = AuthorityContext::new(
            [4; 16],
            [5; 16],
            6,
            digest_label(b"capability", &[7]),
            registry.identity(),
        )
        .expect("context");
        Authority::new_read([8; 32], 9, 10, DEADLINE, context).expect("authority")
    }

    #[derive(Clone)]
    struct TestBackend {
        identity: BackendIdentity,
        calls: Rc<Cell<u32>>,
    }

    impl Backend for TestBackend {
        fn identity(&self) -> BackendIdentity {
            self.identity
        }

        fn execute(
            &mut self,
            _operation: Operation,
            _limits: ExecutionLimits,
            output: &mut BoundedOutput,
        ) -> Result<(), ProtocolError> {
            self.calls.set(self.calls.get() + 1);
            output.write(&[1])?;
            output.complete_row()
        }
    }

    impl BatchBackend for TestBackend {
        fn identity(&self) -> BackendIdentity {
            self.identity
        }

        fn execute_batch(
            &mut self,
            _operation: BatchOperation,
            items: BatchItems<'_>,
            _limits: ExecutionLimits,
            output: &mut BoundedOutput,
        ) -> Result<(), ProtocolError> {
            self.calls.set(self.calls.get() + 1);
            output.write(&[2])?;
            output.complete_rows(items.len() as u32)
        }
    }

    struct TestClock;

    impl crate::Clock for TestClock {
        fn now_unix_us(&self) -> Result<u64, ProtocolError> {
            Ok(NOW)
        }
    }

    #[test]
    fn registry_identity_is_order_independent_and_binds_plan_changes() {
        let first = registry([plan(12, 1), plan(14, 2)]);
        let reordered = registry([plan(14, 2), plan(12, 1)]);
        let changed = registry([plan(12, 1), plan(14, 3)]);
        assert_eq!(first.digest(), reordered.digest());
        assert_ne!(first.digest(), changed.digest());
    }

    #[test]
    fn duplicate_handles_and_missing_capabilities_refuse() {
        assert_eq!(
            PlanRegistry::new(
                21,
                22,
                digest_label(b"schema", &[2]),
                digest_label(b"policy", &[3]),
                CapabilityManifest::new(CAPABILITY_QUERY | CAPABILITY_BATCH).expect("manifest"),
                [plan(12, 1), plan(12, 2)],
            )
            .unwrap_err(),
            ProtocolError::DuplicatePlan
        );
        assert_eq!(
            PlanRegistry::new(
                21,
                22,
                digest_label(b"schema", &[2]),
                digest_label(b"policy", &[3]),
                CapabilityManifest::new(CAPABILITY_QUERY).expect("manifest"),
                [plan(12, 1)],
            )
            .unwrap_err(),
            ProtocolError::CapabilityMismatch
        );
    }

    #[test]
    fn authenticated_discovery_round_trips_the_sealed_registry() {
        let registry = registry([plan(14, 2), plan(12, 1)]);
        let authority = authority(&registry);
        let bytes =
            encode_registry_discovery(&authority, &registry, 7, DEADLINE).expect("discovery frame");
        let discovered =
            decode_registry_discovery(&authority, &bytes, NOW).expect("discovered registry");
        assert_eq!(discovered.generation(), 7);
        assert_eq!(discovered.expires_unix_us(), DEADLINE);
        assert_eq!(discovered.registry().identity(), registry.identity());
        assert_eq!(discovered.registry().plans(), registry.plans());
    }

    #[test]
    fn authenticated_discovery_refuses_mutation_expiry_and_identity_drift() {
        let plan_registry = registry([plan(12, 1)]);
        let authority = authority(&plan_registry);
        let mut bytes = encode_registry_discovery(&authority, &plan_registry, 7, DEADLINE)
            .expect("discovery frame");
        bytes[64] ^= 1;
        assert_eq!(
            decode_registry_discovery(&authority, &bytes, NOW).unwrap_err(),
            ProtocolError::AuthenticationFailed
        );

        let bytes = encode_registry_discovery(&authority, &plan_registry, 7, DEADLINE)
            .expect("discovery frame");
        assert_eq!(
            decode_registry_discovery(&authority, &bytes, DEADLINE + 1).unwrap_err(),
            ProtocolError::Expired
        );

        let changed_registry = registry([plan(12, 2)]);
        assert_eq!(
            encode_registry_discovery(&authority, &changed_registry, 7, DEADLINE).unwrap_err(),
            ProtocolError::PlanRegistryMismatch
        );
    }

    #[test]
    fn an_unregistered_plan_refuses_before_backend_dispatch() {
        let registry = registry([plan(12, 1)]);
        let authority = authority(&registry);
        let mut client = ClientSession::new(authority.clone());
        let frame = client
            .encode(
                Operation::new(11, 99, 13, 1, 2, 3).expect("operation"),
                64,
                4,
                DEADLINE,
            )
            .expect("frame");
        let backend = TestBackend {
            identity: registry.identity(),
            calls: Rc::new(Cell::new(0)),
        };
        let calls = backend.calls.clone();
        let mut backend = RegisteredBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 128).expect("server");
        assert_eq!(
            server
                .execute(
                    &frame,
                    &mut backend,
                    &mut MemoryReplayStore::default(),
                    &TestClock,
                )
                .unwrap_err(),
            ProtocolError::PlanNotRegistered
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn a_registry_identity_mismatch_refuses_before_session_construction() {
        let plan_registry = registry([plan(12, 1)]);
        let other_registry = registry([plan(12, 2)]);
        let backend = TestBackend {
            identity: other_registry.identity(),
            calls: Rc::new(Cell::new(0)),
        };
        assert!(matches!(
            RegisteredBackend::new(&plan_registry, backend),
            Err(ProtocolError::PlanRegistryMismatch)
        ));
    }

    #[test]
    fn a_plan_shape_mismatch_refuses_before_backend_dispatch() {
        let registry = registry([plan(12, 1)]);
        let authority = authority(&registry);
        let frame = ClientSession::new(authority.clone())
            .encode(
                Operation::new(11, 12, 99, 1, 2, 3).expect("operation"),
                64,
                4,
                DEADLINE,
            )
            .expect("frame");
        let backend = TestBackend {
            identity: registry.identity(),
            calls: Rc::new(Cell::new(0)),
        };
        let calls = backend.calls.clone();
        let mut backend = RegisteredBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 128).expect("server");
        assert_eq!(
            server
                .execute(
                    &frame,
                    &mut backend,
                    &mut MemoryReplayStore::default(),
                    &TestClock,
                )
                .unwrap_err(),
            ProtocolError::PlanShapeMismatch
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn a_plan_budget_refuses_before_backend_dispatch() {
        let restricted_plan = RegisteredPlan::new_read(
            11,
            12,
            13,
            1,
            32,
            2,
            CAPABILITY_QUERY,
            digest_label(b"parameters", &[1]),
            digest_label(b"implementation", &[1]),
        )
        .expect("plan");
        let registry = registry([restricted_plan]);
        let authority = authority(&registry);
        let frame = ClientSession::new(authority.clone())
            .encode(
                Operation::new(11, 12, 13, 1, 2, 3).expect("operation"),
                64,
                2,
                DEADLINE,
            )
            .expect("frame");
        let backend = TestBackend {
            identity: registry.identity(),
            calls: Rc::new(Cell::new(0)),
        };
        let calls = backend.calls.clone();
        let mut backend = RegisteredBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 128).expect("server");
        assert_eq!(
            server
                .execute(
                    &frame,
                    &mut backend,
                    &mut MemoryReplayStore::default(),
                    &TestClock,
                )
                .unwrap_err(),
            ProtocolError::PlanLimitExceeded
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn a_registered_batch_dispatches_once() {
        let registry = registry([plan(12, 1)]);
        let authority = authority(&registry);
        let items = [BatchItem::new(1, 2, 3), BatchItem::new(4, 5, 6)];
        let mut frame = vec![0; batch_frame_bytes(items.len()).expect("frame bytes")];
        ClientSession::new(authority.clone())
            .encode_batch_into(
                BatchOperation::new(11, 12, 13).expect("operation"),
                &items,
                64,
                4,
                DEADLINE,
                &mut frame,
            )
            .expect("frame");
        let backend = TestBackend {
            identity: registry.identity(),
            calls: Rc::new(Cell::new(0)),
        };
        let calls = backend.calls.clone();
        let mut backend = RegisteredBatchBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 128).expect("server");
        let execution = server
            .execute_batch(
                &frame,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &TestClock,
            )
            .expect("execution");
        assert_eq!(execution.bytes, [2]);
        assert_eq!(execution.rows, 2);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_batch_above_the_plan_limit_refuses_before_backend_dispatch() {
        let restricted_plan = RegisteredPlan::new_read(
            11,
            12,
            13,
            2,
            4_096,
            128,
            CAPABILITY_QUERY | CAPABILITY_BATCH,
            digest_label(b"parameters", &[1]),
            digest_label(b"implementation", &[1]),
        )
        .expect("plan");
        let registry = registry([restricted_plan]);
        let authority = authority(&registry);
        let items = [
            BatchItem::new(1, 2, 3),
            BatchItem::new(4, 5, 6),
            BatchItem::new(7, 8, 9),
        ];
        let mut frame = vec![0; batch_frame_bytes(items.len()).expect("frame bytes")];
        ClientSession::new(authority.clone())
            .encode_batch_into(
                BatchOperation::new(11, 12, 13).expect("operation"),
                &items,
                64,
                4,
                DEADLINE,
                &mut frame,
            )
            .expect("frame");
        let backend = TestBackend {
            identity: registry.identity(),
            calls: Rc::new(Cell::new(0)),
        };
        let calls = backend.calls.clone();
        let mut backend = RegisteredBatchBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 128).expect("server");
        assert_eq!(
            server
                .execute_batch(
                    &frame,
                    &mut backend,
                    &mut MemoryReplayStore::default(),
                    &TestClock,
                )
                .unwrap_err(),
            ProtocolError::PlanLimitExceeded
        );
        assert_eq!(calls.get(), 0);
    }
}
