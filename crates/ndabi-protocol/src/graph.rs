//! Execute one registered, bounded graph through one authenticated request.
//!
//! The hot frame carries one graph handle and one typed parameter block.
//! The sealed registry binds the complete graph and its native implementation.
//! A backend must execute the graph as one fused engine operation or refuse it.

use subtle::ConstantTimeEq;

use super::registry::{
    CapabilityManifest, CAPABILITY_GRAPH, CAPABILITY_MUTATION, CAPABILITY_QUERY,
    CAPABILITY_TRANSACTION, KNOWN_CAPABILITIES,
};
use super::{
    get_u16, get_u32, get_u64, is_zero, put_u16, put_u32, put_u64, receipt, Authority,
    BackendIdentity, BoundedOutput, ClientSession, Clock, ExecutionLimits, ProtocolError,
    ReplayStore, ServerSession, MAGIC, READ_ACCESS, TAG_BYTES, VERSION_MAJOR, VERSION_MINOR,
};

const EXECUTE_GRAPH_HANDLE: u8 = 4;
const GRAPH_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v1/graph-frame";
const GRAPH_REGISTRY_DOMAIN: &[u8] = b"ndabi/wire/v1/graph-registry";
const GRAPH_REGISTRY_VERSION: u16 = 1;
const GRAPH_HEADER_BYTES: usize = 128;
const GRAPH_BASE_BYTES: usize = GRAPH_HEADER_BYTES + TAG_BYTES;

pub const MAX_GRAPH_NODES: usize = 4_096;
pub const MAX_GRAPH_DEPENDENCIES: usize = 16_384;
pub const MAX_GRAPH_PARAMETER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphNode {
    plan_handle: u32,
    result_shape: u32,
    dependencies: Vec<u16>,
}

impl GraphNode {
    pub fn new(
        plan_handle: u32,
        result_shape: u32,
        dependencies: impl Into<Vec<u16>>,
    ) -> Result<Self, ProtocolError> {
        if plan_handle == 0 || result_shape == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        Ok(Self {
            plan_handle,
            result_shape,
            dependencies: dependencies.into(),
        })
    }

    pub fn plan_handle(&self) -> u32 {
        self.plan_handle
    }

    pub fn result_shape(&self) -> u32 {
        self.result_shape
    }

    pub fn dependencies(&self) -> &[u16] {
        &self.dependencies
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredGraph {
    opcode: u16,
    handle: u32,
    result_shape: u32,
    maximum_parameter_bytes: u32,
    maximum_result_bytes: u32,
    maximum_rows: u32,
    required_capabilities: u64,
    parameter_schema_digest: [u8; 32],
    implementation_digest: [u8; 32],
    graph_digest: [u8; 32],
    nodes: Vec<GraphNode>,
}

impl RegisteredGraph {
    #[allow(clippy::too_many_arguments)]
    pub fn new_read(
        opcode: u16,
        handle: u32,
        result_shape: u32,
        maximum_parameter_bytes: u32,
        maximum_result_bytes: u32,
        maximum_rows: u32,
        required_capabilities: u64,
        parameter_schema_digest: [u8; 32],
        implementation_digest: [u8; 32],
        nodes: impl IntoIterator<Item = GraphNode>,
    ) -> Result<Self, ProtocolError> {
        if opcode == 0 || handle == 0 || result_shape == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        if maximum_parameter_bytes as usize > MAX_GRAPH_PARAMETER_BYTES
            || maximum_result_bytes == 0
            || maximum_rows == 0
        {
            return Err(ProtocolError::PlanLimitExceeded);
        }
        let required = CAPABILITY_QUERY | CAPABILITY_GRAPH;
        if required_capabilities & !KNOWN_CAPABILITIES != 0
            || required_capabilities & required != required
            || required_capabilities & (CAPABILITY_MUTATION | CAPABILITY_TRANSACTION) != 0
        {
            return Err(ProtocolError::CapabilityMismatch);
        }
        if is_zero(&parameter_schema_digest) || is_zero(&implementation_digest) {
            return Err(ProtocolError::ZeroDigest);
        }
        let nodes = nodes.into_iter().collect::<Vec<_>>();
        validate_nodes(&nodes)?;
        let graph_digest = calculate_graph_digest(
            opcode,
            handle,
            result_shape,
            parameter_schema_digest,
            &nodes,
        );
        Ok(Self {
            opcode,
            handle,
            result_shape,
            maximum_parameter_bytes,
            maximum_result_bytes,
            maximum_rows,
            required_capabilities,
            parameter_schema_digest,
            implementation_digest,
            graph_digest,
            nodes,
        })
    }

    pub fn opcode(&self) -> u16 {
        self.opcode
    }

    pub fn handle(&self) -> u32 {
        self.handle
    }

    pub fn result_shape(&self) -> u32 {
        self.result_shape
    }

    pub fn graph_digest(&self) -> [u8; 32] {
        self.graph_digest
    }

    pub fn maximum_parameter_bytes(&self) -> u32 {
        self.maximum_parameter_bytes
    }

    pub fn maximum_result_bytes(&self) -> u32 {
        self.maximum_result_bytes
    }

    pub fn maximum_rows(&self) -> u32 {
        self.maximum_rows
    }

    pub fn required_capabilities(&self) -> u64 {
        self.required_capabilities
    }

    pub fn parameter_schema_digest(&self) -> [u8; 32] {
        self.parameter_schema_digest
    }

    pub fn implementation_digest(&self) -> [u8; 32] {
        self.implementation_digest
    }

    pub fn nodes(&self) -> &[GraphNode] {
        &self.nodes
    }
}

fn validate_nodes(nodes: &[GraphNode]) -> Result<(), ProtocolError> {
    if !(2..=MAX_GRAPH_NODES).contains(&nodes.len()) {
        return Err(ProtocolError::PlanLimitExceeded);
    }
    let mut dependency_total = 0_usize;
    let mut graph_has_dependency = false;
    for (index, node) in nodes.iter().enumerate() {
        let mut previous = None;
        for dependency in &node.dependencies {
            if usize::from(*dependency) >= index {
                return Err(ProtocolError::DependencyOrder);
            }
            if previous == Some(*dependency) {
                return Err(ProtocolError::DuplicateDependency);
            }
            if previous.is_some_and(|value| value > *dependency) {
                return Err(ProtocolError::NonCanonicalFrame);
            }
            previous = Some(*dependency);
            graph_has_dependency = true;
        }
        dependency_total = dependency_total
            .checked_add(node.dependencies.len())
            .ok_or(ProtocolError::PlanLimitExceeded)?;
    }
    if !graph_has_dependency || dependency_total > MAX_GRAPH_DEPENDENCIES {
        return Err(ProtocolError::PlanLimitExceeded);
    }
    Ok(())
}

fn calculate_graph_digest(
    opcode: u16,
    handle: u32,
    result_shape: u32,
    parameter_schema_digest: [u8; 32],
    nodes: &[GraphNode],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(GRAPH_REGISTRY_DOMAIN);
    digest.update(b"graph");
    digest.update(&opcode.to_le_bytes());
    digest.update(&handle.to_le_bytes());
    digest.update(&result_shape.to_le_bytes());
    digest.update(&parameter_schema_digest);
    digest.update(&(nodes.len() as u32).to_le_bytes());
    for node in nodes {
        digest.update(&node.plan_handle.to_le_bytes());
        digest.update(&node.result_shape.to_le_bytes());
        digest.update(&(node.dependencies.len() as u32).to_le_bytes());
        for dependency in &node.dependencies {
            digest.update(&dependency.to_le_bytes());
        }
    }
    *digest.finalize().as_bytes()
}

#[derive(Clone, Debug)]
pub struct GraphRegistry {
    manifest: CapabilityManifest,
    graphs: Vec<RegisteredGraph>,
    identity: BackendIdentity,
}

impl GraphRegistry {
    pub fn new(
        engine: u32,
        profile: u32,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
        manifest: CapabilityManifest,
        graphs: impl IntoIterator<Item = RegisteredGraph>,
    ) -> Result<Self, ProtocolError> {
        if engine == 0 || profile == 0 {
            return Err(ProtocolError::ZeroIdentity);
        }
        if is_zero(&schema_digest) || is_zero(&policy_digest) {
            return Err(ProtocolError::ZeroDigest);
        }
        if !manifest.supports(CAPABILITY_QUERY | CAPABILITY_GRAPH) {
            return Err(ProtocolError::CapabilityMismatch);
        }
        let mut graphs = graphs.into_iter().collect::<Vec<_>>();
        if graphs.is_empty() {
            return Err(ProtocolError::PlanRegistryEmpty);
        }
        if graphs.len() > super::registry::MAX_REGISTERED_PLANS {
            return Err(ProtocolError::PlanLimitExceeded);
        }
        graphs.sort_unstable_by_key(|graph| graph.handle);
        if graphs
            .windows(2)
            .any(|pair| pair[0].handle == pair[1].handle)
        {
            return Err(ProtocolError::DuplicatePlan);
        }
        if graphs
            .iter()
            .any(|graph| !manifest.supports(graph.required_capabilities))
        {
            return Err(ProtocolError::CapabilityMismatch);
        }
        let registry_digest = calculate_registry_digest(
            engine,
            profile,
            schema_digest,
            policy_digest,
            manifest,
            &graphs,
        );
        let identity = BackendIdentity::new(
            engine,
            profile,
            schema_digest,
            policy_digest,
            registry_digest,
        )?;
        Ok(Self {
            manifest,
            graphs,
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

    pub fn graphs(&self) -> &[RegisteredGraph] {
        &self.graphs
    }

    pub fn graph(&self, handle: u32) -> Option<&RegisteredGraph> {
        if let [graph] = self.graphs.as_slice() {
            return (graph.handle == handle).then_some(graph);
        }
        self.graphs
            .binary_search_by_key(&handle, |graph| graph.handle)
            .ok()
            .map(|index| &self.graphs[index])
    }

    fn validate(
        &self,
        operation: GraphOperation,
        parameter_bytes: usize,
        limits: ExecutionLimits,
    ) -> Result<(), ProtocolError> {
        let graph = self
            .graph(operation.graph_handle)
            .ok_or(ProtocolError::PlanNotRegistered)?;
        if operation.opcode != graph.opcode || operation.result_shape != graph.result_shape {
            return Err(ProtocolError::PlanShapeMismatch);
        }
        if parameter_bytes > graph.maximum_parameter_bytes as usize {
            return Err(ProtocolError::ParameterLimitExceeded);
        }
        if limits.maximum_result_bytes > graph.maximum_result_bytes
            || limits.maximum_rows > graph.maximum_rows
        {
            return Err(ProtocolError::PlanLimitExceeded);
        }
        Ok(())
    }
}

fn calculate_registry_digest(
    engine: u32,
    profile: u32,
    schema_digest: [u8; 32],
    policy_digest: [u8; 32],
    manifest: CapabilityManifest,
    graphs: &[RegisteredGraph],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(GRAPH_REGISTRY_DOMAIN);
    digest.update(&GRAPH_REGISTRY_VERSION.to_le_bytes());
    digest.update(&engine.to_le_bytes());
    digest.update(&profile.to_le_bytes());
    digest.update(&schema_digest);
    digest.update(&policy_digest);
    digest.update(&manifest.bits().to_le_bytes());
    digest.update(&(graphs.len() as u32).to_le_bytes());
    for graph in graphs {
        digest.update(&graph.opcode.to_le_bytes());
        digest.update(&graph.handle.to_le_bytes());
        digest.update(&graph.result_shape.to_le_bytes());
        digest.update(&graph.maximum_parameter_bytes.to_le_bytes());
        digest.update(&graph.maximum_result_bytes.to_le_bytes());
        digest.update(&graph.maximum_rows.to_le_bytes());
        digest.update(&graph.required_capabilities.to_le_bytes());
        digest.update(&graph.parameter_schema_digest);
        digest.update(&graph.implementation_digest);
        digest.update(&graph.graph_digest);
    }
    *digest.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphOperation {
    pub opcode: u16,
    pub graph_handle: u32,
    pub result_shape: u32,
}

impl GraphOperation {
    pub fn new(opcode: u16, graph_handle: u32, result_shape: u32) -> Result<Self, ProtocolError> {
        if opcode == 0 || graph_handle == 0 || result_shape == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        Ok(Self {
            opcode,
            graph_handle,
            result_shape,
        })
    }
}

pub fn graph_frame_bytes(parameter_bytes: usize) -> Result<usize, ProtocolError> {
    if parameter_bytes > MAX_GRAPH_PARAMETER_BYTES {
        return Err(ProtocolError::ParameterLimitExceeded);
    }
    GRAPH_BASE_BYTES
        .checked_add(parameter_bytes)
        .ok_or(ProtocolError::ParameterLimitExceeded)
}

impl ClientSession {
    #[allow(clippy::too_many_arguments)]
    pub fn encode_graph(
        &mut self,
        operation: GraphOperation,
        parameters: &[u8],
        result_budget: u32,
        row_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut output = vec![0_u8; graph_frame_bytes(parameters.len())?];
        self.encode_graph_into(
            operation,
            parameters,
            result_budget,
            row_budget,
            deadline_unix_us,
            &mut output,
        )?;
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encode_graph_into(
        &mut self,
        operation: GraphOperation,
        parameters: &[u8],
        result_budget: u32,
        row_budget: u32,
        deadline_unix_us: u64,
        output: &mut [u8],
    ) -> Result<(), ProtocolError> {
        GraphOperation::new(
            operation.opcode,
            operation.graph_handle,
            operation.result_shape,
        )?;
        let expected_bytes = graph_frame_bytes(parameters.len())?;
        if output.len() != expected_bytes {
            return Err(ProtocolError::LengthMismatch);
        }
        if result_budget == 0 || row_budget == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        output.fill(0);
        output[0..4].copy_from_slice(&MAGIC);
        output[4] = VERSION_MAJOR;
        output[5] = VERSION_MINOR;
        output[6] = EXECUTE_GRAPH_HANDLE;
        output[7] = READ_ACCESS;
        put_u16(output, 8, 0);
        put_u16(output, 10, operation.opcode);
        put_u32(
            output,
            12,
            u32::try_from(output.len()).map_err(|_| ProtocolError::LengthMismatch)?,
        );
        put_u64(output, 16, self.authority.session);
        put_u64(output, 24, self.authority.generation);
        put_u64(output, 32, nonce);
        put_u64(output, 40, deadline_unix_us);
        put_u32(output, 48, result_budget);
        put_u32(output, 52, row_budget);
        put_u32(output, 56, operation.graph_handle);
        put_u32(output, 60, operation.result_shape);
        put_u32(
            output,
            64,
            u32::try_from(parameters.len()).map_err(|_| ProtocolError::ParameterLimitExceeded)?,
        );
        output[96..128].copy_from_slice(&self.authority.context_digest);
        let tag_offset = output.len() - TAG_BYTES;
        output[GRAPH_HEADER_BYTES..tag_offset].copy_from_slice(parameters);
        let tag = self
            .authority
            .tag_for(GRAPH_FRAME_DOMAIN, &output[..tag_offset]);
        output[tag_offset..].copy_from_slice(&tag);
        self.next_nonce = next_nonce;
        Ok(())
    }
}

pub trait GraphBackend {
    fn identity(&self) -> BackendIdentity;

    fn required_tenant(&self) -> Option<[u8; 16]> {
        None
    }

    fn required_principal(&self) -> Option<[u8; 16]> {
        None
    }

    fn maximum_deadline_unix_us(&self) -> Option<u64> {
        None
    }

    fn execute_graph(
        &mut self,
        operation: GraphOperation,
        parameters: &[u8],
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError>;
}

pub struct RegisteredGraphBackend<'a, B> {
    registry: &'a GraphRegistry,
    backend: B,
}

impl<'a, B> RegisteredGraphBackend<'a, B>
where
    B: GraphBackend,
{
    pub fn new(registry: &'a GraphRegistry, backend: B) -> Result<Self, ProtocolError> {
        if registry.identity() != backend.identity() {
            return Err(ProtocolError::PlanRegistryMismatch);
        }
        Ok(Self { registry, backend })
    }
}

impl<B> GraphBackend for RegisteredGraphBackend<'_, B>
where
    B: GraphBackend,
{
    fn identity(&self) -> BackendIdentity {
        self.backend.identity()
    }

    fn required_tenant(&self) -> Option<[u8; 16]> {
        self.backend.required_tenant()
    }

    fn required_principal(&self) -> Option<[u8; 16]> {
        self.backend.required_principal()
    }

    fn maximum_deadline_unix_us(&self) -> Option<u64> {
        self.backend.maximum_deadline_unix_us()
    }

    fn execute_graph(
        &mut self,
        operation: GraphOperation,
        parameters: &[u8],
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError> {
        self.registry
            .validate(operation, parameters.len(), limits)?;
        self.backend
            .execute_graph(operation, parameters, limits, output)
    }
}

#[derive(Debug)]
pub struct GraphExecution {
    pub operation: GraphOperation,
    pub bytes: Vec<u8>,
    pub rows: u32,
    pub receipt: [u8; 32],
}

#[derive(Debug)]
pub struct BorrowedGraphExecution<'a> {
    pub operation: GraphOperation,
    pub bytes: &'a [u8],
    pub rows: u32,
    pub receipt: [u8; 32],
}

struct AuthenticatedGraph<'a> {
    nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    row_budget: u32,
    operation: GraphOperation,
    parameters: &'a [u8],
}

impl ServerSession {
    pub fn execute_graph<B: GraphBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<GraphExecution, ProtocolError> {
        let (request, previous_nonce, limits) = self.admit_graph(frame, backend, replay, clock)?;
        let mut output = BoundedOutput::new_deferred(request.result_budget, request.row_budget);
        backend.execute_graph(request.operation, request.parameters, limits, &mut output)?;
        if clock.now_unix_us()? >= request.deadline_unix_us {
            return Err(ProtocolError::ExpiredDuringExecution);
        }
        replay.commit(self.authority.replay_key(), previous_nonce, request.nonce)?;
        let receipt = receipt(
            &self.authority,
            *blake3::hash(frame).as_bytes(),
            request.nonce,
            output.rows,
            &output.bytes,
        );
        Ok(GraphExecution {
            operation: request.operation,
            bytes: output.bytes,
            rows: output.rows,
            receipt,
        })
    }

    pub fn execute_graph_reusing<'a, B: GraphBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
        result_buffer: &'a mut Vec<u8>,
    ) -> Result<BorrowedGraphExecution<'a>, ProtocolError> {
        let (request, previous_nonce, limits) = self.admit_graph(frame, backend, replay, clock)?;
        let reusable = std::mem::take(result_buffer);
        let mut output =
            BoundedOutput::new_reusing(reusable, request.result_budget, request.row_budget);
        let result = (|| {
            backend.execute_graph(request.operation, request.parameters, limits, &mut output)?;
            if clock.now_unix_us()? >= request.deadline_unix_us {
                return Err(ProtocolError::ExpiredDuringExecution);
            }
            replay.commit(self.authority.replay_key(), previous_nonce, request.nonce)?;
            let receipt = receipt(
                &self.authority,
                *blake3::hash(frame).as_bytes(),
                request.nonce,
                output.rows,
                &output.bytes,
            );
            Ok((output.rows, receipt))
        })();
        *result_buffer = output.bytes;
        let (rows, receipt) = result?;
        Ok(BorrowedGraphExecution {
            operation: request.operation,
            bytes: result_buffer.as_slice(),
            rows,
            receipt,
        })
    }

    fn admit_graph<'a, B: GraphBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &'a [u8],
        backend: &B,
        replay: &R,
        clock: &C,
    ) -> Result<(AuthenticatedGraph<'a>, u64, ExecutionLimits), ProtocolError> {
        let admitted_unix_us = clock.now_unix_us()?;
        let request = authenticate_graph(&self.authority, frame)?;
        if request.deadline_unix_us <= admitted_unix_us
            || request.deadline_unix_us > self.authority.expires_unix_us
        {
            return Err(ProtocolError::Expired);
        }
        if request.result_budget == 0
            || request.result_budget > self.maximum_result_bytes
            || request.row_budget == 0
            || request.row_budget > self.maximum_rows
        {
            return Err(ProtocolError::BudgetExceeded);
        }
        let previous_nonce = replay.last_nonce(self.authority.replay_key())?;
        if request.nonce
            != previous_nonce
                .checked_add(1)
                .ok_or(ProtocolError::NonceEnded)?
        {
            return Err(ProtocolError::Replay);
        }
        if backend.identity() != self.authority.context.backend() {
            return Err(ProtocolError::BackendIdentityMismatch);
        }
        if backend
            .required_tenant()
            .is_some_and(|tenant| tenant != self.authority.context.tenant())
            || backend
                .required_principal()
                .is_some_and(|principal| principal != self.authority.context.principal())
        {
            return Err(ProtocolError::AuthorityMismatch);
        }
        if backend
            .maximum_deadline_unix_us()
            .is_some_and(|maximum| request.deadline_unix_us > maximum)
        {
            return Err(ProtocolError::Expired);
        }
        let limits = ExecutionLimits {
            admitted_unix_us,
            deadline_unix_us: request.deadline_unix_us,
            maximum_result_bytes: request.result_budget,
            maximum_rows: request.row_budget,
        };
        Ok((request, previous_nonce, limits))
    }
}

fn authenticate_graph<'a>(
    authority: &Authority,
    frame: &'a [u8],
) -> Result<AuthenticatedGraph<'a>, ProtocolError> {
    if frame.len() < GRAPH_BASE_BYTES || frame.len() > graph_frame_bytes(MAX_GRAPH_PARAMETER_BYTES)?
    {
        return Err(ProtocolError::LengthMismatch);
    }
    let tag_offset = frame.len() - TAG_BYTES;
    let expected = authority.tag_for(GRAPH_FRAME_DOMAIN, &frame[..tag_offset]);
    if expected.ct_eq(&frame[tag_offset..]).unwrap_u8() != 1 {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if frame[0..4] != MAGIC
        || frame[4] != VERSION_MAJOR
        || frame[5] != VERSION_MINOR
        || frame[6] != EXECUTE_GRAPH_HANDLE
        || frame[7] != READ_ACCESS
    {
        return Err(ProtocolError::UnsupportedFrame);
    }
    let parameter_bytes = get_u32(frame, 64) as usize;
    if get_u16(frame, 8) != 0
        || get_u32(frame, 12) as usize != frame.len()
        || frame[68..96].iter().any(|byte| *byte != 0)
        || graph_frame_bytes(parameter_bytes)? != frame.len()
    {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    if get_u64(frame, 16) != authority.session
        || get_u64(frame, 24) != authority.generation
        || frame[96..128] != authority.context_digest
    {
        return Err(ProtocolError::AuthorityMismatch);
    }
    Ok(AuthenticatedGraph {
        nonce: get_u64(frame, 32),
        deadline_unix_us: get_u64(frame, 40),
        result_budget: get_u32(frame, 48),
        row_budget: get_u32(frame, 52),
        operation: GraphOperation::new(get_u16(frame, 10), get_u32(frame, 56), get_u32(frame, 60))?,
        parameters: &frame[GRAPH_HEADER_BYTES..tag_offset],
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::{
        digest_label, AuthorityContext, MemoryReplayStore, SingleSessionReplayStore,
        CAPABILITY_AGGREGATE,
    };

    const NOW: u64 = 1_000_000;
    const DEADLINE: u64 = 2_000_000;

    struct TestClock;

    impl Clock for TestClock {
        fn now_unix_us(&self) -> Result<u64, ProtocolError> {
            Ok(NOW)
        }
    }

    fn registered_graph(handle: u32) -> RegisteredGraph {
        RegisteredGraph::new_read(
            11,
            handle,
            13,
            256,
            4_096,
            64,
            CAPABILITY_QUERY | CAPABILITY_GRAPH | CAPABILITY_AGGREGATE,
            digest_label(b"graph-parameters", &[1]),
            digest_label(b"graph-implementation", &[2]),
            [
                GraphNode::new(21, 31, []).expect("first node"),
                GraphNode::new(22, 32, [0]).expect("second node"),
            ],
        )
        .expect("registered graph")
    }

    fn registry() -> GraphRegistry {
        GraphRegistry::new(
            41,
            43,
            digest_label(b"schema", &[3]),
            digest_label(b"policy", &[4]),
            CapabilityManifest::new(CAPABILITY_QUERY | CAPABILITY_GRAPH | CAPABILITY_AGGREGATE)
                .expect("manifest"),
            [registered_graph(17)],
        )
        .expect("registry")
    }

    fn authority(registry: &GraphRegistry) -> Authority {
        let context = AuthorityContext::new(
            [5; 16],
            [6; 16],
            47,
            digest_label(b"capability", &[7]),
            registry.identity(),
        )
        .expect("context");
        Authority::new_read([8; 32], 53, 59, DEADLINE, context).expect("authority")
    }

    struct FakeGraphBackend {
        identity: BackendIdentity,
        calls: Rc<Cell<u32>>,
    }

    impl GraphBackend for FakeGraphBackend {
        fn identity(&self) -> BackendIdentity {
            self.identity
        }

        fn execute_graph(
            &mut self,
            operation: GraphOperation,
            parameters: &[u8],
            _limits: ExecutionLimits,
            output: &mut BoundedOutput,
        ) -> Result<(), ProtocolError> {
            self.calls.set(self.calls.get() + 1);
            output.write(&operation.graph_handle.to_le_bytes())?;
            output.write(parameters)?;
            output.complete_row()
        }
    }

    struct AuthorityBoundBackend {
        inner: FakeGraphBackend,
        tenant: [u8; 16],
        principal: [u8; 16],
        maximum_deadline_unix_us: u64,
    }

    impl GraphBackend for AuthorityBoundBackend {
        fn identity(&self) -> BackendIdentity {
            self.inner.identity()
        }

        fn required_tenant(&self) -> Option<[u8; 16]> {
            Some(self.tenant)
        }

        fn required_principal(&self) -> Option<[u8; 16]> {
            Some(self.principal)
        }

        fn maximum_deadline_unix_us(&self) -> Option<u64> {
            Some(self.maximum_deadline_unix_us)
        }

        fn execute_graph(
            &mut self,
            operation: GraphOperation,
            parameters: &[u8],
            limits: ExecutionLimits,
            output: &mut BoundedOutput,
        ) -> Result<(), ProtocolError> {
            self.inner
                .execute_graph(operation, parameters, limits, output)
        }
    }

    #[test]
    fn a_registered_graph_executes_once_and_returns_a_verified_receipt() {
        let registry = registry();
        let authority = authority(&registry);
        let mut client = ClientSession::new(authority.clone());
        let frame = client
            .encode_graph(
                GraphOperation::new(11, 17, 13).expect("operation"),
                b"typed-operands",
                128,
                1,
                DEADLINE,
            )
            .expect("frame");
        let calls = Rc::new(Cell::new(0));
        let backend = FakeGraphBackend {
            identity: registry.identity(),
            calls: Rc::clone(&calls),
        };
        let mut backend = RegisteredGraphBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 64).expect("server");
        let mut replay = MemoryReplayStore::default();
        let execution = server
            .execute_graph(&frame, &mut backend, &mut replay, &TestClock)
            .expect("execution");
        assert_eq!(calls.get(), 1);
        assert_eq!(execution.rows, 1);
        assert_eq!(&execution.bytes[4..], b"typed-operands");
        client
            .verify_execution_receipt(&frame, execution.rows, &execution.bytes, &execution.receipt)
            .expect("receipt");
    }

    #[test]
    fn a_registered_graph_reuses_the_caller_result_buffer() {
        let registry = registry();
        let authority = authority(&registry);
        let mut client = ClientSession::new(authority.clone());
        let calls = Rc::new(Cell::new(0));
        let backend = FakeGraphBackend {
            identity: registry.identity(),
            calls: Rc::clone(&calls),
        };
        let mut backend = RegisteredGraphBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 64).expect("server");
        let mut replay = SingleSessionReplayStore::default();
        let mut result_buffer = Vec::with_capacity(128);
        let initial_pointer = result_buffer.as_ptr();

        for _ in 0..2 {
            let frame = client
                .encode_graph(
                    GraphOperation::new(11, 17, 13).expect("operation"),
                    b"typed-operands",
                    128,
                    1,
                    DEADLINE,
                )
                .expect("frame");
            let execution = server
                .execute_graph_reusing(
                    &frame,
                    &mut backend,
                    &mut replay,
                    &TestClock,
                    &mut result_buffer,
                )
                .expect("execution");
            client
                .verify_execution_receipt(
                    &frame,
                    execution.rows,
                    execution.bytes,
                    &execution.receipt,
                )
                .expect("receipt");
        }

        assert_eq!(calls.get(), 2);
        assert_eq!(result_buffer.as_ptr(), initial_pointer);
    }

    #[test]
    fn authority_bound_graphs_refuse_identity_and_session_expiry_drift() {
        let registry = registry();
        let authority = authority(&registry);
        let frame = ClientSession::new(authority.clone())
            .encode_graph(
                GraphOperation::new(11, 17, 13).expect("operation"),
                b"typed-operands",
                128,
                1,
                DEADLINE,
            )
            .expect("frame");
        let calls = Rc::new(Cell::new(0));
        let backend = AuthorityBoundBackend {
            inner: FakeGraphBackend {
                identity: registry.identity(),
                calls: Rc::clone(&calls),
            },
            tenant: [5; 16],
            principal: [9; 16],
            maximum_deadline_unix_us: DEADLINE,
        };
        let mut backend = RegisteredGraphBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority.clone(), 4_096, 64).expect("server");
        assert_eq!(
            server
                .execute_graph(
                    &frame,
                    &mut backend,
                    &mut MemoryReplayStore::default(),
                    &TestClock,
                )
                .expect_err("principal mismatch"),
            ProtocolError::AuthorityMismatch,
        );
        assert_eq!(calls.get(), 0);

        backend.backend.principal = [6; 16];
        backend.backend.maximum_deadline_unix_us = DEADLINE - 1;
        assert_eq!(
            server
                .execute_graph(
                    &frame,
                    &mut backend,
                    &mut MemoryReplayStore::default(),
                    &TestClock,
                )
                .expect_err("deadline mismatch"),
            ProtocolError::Expired,
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn authentication_refusal_precedes_graph_dispatch() {
        let registry = registry();
        let authority = authority(&registry);
        let mut client = ClientSession::new(authority.clone());
        let mut changed = client
            .encode_graph(
                GraphOperation::new(11, 17, 13).expect("operation"),
                b"typed-operands",
                128,
                1,
                DEADLINE,
            )
            .expect("frame");
        changed[GRAPH_HEADER_BYTES] ^= 1;
        let calls = Rc::new(Cell::new(0));
        let backend = FakeGraphBackend {
            identity: registry.identity(),
            calls: Rc::clone(&calls),
        };
        let mut backend = RegisteredGraphBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 64).expect("server");
        assert!(matches!(
            server.execute_graph(
                &changed,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &TestClock,
            ),
            Err(ProtocolError::AuthenticationFailed)
        ));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn every_graph_frame_bit_is_authenticated() {
        let registry = registry();
        let authority = authority(&registry);
        let frame = ClientSession::new(authority.clone())
            .encode_graph(
                GraphOperation::new(11, 17, 13).expect("operation"),
                b"typed-operands",
                128,
                1,
                DEADLINE,
            )
            .expect("frame");
        for bit in 0..frame.len() * 8 {
            let mut changed = frame.clone();
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                authenticate_graph(&authority, &changed).map(|_| ()),
                Err(ProtocolError::AuthenticationFailed),
                "accepted bit {bit}",
            );
        }
    }

    #[test]
    fn registry_identity_binds_graph_semantics_and_implementation() {
        let expected = registry();
        let mut changed_graph = registered_graph(17);
        changed_graph.nodes[1].plan_handle = 99;
        changed_graph.graph_digest = calculate_graph_digest(
            changed_graph.opcode,
            changed_graph.handle,
            changed_graph.result_shape,
            changed_graph.parameter_schema_digest,
            &changed_graph.nodes,
        );
        let changed_semantics = GraphRegistry::new(
            41,
            43,
            digest_label(b"schema", &[3]),
            digest_label(b"policy", &[4]),
            expected.manifest(),
            [changed_graph],
        )
        .expect("changed semantics");
        assert_ne!(expected.identity(), changed_semantics.identity());

        let mut changed_implementation = registered_graph(17);
        changed_implementation.implementation_digest = digest_label(b"implementation", &[99]);
        let changed_implementation = GraphRegistry::new(
            41,
            43,
            digest_label(b"schema", &[3]),
            digest_label(b"policy", &[4]),
            expected.manifest(),
            [changed_implementation],
        )
        .expect("changed implementation");
        assert_ne!(expected.identity(), changed_implementation.identity());
    }

    #[test]
    fn graph_dependencies_are_bounded_and_canonical() {
        let forward = RegisteredGraph::new_read(
            11,
            17,
            13,
            256,
            4_096,
            64,
            CAPABILITY_QUERY | CAPABILITY_GRAPH,
            digest_label(b"parameters", &[1]),
            digest_label(b"implementation", &[2]),
            [
                GraphNode::new(21, 31, []).expect("first"),
                GraphNode::new(22, 32, [1]).expect("second"),
            ],
        );
        assert_eq!(forward, Err(ProtocolError::DependencyOrder));

        let duplicate = RegisteredGraph::new_read(
            11,
            17,
            13,
            256,
            4_096,
            64,
            CAPABILITY_QUERY | CAPABILITY_GRAPH,
            digest_label(b"parameters", &[1]),
            digest_label(b"implementation", &[2]),
            [
                GraphNode::new(21, 31, []).expect("first"),
                GraphNode::new(22, 32, [0, 0]).expect("second"),
            ],
        );
        assert_eq!(duplicate, Err(ProtocolError::DuplicateDependency));
    }

    #[test]
    fn replay_and_unknown_graphs_do_not_repeat_backend_work() {
        let registry = registry();
        let authority = authority(&registry);
        let mut unknown_client = ClientSession::new(authority.clone());
        let unknown = unknown_client
            .encode_graph(
                GraphOperation::new(11, 99, 13).expect("unknown operation"),
                b"x",
                128,
                1,
                DEADLINE,
            )
            .expect("unknown frame");
        let mut client = ClientSession::new(authority.clone());
        let frame = client
            .encode_graph(
                GraphOperation::new(11, 17, 13).expect("operation"),
                b"x",
                128,
                1,
                DEADLINE,
            )
            .expect("frame");
        let calls = Rc::new(Cell::new(0));
        let backend = FakeGraphBackend {
            identity: registry.identity(),
            calls: Rc::clone(&calls),
        };
        let mut backend = RegisteredGraphBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 64).expect("server");
        let mut replay = MemoryReplayStore::default();
        assert!(matches!(
            server.execute_graph(&unknown, &mut backend, &mut replay, &TestClock),
            Err(ProtocolError::PlanNotRegistered)
        ));
        assert_eq!(calls.get(), 0);
        assert!(server
            .execute_graph(&frame, &mut backend, &mut replay, &TestClock)
            .is_ok());
        assert!(matches!(
            server.execute_graph(&frame, &mut backend, &mut replay, &TestClock),
            Err(ProtocolError::Replay)
        ));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn graph_parameter_limits_apply_before_backend_work() {
        let registry = registry();
        let authority = authority(&registry);
        let mut client = ClientSession::new(authority.clone());
        let frame = client
            .encode_graph(
                GraphOperation::new(11, 17, 13).expect("operation"),
                &[0; 257],
                128,
                1,
                DEADLINE,
            )
            .expect("frame");
        let calls = Rc::new(Cell::new(0));
        let backend = FakeGraphBackend {
            identity: registry.identity(),
            calls: Rc::clone(&calls),
        };
        let mut backend = RegisteredGraphBackend::new(&registry, backend).expect("backend");
        let server = ServerSession::new(authority, 4_096, 64).expect("server");
        assert!(matches!(
            server.execute_graph(
                &frame,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &TestClock,
            ),
            Err(ProtocolError::ParameterLimitExceeded)
        ));
        assert_eq!(calls.get(), 0);
    }
}
