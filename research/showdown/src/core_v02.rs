//! Define the first bounded NDABI execution contract.
//!
//! The decoder authenticates the complete frame before it allocates operation data.
//! It refuses unknown flags, non-canonical layouts, forward dependencies, and replayed nonces.
//! This module does not execute database work or claim backend performance.

use std::collections::BTreeSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const MAGIC: [u8; 4] = *b"NDBI";
const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 1;
const HEADER_BYTES: usize = 80;
const OPERATION_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_OPERATIONS: usize = 4_096;
const MAX_DEPENDENCIES: usize = 16_384;
const MAX_PARAMETER_BYTES: usize = 1024 * 1024;
const MAC_DOMAIN: &[u8] = b"ndabi-core-v1.1-frame";

pub const FRAME_ATOMIC: u8 = 1 << 0;
pub const FRAME_ALLOW_PARTIAL: u8 = 1 << 1;
const FRAME_FLAG_MASK: u8 = FRAME_ATOMIC | FRAME_ALLOW_PARTIAL;

pub const OPERATION_READ: u16 = 1 << 0;
pub const OPERATION_WRITE: u16 = 1 << 1;
pub const OPERATION_IDEMPOTENT: u16 = 1 << 2;
const OPERATION_FLAG_MASK: u16 = OPERATION_READ | OPERATION_WRITE | OPERATION_IDEMPOTENT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    ExecuteOne = 1,
    ExecuteBatch = 2,
    ExecuteGraph = 3,
}

impl TryFrom<u8> for FrameKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ExecuteOne),
            2 => Ok(Self::ExecuteBatch),
            3 => Ok(Self::ExecuteGraph),
            _ => Err(ProtocolError::UnknownKind(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operation {
    pub id: u32,
    pub plan_handle: u32,
    pub transaction_group: u32,
    pub result_shape: u32,
    pub flags: u16,
    pub dependencies: Vec<u16>,
    pub parameters: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: FrameKind,
    pub flags: u8,
    pub session_handle: u32,
    pub capability_handle: u32,
    pub schema_handle: u32,
    pub generation: u64,
    pub nonce: u64,
    pub deadline_unix_us: u64,
    pub result_budget: u32,
    pub operations: Vec<Operation>,
}

pub struct SessionBinding {
    pub session_handle: u32,
    pub capability_handle: u32,
    pub schema_handle: u32,
    pub generation: u64,
    pub max_result_bytes: u32,
    pub expires_unix_us: u64,
    key: [u8; 32],
}

impl Drop for SessionBinding {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl fmt::Debug for SessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionBinding")
            .field("session_handle", &self.session_handle)
            .field("capability_handle", &self.capability_handle)
            .field("schema_handle", &self.schema_handle)
            .field("generation", &self.generation)
            .field("max_result_bytes", &self.max_result_bytes)
            .field("expires_unix_us", &self.expires_unix_us)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl SessionBinding {
    pub fn new(
        session_handle: u32,
        capability_handle: u32,
        schema_handle: u32,
        generation: u64,
        max_result_bytes: u32,
        expires_unix_us: u64,
        key: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        if session_handle == 0 || capability_handle == 0 || schema_handle == 0 || generation == 0 {
            return Err(ProtocolError::ZeroBinding);
        }
        if max_result_bytes == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        if expires_unix_us == 0 {
            return Err(ProtocolError::ZeroDeadline);
        }
        Ok(Self {
            session_handle,
            capability_handle,
            schema_handle,
            generation,
            max_result_bytes,
            expires_unix_us,
            key,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProtocolError {
    AtomicPartialConflict,
    AuthenticationFailed,
    BindingMismatch,
    Bounds,
    DependencyCount,
    DependencyOrder,
    DuplicateDependency,
    DeadlineBeyondBinding,
    Expired,
    GenerationMismatch,
    InvalidFrameShape,
    InvalidOperationFlags,
    InvalidTransactionGroup,
    LengthMismatch,
    NonCanonicalLayout,
    NonCanonicalOperationId,
    Replay,
    ReservedBytes,
    ResultBudgetExceeded,
    UnknownFrameFlags(u8),
    UnknownKind(u8),
    UnknownOperationFlags(u16),
    UnsupportedExecution,
    UnsupportedVersion(u8, u8),
    ZeroBinding,
    ZeroBudget,
    ZeroDeadline,
    ZeroNonce,
    ZeroOperationField,
    WriteUnsupported,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProtocolError {}

pub struct SessionVerifier {
    binding: SessionBinding,
    last_nonce: u64,
}

impl SessionVerifier {
    pub fn new(binding: SessionBinding, last_nonce: u64) -> Self {
        Self {
            binding,
            last_nonce,
        }
    }

    pub fn last_nonce(&self) -> u64 {
        self.last_nonce
    }

    pub fn verify(&mut self, bytes: &[u8]) -> Result<Frame, ProtocolError> {
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProtocolError::Expired)?
            .as_micros();
        self.verify_at(bytes, u64::try_from(now_us).unwrap_or(u64::MAX))
    }

    pub fn verify_at(&mut self, bytes: &[u8], now_unix_us: u64) -> Result<Frame, ProtocolError> {
        // Reject stale work before the owned diagnostic path allocates operation parameters.
        let view = decode_authenticated_view(bytes, &self.binding)?;
        if view.deadline_unix_us <= now_unix_us {
            return Err(ProtocolError::Expired);
        }
        if view.nonce <= self.last_nonce {
            return Err(ProtocolError::Replay);
        }
        let frame = decode_authenticated(bytes, &self.binding)?;
        self.last_nonce = frame.nonce;
        Ok(frame)
    }

    pub fn verify_view<'a>(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<VerifiedFrameView<'a>, ProtocolError> {
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProtocolError::Expired)?
            .as_micros();
        self.verify_view_at(bytes, u64::try_from(now_us).unwrap_or(u64::MAX))
    }

    pub fn verify_view_at<'a>(
        &mut self,
        bytes: &'a [u8],
        now_unix_us: u64,
    ) -> Result<VerifiedFrameView<'a>, ProtocolError> {
        let frame = decode_authenticated_view(bytes, &self.binding)?;
        if frame.deadline_unix_us <= now_unix_us {
            return Err(ProtocolError::Expired);
        }
        if frame.nonce <= self.last_nonce {
            return Err(ProtocolError::Replay);
        }
        self.last_nonce = frame.nonce;
        Ok(frame)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedFrameView<'a> {
    kind: FrameKind,
    nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    operation_count: usize,
    operation_bytes: usize,
    payload: &'a [u8],
}

impl<'a> VerifiedFrameView<'a> {
    pub fn kind(self) -> FrameKind {
        self.kind
    }

    pub fn operation_count(self) -> usize {
        self.operation_count
    }

    pub fn result_budget(self) -> u32 {
        self.result_budget
    }

    pub fn operation(self, index: usize) -> Result<OperationView<'a>, ProtocolError> {
        if index >= self.operation_count {
            return Err(ProtocolError::Bounds);
        }
        Ok(operation_view(self.payload, self.operation_bytes, index))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OperationView<'a> {
    pub id: u32,
    pub plan_handle: u32,
    pub transaction_group: u32,
    pub result_shape: u32,
    pub flags: u16,
    pub dependencies: &'a [u8],
    pub parameters: &'a [u8],
}

impl OperationView<'_> {
    pub fn dependency_count(self) -> usize {
        self.dependencies.len() / size_of::<u16>()
    }

    pub fn dependency(self, index: usize) -> Result<u16, ProtocolError> {
        if index >= self.dependency_count() {
            return Err(ProtocolError::Bounds);
        }
        Ok(get_u16(self.dependencies, index * size_of::<u16>()))
    }
}

impl Frame {
    pub fn encode(&self, binding: &SessionBinding) -> Result<Vec<u8>, ProtocolError> {
        validate_frame(self)?;
        if self.session_handle != binding.session_handle
            || self.capability_handle != binding.capability_handle
            || self.schema_handle != binding.schema_handle
        {
            return Err(ProtocolError::BindingMismatch);
        }
        if self.generation != binding.generation {
            return Err(ProtocolError::GenerationMismatch);
        }
        if self.deadline_unix_us > binding.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondBinding);
        }
        if self.result_budget > binding.max_result_bytes {
            return Err(ProtocolError::ResultBudgetExceeded);
        }

        let dependency_count = self
            .operations
            .iter()
            .try_fold(0usize, |total, operation| {
                total.checked_add(operation.dependencies.len())
            })
            .ok_or(ProtocolError::Bounds)?;
        let operation_bytes = self
            .operations
            .len()
            .checked_mul(OPERATION_BYTES)
            .ok_or(ProtocolError::Bounds)?;
        let dependency_bytes = dependency_count
            .checked_mul(size_of::<u16>())
            .ok_or(ProtocolError::Bounds)?;
        let parameter_bytes = self.operations.iter().try_fold(0usize, |total, operation| {
            total.checked_add(operation.parameters.len())
        });
        let payload_bytes = operation_bytes
            .checked_add(dependency_bytes)
            .and_then(|value| value.checked_add(parameter_bytes?))
            .ok_or(ProtocolError::Bounds)?;
        let total_bytes = HEADER_BYTES
            .checked_add(payload_bytes)
            .ok_or(ProtocolError::Bounds)?;
        if total_bytes > MAX_FRAME_BYTES {
            return Err(ProtocolError::Bounds);
        }

        let mut bytes = vec![0u8; total_bytes];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = VERSION_MAJOR;
        bytes[5] = VERSION_MINOR;
        bytes[6] = self.kind as u8;
        bytes[7] = self.flags;
        put_u32(&mut bytes, 8, to_u32(total_bytes)?);
        put_u32(&mut bytes, 12, self.session_handle);
        put_u32(&mut bytes, 16, self.capability_handle);
        put_u32(&mut bytes, 20, self.schema_handle);
        put_u16(&mut bytes, 24, to_u16(self.operations.len())?);
        put_u16(&mut bytes, 26, to_u16(dependency_count)?);
        put_u64(&mut bytes, 28, self.generation);
        put_u64(&mut bytes, 36, self.nonce);
        put_u64(&mut bytes, 44, self.deadline_unix_us);
        put_u32(&mut bytes, 52, self.result_budget);
        put_u32(&mut bytes, 56, to_u32(payload_bytes)?);

        let dependency_base = HEADER_BYTES + operation_bytes;
        let parameter_base = dependency_base + dependency_bytes;
        let mut dependency_index = 0usize;
        let mut parameter_offset = parameter_base;
        for (index, operation) in self.operations.iter().enumerate() {
            let offset = HEADER_BYTES + index * OPERATION_BYTES;
            put_u32(&mut bytes, offset, operation.id);
            put_u32(&mut bytes, offset + 4, operation.plan_handle);
            put_u32(&mut bytes, offset + 8, operation.transaction_group);
            put_u32(&mut bytes, offset + 12, operation.result_shape);
            put_u32(
                &mut bytes,
                offset + 16,
                to_u32(parameter_offset - HEADER_BYTES)?,
            );
            put_u32(&mut bytes, offset + 20, to_u32(operation.parameters.len())?);
            put_u16(&mut bytes, offset + 24, to_u16(dependency_index)?);
            put_u16(
                &mut bytes,
                offset + 26,
                to_u16(operation.dependencies.len())?,
            );
            put_u16(&mut bytes, offset + 28, operation.flags);

            for dependency in &operation.dependencies {
                put_u16(
                    &mut bytes,
                    dependency_base + dependency_index * size_of::<u16>(),
                    *dependency,
                );
                dependency_index += 1;
            }
            let end = parameter_offset + operation.parameters.len();
            bytes[parameter_offset..end].copy_from_slice(&operation.parameters);
            parameter_offset = end;
        }
        apply_tag(&mut bytes, &binding.key);
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendCapabilities {
    pub set_queries: bool,
    pub prepared_pipeline: bool,
    pub server_graph: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionStrategy {
    DirectPrepared,
    SetQuery,
    PreparedPipeline,
    ServerGraph,
}

pub fn plan_execution(
    frame: &Frame,
    capabilities: BackendCapabilities,
) -> Result<ExecutionStrategy, ProtocolError> {
    validate_frame(frame)?;
    match frame.kind {
        FrameKind::ExecuteOne => Ok(ExecutionStrategy::DirectPrepared),
        FrameKind::ExecuteBatch => {
            let one_plan = frame
                .operations
                .windows(2)
                .all(|pair| pair[0].plan_handle == pair[1].plan_handle);
            if one_plan && capabilities.set_queries {
                Ok(ExecutionStrategy::SetQuery)
            } else if capabilities.prepared_pipeline {
                Ok(ExecutionStrategy::PreparedPipeline)
            } else {
                Err(ProtocolError::UnsupportedExecution)
            }
        }
        FrameKind::ExecuteGraph if capabilities.server_graph => Ok(ExecutionStrategy::ServerGraph),
        FrameKind::ExecuteGraph => Err(ProtocolError::UnsupportedExecution),
    }
}

pub fn plan_execution_view(
    frame: VerifiedFrameView<'_>,
    capabilities: BackendCapabilities,
) -> Result<ExecutionStrategy, ProtocolError> {
    match frame.kind {
        FrameKind::ExecuteOne => Ok(ExecutionStrategy::DirectPrepared),
        FrameKind::ExecuteBatch => {
            let first_plan = frame.operation(0)?.plan_handle;
            let mut one_plan = true;
            for index in 1..frame.operation_count {
                one_plan &= frame.operation(index)?.plan_handle == first_plan;
            }
            if one_plan && capabilities.set_queries {
                Ok(ExecutionStrategy::SetQuery)
            } else if capabilities.prepared_pipeline {
                Ok(ExecutionStrategy::PreparedPipeline)
            } else {
                Err(ProtocolError::UnsupportedExecution)
            }
        }
        FrameKind::ExecuteGraph if capabilities.server_graph => Ok(ExecutionStrategy::ServerGraph),
        FrameKind::ExecuteGraph => Err(ProtocolError::UnsupportedExecution),
    }
}

fn decode_authenticated_view<'a>(
    bytes: &'a [u8],
    binding: &SessionBinding,
) -> Result<VerifiedFrameView<'a>, ProtocolError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::Bounds);
    }
    if !tag_matches(bytes, &binding.key) {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if bytes[0..4] != MAGIC {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if bytes[4] != VERSION_MAJOR || bytes[5] != VERSION_MINOR {
        return Err(ProtocolError::UnsupportedVersion(bytes[4], bytes[5]));
    }
    let kind = FrameKind::try_from(bytes[6])?;
    let flags = bytes[7];
    let total_bytes = to_usize(get_u32(bytes, 8));
    let payload_bytes = to_usize(get_u32(bytes, 56));
    if total_bytes != bytes.len() || payload_bytes != bytes.len() - HEADER_BYTES {
        return Err(ProtocolError::LengthMismatch);
    }
    if bytes[60..64] != [0; 4] {
        return Err(ProtocolError::ReservedBytes);
    }
    let session_handle = get_u32(bytes, 12);
    let capability_handle = get_u32(bytes, 16);
    let schema_handle = get_u32(bytes, 20);
    if session_handle != binding.session_handle
        || capability_handle != binding.capability_handle
        || schema_handle != binding.schema_handle
    {
        return Err(ProtocolError::BindingMismatch);
    }
    let generation = get_u64(bytes, 28);
    if generation != binding.generation {
        return Err(ProtocolError::GenerationMismatch);
    }
    if flags & !FRAME_FLAG_MASK != 0 {
        return Err(ProtocolError::UnknownFrameFlags(flags));
    }
    if flags & FRAME_ATOMIC != 0 && flags & FRAME_ALLOW_PARTIAL != 0 {
        return Err(ProtocolError::AtomicPartialConflict);
    }

    let operation_count = usize::from(get_u16(bytes, 24));
    let dependency_count = usize::from(get_u16(bytes, 26));
    let valid_shape = match kind {
        FrameKind::ExecuteOne => operation_count == 1,
        FrameKind::ExecuteBatch | FrameKind::ExecuteGraph => operation_count >= 2,
    };
    if !valid_shape || operation_count > MAX_OPERATIONS || dependency_count > MAX_DEPENDENCIES {
        return Err(ProtocolError::InvalidFrameShape);
    }
    let operation_bytes = operation_count
        .checked_mul(OPERATION_BYTES)
        .ok_or(ProtocolError::Bounds)?;
    let dependency_bytes = dependency_count
        .checked_mul(size_of::<u16>())
        .ok_or(ProtocolError::Bounds)?;
    let parameter_base = operation_bytes
        .checked_add(dependency_bytes)
        .ok_or(ProtocolError::Bounds)?;
    if parameter_base > payload_bytes {
        return Err(ProtocolError::Bounds);
    }
    let payload = &bytes[HEADER_BYTES..];
    let mut expected_dependency_index = 0usize;
    let mut expected_parameter_offset = parameter_base;
    let mut graph_has_dependency = false;
    for index in 0..operation_count {
        let offset = index * OPERATION_BYTES;
        if payload[offset + 30..offset + 32] != [0; 2] {
            return Err(ProtocolError::ReservedBytes);
        }
        let dependency_start = usize::from(get_u16(payload, offset + 24));
        let operation_dependency_count = usize::from(get_u16(payload, offset + 26));
        let parameter_offset = to_usize(get_u32(payload, offset + 16));
        let parameter_length = to_usize(get_u32(payload, offset + 20));
        if dependency_start != expected_dependency_index
            || parameter_offset != expected_parameter_offset
            || parameter_length > MAX_PARAMETER_BYTES
        {
            return Err(ProtocolError::NonCanonicalLayout);
        }
        let dependency_end = dependency_start
            .checked_add(operation_dependency_count)
            .ok_or(ProtocolError::Bounds)?;
        let parameter_end = parameter_offset
            .checked_add(parameter_length)
            .ok_or(ProtocolError::Bounds)?;
        if dependency_end > dependency_count || parameter_end > payload.len() {
            return Err(ProtocolError::Bounds);
        }
        let operation = operation_view(payload, operation_bytes, index);
        let expected_id = u32::try_from(index + 1).map_err(|_| ProtocolError::Bounds)?;
        if operation.id != expected_id {
            return Err(ProtocolError::NonCanonicalOperationId);
        }
        if operation.plan_handle == 0 || operation.result_shape == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        if operation.flags & !OPERATION_FLAG_MASK != 0 {
            return Err(ProtocolError::UnknownOperationFlags(operation.flags));
        }
        if operation.flags & OPERATION_WRITE != 0 {
            return Err(ProtocolError::WriteUnsupported);
        }
        let access = operation.flags & (OPERATION_READ | OPERATION_WRITE);
        if access != OPERATION_READ && access != OPERATION_WRITE {
            return Err(ProtocolError::InvalidOperationFlags);
        }
        if operation.transaction_group != 0 && flags & FRAME_ATOMIC == 0 {
            return Err(ProtocolError::InvalidTransactionGroup);
        }
        if kind != FrameKind::ExecuteGraph && operation_dependency_count != 0 {
            return Err(ProtocolError::DependencyCount);
        }
        for dependency_index in 0..operation_dependency_count {
            let dependency = operation.dependency(dependency_index)?;
            if usize::from(dependency) >= index {
                return Err(ProtocolError::DependencyOrder);
            }
            for prior_dependency in 0..dependency_index {
                if operation.dependency(prior_dependency)? == dependency {
                    return Err(ProtocolError::DuplicateDependency);
                }
            }
            graph_has_dependency = true;
        }
        expected_dependency_index = dependency_end;
        expected_parameter_offset = parameter_end;
    }
    if expected_dependency_index != dependency_count || expected_parameter_offset != payload.len() {
        return Err(ProtocolError::NonCanonicalLayout);
    }
    if kind == FrameKind::ExecuteGraph && !graph_has_dependency {
        return Err(ProtocolError::DependencyCount);
    }

    let nonce = get_u64(bytes, 36);
    let deadline_unix_us = get_u64(bytes, 44);
    let result_budget = get_u32(bytes, 52);
    if nonce == 0 {
        return Err(ProtocolError::ZeroNonce);
    }
    if deadline_unix_us == 0 {
        return Err(ProtocolError::ZeroDeadline);
    }
    if result_budget == 0 {
        return Err(ProtocolError::ZeroBudget);
    }
    if deadline_unix_us > binding.expires_unix_us {
        return Err(ProtocolError::DeadlineBeyondBinding);
    }
    if result_budget > binding.max_result_bytes {
        return Err(ProtocolError::ResultBudgetExceeded);
    }
    Ok(VerifiedFrameView {
        kind,
        nonce,
        deadline_unix_us,
        result_budget,
        operation_count,
        operation_bytes,
        payload,
    })
}

fn operation_view<'a>(
    payload: &'a [u8],
    operation_bytes: usize,
    index: usize,
) -> OperationView<'a> {
    let offset = index * OPERATION_BYTES;
    let dependency_start = usize::from(get_u16(payload, offset + 24));
    let dependency_count = usize::from(get_u16(payload, offset + 26));
    let dependency_byte_start = operation_bytes + dependency_start * size_of::<u16>();
    let dependency_byte_end = dependency_byte_start + dependency_count * size_of::<u16>();
    let parameter_start = to_usize(get_u32(payload, offset + 16));
    let parameter_end = parameter_start + to_usize(get_u32(payload, offset + 20));
    OperationView {
        id: get_u32(payload, offset),
        plan_handle: get_u32(payload, offset + 4),
        transaction_group: get_u32(payload, offset + 8),
        result_shape: get_u32(payload, offset + 12),
        flags: get_u16(payload, offset + 28),
        dependencies: &payload[dependency_byte_start..dependency_byte_end],
        parameters: &payload[parameter_start..parameter_end],
    }
}

fn decode_authenticated(bytes: &[u8], binding: &SessionBinding) -> Result<Frame, ProtocolError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::Bounds);
    }
    if !tag_matches(bytes, &binding.key) {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if bytes[0..4] != MAGIC {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if bytes[4] != VERSION_MAJOR || bytes[5] != VERSION_MINOR {
        return Err(ProtocolError::UnsupportedVersion(bytes[4], bytes[5]));
    }
    let kind = FrameKind::try_from(bytes[6])?;
    let flags = bytes[7];
    let total_bytes = to_usize(get_u32(bytes, 8));
    let payload_bytes = to_usize(get_u32(bytes, 56));
    if total_bytes != bytes.len() || payload_bytes != bytes.len() - HEADER_BYTES {
        return Err(ProtocolError::LengthMismatch);
    }
    if bytes[60..64] != [0; 4] {
        return Err(ProtocolError::ReservedBytes);
    }
    let session_handle = get_u32(bytes, 12);
    let capability_handle = get_u32(bytes, 16);
    let schema_handle = get_u32(bytes, 20);
    if session_handle != binding.session_handle
        || capability_handle != binding.capability_handle
        || schema_handle != binding.schema_handle
    {
        return Err(ProtocolError::BindingMismatch);
    }
    let generation = get_u64(bytes, 28);
    if generation != binding.generation {
        return Err(ProtocolError::GenerationMismatch);
    }
    let operation_count = usize::from(get_u16(bytes, 24));
    let dependency_count = usize::from(get_u16(bytes, 26));
    if operation_count == 0
        || operation_count > MAX_OPERATIONS
        || dependency_count > MAX_DEPENDENCIES
    {
        return Err(ProtocolError::Bounds);
    }
    let operation_bytes = operation_count
        .checked_mul(OPERATION_BYTES)
        .ok_or(ProtocolError::Bounds)?;
    let dependency_bytes = dependency_count
        .checked_mul(size_of::<u16>())
        .ok_or(ProtocolError::Bounds)?;
    let parameter_base = operation_bytes
        .checked_add(dependency_bytes)
        .ok_or(ProtocolError::Bounds)?;
    if parameter_base > payload_bytes {
        return Err(ProtocolError::Bounds);
    }

    let payload = &bytes[HEADER_BYTES..];
    let mut operations = Vec::with_capacity(operation_count);
    let mut expected_dependency_index = 0usize;
    let mut expected_parameter_offset = parameter_base;
    for index in 0..operation_count {
        let offset = index * OPERATION_BYTES;
        if payload[offset + 30..offset + 32] != [0; 2] {
            return Err(ProtocolError::ReservedBytes);
        }
        let dependency_start = usize::from(get_u16(payload, offset + 24));
        let operation_dependency_count = usize::from(get_u16(payload, offset + 26));
        let parameter_offset = to_usize(get_u32(payload, offset + 16));
        let parameter_length = to_usize(get_u32(payload, offset + 20));
        if dependency_start != expected_dependency_index
            || parameter_offset != expected_parameter_offset
            || parameter_length > MAX_PARAMETER_BYTES
        {
            return Err(ProtocolError::NonCanonicalLayout);
        }
        let dependency_end = dependency_start
            .checked_add(operation_dependency_count)
            .ok_or(ProtocolError::Bounds)?;
        let parameter_end = parameter_offset
            .checked_add(parameter_length)
            .ok_or(ProtocolError::Bounds)?;
        if dependency_end > dependency_count || parameter_end > payload.len() {
            return Err(ProtocolError::Bounds);
        }
        let dependencies = (dependency_start..dependency_end)
            .map(|dependency_index| {
                get_u16(
                    payload,
                    operation_bytes + dependency_index * size_of::<u16>(),
                )
            })
            .collect();
        operations.push(Operation {
            id: get_u32(payload, offset),
            plan_handle: get_u32(payload, offset + 4),
            transaction_group: get_u32(payload, offset + 8),
            result_shape: get_u32(payload, offset + 12),
            flags: get_u16(payload, offset + 28),
            dependencies,
            parameters: payload[parameter_offset..parameter_end].to_vec(),
        });
        expected_dependency_index = dependency_end;
        expected_parameter_offset = parameter_end;
    }
    if expected_dependency_index != dependency_count || expected_parameter_offset != payload.len() {
        return Err(ProtocolError::NonCanonicalLayout);
    }

    let frame = Frame {
        kind,
        flags,
        session_handle,
        capability_handle,
        schema_handle,
        generation,
        nonce: get_u64(bytes, 36),
        deadline_unix_us: get_u64(bytes, 44),
        result_budget: get_u32(bytes, 52),
        operations,
    };
    if frame.deadline_unix_us > binding.expires_unix_us {
        return Err(ProtocolError::DeadlineBeyondBinding);
    }
    if frame.result_budget > binding.max_result_bytes {
        return Err(ProtocolError::ResultBudgetExceeded);
    }
    validate_frame(&frame)?;
    Ok(frame)
}

fn validate_frame(frame: &Frame) -> Result<(), ProtocolError> {
    if frame.flags & !FRAME_FLAG_MASK != 0 {
        return Err(ProtocolError::UnknownFrameFlags(frame.flags));
    }
    if frame.flags & FRAME_ATOMIC != 0 && frame.flags & FRAME_ALLOW_PARTIAL != 0 {
        return Err(ProtocolError::AtomicPartialConflict);
    }
    if frame.session_handle == 0 || frame.capability_handle == 0 || frame.schema_handle == 0 {
        return Err(ProtocolError::ZeroBinding);
    }
    if frame.generation == 0 {
        return Err(ProtocolError::GenerationMismatch);
    }
    if frame.nonce == 0 {
        return Err(ProtocolError::ZeroNonce);
    }
    if frame.deadline_unix_us == 0 {
        return Err(ProtocolError::ZeroDeadline);
    }
    if frame.result_budget == 0 {
        return Err(ProtocolError::ZeroBudget);
    }
    let operation_count = frame.operations.len();
    let shape_is_valid = match frame.kind {
        FrameKind::ExecuteOne => operation_count == 1,
        FrameKind::ExecuteBatch | FrameKind::ExecuteGraph => operation_count >= 2,
    };
    if !shape_is_valid || operation_count > MAX_OPERATIONS {
        return Err(ProtocolError::InvalidFrameShape);
    }

    let mut dependency_total = 0usize;
    let mut graph_has_dependency = false;
    for (index, operation) in frame.operations.iter().enumerate() {
        let expected_id = u32::try_from(index + 1).map_err(|_| ProtocolError::Bounds)?;
        if operation.id != expected_id {
            return Err(ProtocolError::NonCanonicalOperationId);
        }
        if operation.plan_handle == 0 || operation.result_shape == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        if operation.flags & !OPERATION_FLAG_MASK != 0 {
            return Err(ProtocolError::UnknownOperationFlags(operation.flags));
        }
        if operation.flags & OPERATION_WRITE != 0 {
            return Err(ProtocolError::WriteUnsupported);
        }
        let access = operation.flags & (OPERATION_READ | OPERATION_WRITE);
        if access != OPERATION_READ && access != OPERATION_WRITE {
            return Err(ProtocolError::InvalidOperationFlags);
        }
        if operation.parameters.len() > MAX_PARAMETER_BYTES {
            return Err(ProtocolError::Bounds);
        }
        if operation.transaction_group != 0 && frame.flags & FRAME_ATOMIC == 0 {
            return Err(ProtocolError::InvalidTransactionGroup);
        }
        if frame.kind != FrameKind::ExecuteGraph && !operation.dependencies.is_empty() {
            return Err(ProtocolError::DependencyCount);
        }
        let mut dependencies = BTreeSet::new();
        for dependency in &operation.dependencies {
            if usize::from(*dependency) >= index {
                return Err(ProtocolError::DependencyOrder);
            }
            if !dependencies.insert(*dependency) {
                return Err(ProtocolError::DuplicateDependency);
            }
            graph_has_dependency = true;
        }
        dependency_total = dependency_total
            .checked_add(operation.dependencies.len())
            .ok_or(ProtocolError::Bounds)?;
    }
    if dependency_total > MAX_DEPENDENCIES {
        return Err(ProtocolError::Bounds);
    }
    if frame.kind == FrameKind::ExecuteGraph && !graph_has_dependency {
        return Err(ProtocolError::DependencyCount);
    }
    Ok(())
}

fn apply_tag(bytes: &mut [u8], key: &[u8; 32]) {
    let tag = calculate_tag(bytes, key);
    bytes[64..64 + TAG_BYTES].copy_from_slice(&tag);
}

fn tag_matches(bytes: &[u8], key: &[u8; 32]) -> bool {
    let expected = calculate_tag(bytes, key);
    bool::from(bytes[64..64 + TAG_BYTES].ct_eq(&expected))
}

fn calculate_tag(bytes: &[u8], key: &[u8; 32]) -> [u8; TAG_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(MAC_DOMAIN);
    hasher.update(&bytes[..64]);
    hasher.update(&bytes[HEADER_BYTES..]);
    let digest = hasher.finalize();
    hasher.zeroize();
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&digest.as_bytes()[..TAG_BYTES]);
    tag
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("bounded slice"))
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("bounded slice"))
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("bounded slice"))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn to_u16(value: usize) -> Result<u16, ProtocolError> {
    u16::try_from(value).map_err(|_| ProtocolError::Bounds)
}

fn to_u32(value: usize) -> Result<u32, ProtocolError> {
    u32::try_from(value).map_err(|_| ProtocolError::Bounds)
}

fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("u32 fits usize on supported targets")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    fn binding() -> SessionBinding {
        SessionBinding::new(7, 11, 13, 17, 65_536, u64::MAX, KEY).expect("valid binding")
    }

    fn operation(id: u32, plan_handle: u32, parameters: &[u8]) -> Operation {
        Operation {
            id,
            plan_handle,
            transaction_group: 0,
            result_shape: 23,
            flags: OPERATION_READ | OPERATION_IDEMPOTENT,
            dependencies: Vec::new(),
            parameters: parameters.to_vec(),
        }
    }

    fn frame(kind: FrameKind, operations: Vec<Operation>) -> Frame {
        Frame {
            kind,
            flags: 0,
            session_handle: 7,
            capability_handle: 11,
            schema_handle: 13,
            generation: 17,
            nonce: 19,
            deadline_unix_us: u64::MAX,
            result_budget: 65_536,
            operations,
        }
    }

    #[test]
    fn one_operation_round_trips_exactly() {
        let expected = frame(FrameKind::ExecuteOne, vec![operation(1, 29, b"alpha")]);
        let bytes = expected.encode(&binding()).expect("encode frame");
        let actual = SessionVerifier::new(binding(), 0)
            .verify(&bytes)
            .expect("verify frame");
        assert_eq!(actual, expected);
    }

    #[test]
    fn homogeneous_batch_selects_one_set_query() {
        let expected = frame(
            FrameKind::ExecuteBatch,
            vec![operation(1, 29, b"a"), operation(2, 29, b"b")],
        );
        assert_eq!(
            plan_execution(
                &expected,
                BackendCapabilities {
                    set_queries: true,
                    prepared_pipeline: true,
                    server_graph: true,
                }
            ),
            Ok(ExecutionStrategy::SetQuery)
        );
        let bytes = expected.encode(&binding()).expect("encode batch");
        assert_eq!(
            SessionVerifier::new(binding(), 0)
                .verify(&bytes)
                .expect("verify batch"),
            expected
        );
        let view = SessionVerifier::new(binding(), 0)
            .verify_view(&bytes)
            .expect("verify borrowed batch");
        assert_eq!(view.kind(), FrameKind::ExecuteBatch);
        assert_eq!(view.operation_count(), 2);
        assert_eq!(view.result_budget(), 65_536);
        assert_eq!(view.operation(0).expect("first operation").parameters, b"a");
        assert_eq!(
            view.operation(1).expect("second operation").parameters,
            b"b"
        );
        assert_eq!(
            plan_execution_view(
                view,
                BackendCapabilities {
                    set_queries: true,
                    prepared_pipeline: true,
                    server_graph: true,
                }
            ),
            Ok(ExecutionStrategy::SetQuery)
        );
    }

    #[test]
    fn heterogeneous_batch_selects_one_prepared_pipeline() {
        let expected = frame(
            FrameKind::ExecuteBatch,
            vec![operation(1, 29, b"a"), operation(2, 31, b"b")],
        );
        assert_eq!(
            plan_execution(
                &expected,
                BackendCapabilities {
                    set_queries: true,
                    prepared_pipeline: true,
                    server_graph: false,
                }
            ),
            Ok(ExecutionStrategy::PreparedPipeline)
        );
    }

    #[test]
    fn graph_requires_prior_dependencies_and_server_support() {
        let first = operation(1, 29, b"a");
        let mut second = operation(2, 31, b"b");
        second.dependencies.push(0);
        let expected = frame(FrameKind::ExecuteGraph, vec![first, second]);
        assert_eq!(
            plan_execution(
                &expected,
                BackendCapabilities {
                    set_queries: true,
                    prepared_pipeline: true,
                    server_graph: true,
                }
            ),
            Ok(ExecutionStrategy::ServerGraph)
        );
        assert_eq!(
            plan_execution(
                &expected,
                BackendCapabilities {
                    set_queries: true,
                    prepared_pipeline: true,
                    server_graph: false,
                }
            ),
            Err(ProtocolError::UnsupportedExecution)
        );
    }

    #[test]
    fn every_authenticated_byte_is_bound() {
        let expected = frame(
            FrameKind::ExecuteBatch,
            vec![operation(1, 29, b"alpha"), operation(2, 29, b"beta")],
        );
        let bytes = expected.encode(&binding()).expect("encode batch");
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            let mut verifier = SessionVerifier::new(binding(), 0);
            assert!(verifier.verify(&changed).is_err(), "accepted byte {index}");
        }
    }

    #[test]
    fn authenticated_invalid_operation_flags_fail_both_decoders() {
        let expected = frame(FrameKind::ExecuteOne, vec![operation(1, 29, b"alpha")]);
        let mut bytes = expected.encode(&binding()).expect("encode frame");
        put_u16(&mut bytes, HEADER_BYTES + 28, 1 << 15);
        apply_tag(&mut bytes, &KEY);
        assert_eq!(
            SessionVerifier::new(binding(), 0).verify(&bytes),
            Err(ProtocolError::UnknownOperationFlags(1 << 15))
        );
        assert!(matches!(
            SessionVerifier::new(binding(), 0).verify_view(&bytes),
            Err(ProtocolError::UnknownOperationFlags(value)) if value == 1 << 15
        ));
    }

    #[test]
    fn replay_does_not_advance_or_repeat() {
        let expected = frame(FrameKind::ExecuteOne, vec![operation(1, 29, b"alpha")]);
        let bytes = expected.encode(&binding()).expect("encode frame");
        let mut verifier = SessionVerifier::new(binding(), 0);
        assert!(verifier.verify(&bytes).is_ok());
        assert_eq!(verifier.verify(&bytes), Err(ProtocolError::Replay));
    }

    #[test]
    fn an_expired_frame_does_not_advance_the_nonce() {
        let mut expected = frame(FrameKind::ExecuteOne, vec![operation(1, 29, b"alpha")]);
        expected.deadline_unix_us = 20;
        let expired = expected.encode(&binding()).expect("encode expired frame");
        expected.deadline_unix_us = 40;
        let current = expected.encode(&binding()).expect("encode current frame");
        let mut verifier = SessionVerifier::new(binding(), 0);
        assert_eq!(
            verifier.verify_at(&expired, 20),
            Err(ProtocolError::Expired)
        );
        assert!(verifier.verify_at(&current, 30).is_ok());
    }

    #[test]
    fn binding_and_generation_changes_fail_closed() {
        let expected = frame(FrameKind::ExecuteOne, vec![operation(1, 29, b"alpha")]);
        let bytes = expected.encode(&binding()).expect("encode frame");
        let other_session =
            SessionBinding::new(8, 11, 13, 17, 65_536, u64::MAX, KEY).expect("binding");
        assert_eq!(
            SessionVerifier::new(other_session, 0).verify(&bytes),
            Err(ProtocolError::BindingMismatch)
        );
        let other_generation =
            SessionBinding::new(7, 11, 13, 18, 65_536, u64::MAX, KEY).expect("binding");
        assert_eq!(
            SessionVerifier::new(other_generation, 0).verify(&bytes),
            Err(ProtocolError::GenerationMismatch)
        );
    }

    #[test]
    fn invalid_shapes_fail_before_encoding() {
        assert_eq!(
            frame(FrameKind::ExecuteOne, Vec::new()).encode(&binding()),
            Err(ProtocolError::InvalidFrameShape)
        );
        assert_eq!(
            frame(FrameKind::ExecuteBatch, vec![operation(1, 29, b"alpha")]).encode(&binding()),
            Err(ProtocolError::InvalidFrameShape)
        );
    }

    #[test]
    fn graph_refuses_forward_and_duplicate_dependencies() {
        let first = operation(1, 29, b"a");
        let mut second = operation(2, 31, b"b");
        second.dependencies.push(1);
        assert_eq!(
            frame(FrameKind::ExecuteGraph, vec![first.clone(), second]).encode(&binding()),
            Err(ProtocolError::DependencyOrder)
        );
        let mut second = operation(2, 31, b"b");
        second.dependencies.extend_from_slice(&[0, 0]);
        assert_eq!(
            frame(FrameKind::ExecuteGraph, vec![first, second]).encode(&binding()),
            Err(ProtocolError::DuplicateDependency)
        );
    }

    #[test]
    fn operation_identifiers_are_dense_and_canonical() {
        let expected = frame(FrameKind::ExecuteOne, vec![operation(7, 29, b"alpha")]);
        assert_eq!(
            expected.encode(&binding()),
            Err(ProtocolError::NonCanonicalOperationId)
        );
    }

    #[test]
    fn transaction_groups_require_atomic_execution() {
        let mut first = operation(1, 29, b"a");
        first.transaction_group = 1;
        let mut second = operation(2, 29, b"b");
        second.transaction_group = 1;
        let mut expected = frame(FrameKind::ExecuteBatch, vec![first, second]);
        assert_eq!(
            expected.encode(&binding()),
            Err(ProtocolError::InvalidTransactionGroup)
        );
        expected.flags = FRAME_ATOMIC;
        assert!(expected.encode(&binding()).is_ok());
        expected.flags |= FRAME_ALLOW_PARTIAL;
        assert_eq!(
            expected.encode(&binding()),
            Err(ProtocolError::AtomicPartialConflict)
        );
    }

    #[test]
    fn an_unsupported_batch_does_not_fall_back_to_sequential_work() {
        let expected = frame(
            FrameKind::ExecuteBatch,
            vec![operation(1, 29, b"a"), operation(2, 31, b"b")],
        );
        assert_eq!(
            plan_execution(
                &expected,
                BackendCapabilities {
                    set_queries: true,
                    prepared_pipeline: false,
                    server_graph: false,
                }
            ),
            Err(ProtocolError::UnsupportedExecution)
        );
    }

    #[test]
    fn resumed_nonce_state_refuses_a_pre_restart_replay() {
        let expected = frame(FrameKind::ExecuteOne, vec![operation(1, 29, b"alpha")]);
        let bytes = expected.encode(&binding()).expect("encode frame");
        let mut verifier = SessionVerifier::new(binding(), 19);
        assert_eq!(verifier.verify(&bytes), Err(ProtocolError::Replay));
        assert_eq!(verifier.last_nonce(), 19);
    }

    #[test]
    fn binding_secrets_are_redacted() {
        let debug = format!("{:?}", binding());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("66, 66, 66"));
    }

    #[test]
    fn write_deadline_and_budget_escalations_fail_closed() {
        let mut expected = frame(FrameKind::ExecuteOne, vec![operation(1, 29, b"alpha")]);
        expected.operations[0].flags = OPERATION_WRITE | OPERATION_IDEMPOTENT;
        assert_eq!(
            expected.encode(&binding()),
            Err(ProtocolError::WriteUnsupported)
        );

        let strict =
            SessionBinding::new(7, 11, 13, 17, 65_535, u64::MAX - 1, KEY).expect("strict binding");
        expected.operations[0].flags = OPERATION_READ | OPERATION_IDEMPOTENT;
        assert_eq!(
            expected.encode(&strict),
            Err(ProtocolError::DeadlineBeyondBinding)
        );
        expected.deadline_unix_us = u64::MAX - 1;
        assert_eq!(
            expected.encode(&strict),
            Err(ProtocolError::ResultBudgetExceeded)
        );
    }

    #[test]
    fn unauthenticated_headers_return_one_authentication_error() {
        let expected = frame(FrameKind::ExecuteOne, vec![operation(1, 29, b"alpha")]);
        let mut bytes = expected.encode(&binding()).expect("encode frame");
        for index in [4usize, 5, 7, 12, 16, 20, 28, 60] {
            bytes[index] ^= 1;
            assert_eq!(
                SessionVerifier::new(binding(), 0).verify(&bytes),
                Err(ProtocolError::AuthenticationFailed)
            );
            bytes[index] ^= 1;
        }
    }
}
