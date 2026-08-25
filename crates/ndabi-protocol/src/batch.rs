//! Define one canonical homogeneous batch frame.
//!
//! The frame carries many operand tuples for one registered plan.
//! A backend must execute one fused engine operation or refuse the frame.

use std::fmt;

use subtle::ConstantTimeEq;

use super::{
    digest_receipt, get_i64, get_u16, get_u32, get_u64, put_i64, put_u16, put_u32, put_u64,
    receipt, BackendIdentity, BoundedOutput, ClientSession, Clock, ExecutionLimits, ProtocolError,
    ReplayStore, ServerSession, AUTHENTICATED_BYTES, BATCH_FRAME_DOMAIN, MAGIC, READ_ACCESS,
    TAG_BYTES, VERSION_MAJOR, VERSION_MINOR,
};

const EXECUTE_BATCH_HANDLE: u8 = 2;
#[cfg(feature = "benchmark-governed-native")]
const GOVERNED_NATIVE_DOMAIN: &[u8] = b"ndabi/benchmark/governed-native/v1";
const BATCH_HEADER_BYTES: usize = AUTHENTICATED_BYTES;
const BATCH_BASE_BYTES: usize = BATCH_HEADER_BYTES + TAG_BYTES;
pub const BATCH_OPERAND_BYTES: usize = 20;
pub const MAX_BATCH_OPERATIONS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchOperation {
    pub opcode: u16,
    pub plan_handle: u32,
    pub result_shape: u32,
}

impl BatchOperation {
    pub fn new(opcode: u16, plan_handle: u32, result_shape: u32) -> Result<Self, ProtocolError> {
        if opcode == 0 || plan_handle == 0 || result_shape == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        Ok(Self {
            opcode,
            plan_handle,
            result_shape,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchItem {
    pub first: i64,
    pub second: i64,
    pub third: u32,
}

impl BatchItem {
    pub fn new(first: i64, second: i64, third: u32) -> Self {
        Self {
            first,
            second,
            third,
        }
    }
}

#[derive(Clone, Copy)]
pub struct BatchItems<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl fmt::Debug for BatchItems<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchItems")
            .field("remaining", &self.len())
            .finish()
    }
}

impl Iterator for BatchItems<'_> {
    type Item = BatchItem;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.index.checked_mul(BATCH_OPERAND_BYTES)?;
        let bytes = self.bytes.get(offset..offset + BATCH_OPERAND_BYTES)?;
        self.index += 1;
        Some(BatchItem {
            first: get_i64(bytes, 0),
            second: get_i64(bytes, 8),
            third: get_u32(bytes, 16),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for BatchItems<'_> {
    fn len(&self) -> usize {
        self.bytes.len() / BATCH_OPERAND_BYTES - self.index
    }
}

pub fn batch_frame_bytes(operation_count: usize) -> Result<usize, ProtocolError> {
    if operation_count < 2 {
        return Err(ProtocolError::BatchTooSmall);
    }
    if operation_count > MAX_BATCH_OPERATIONS {
        return Err(ProtocolError::BatchLimitExceeded);
    }
    operation_count
        .checked_mul(BATCH_OPERAND_BYTES)
        .and_then(|payload| BATCH_BASE_BYTES.checked_add(payload))
        .ok_or(ProtocolError::LengthMismatch)
}

impl ClientSession {
    #[allow(clippy::too_many_arguments)]
    pub fn encode_batch_into(
        &mut self,
        operation: BatchOperation,
        items: &[BatchItem],
        result_budget: u32,
        row_budget: u32,
        deadline_unix_us: u64,
        output: &mut [u8],
    ) -> Result<(), ProtocolError> {
        if result_budget == 0 || row_budget == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let frame_bytes = batch_frame_bytes(items.len())?;
        if output.len() != frame_bytes {
            return Err(ProtocolError::LengthMismatch);
        }
        let operation_count =
            u32::try_from(items.len()).map_err(|_| ProtocolError::BatchLimitExceeded)?;
        let payload_bytes = operation_count
            .checked_mul(BATCH_OPERAND_BYTES as u32)
            .ok_or(ProtocolError::LengthMismatch)?;
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        output.fill(0);
        output[0..4].copy_from_slice(&MAGIC);
        output[4] = VERSION_MAJOR;
        output[5] = VERSION_MINOR;
        output[6] = EXECUTE_BATCH_HANDLE;
        output[7] = READ_ACCESS;
        put_u16(output, 8, 0);
        put_u16(output, 10, operation.opcode);
        put_u32(output, 12, frame_bytes as u32);
        put_u64(output, 16, self.authority.session);
        put_u64(output, 24, self.authority.generation);
        put_u64(output, 32, nonce);
        put_u64(output, 40, deadline_unix_us);
        put_u32(output, 48, result_budget);
        put_u32(output, 52, row_budget);
        put_u32(output, 56, operation.plan_handle);
        put_u32(output, 60, operation.result_shape);
        put_u32(output, 64, operation_count);
        put_u32(output, 68, BATCH_OPERAND_BYTES as u32);
        put_u32(output, 72, payload_bytes);
        output[96..128].copy_from_slice(&self.authority.context_digest);
        for (index, item) in items.iter().enumerate() {
            let offset = BATCH_HEADER_BYTES + index * BATCH_OPERAND_BYTES;
            put_i64(output, offset, item.first);
            put_i64(output, offset + 8, item.second);
            put_u32(output, offset + 16, item.third);
        }
        let tag_offset = output.len() - TAG_BYTES;
        let tag = self
            .authority
            .tag_for(BATCH_FRAME_DOMAIN, &output[..tag_offset]);
        output[tag_offset..].copy_from_slice(&tag);
        self.next_nonce = next_nonce;
        Ok(())
    }
}

pub trait BatchBackend {
    fn identity(&self) -> BackendIdentity;

    /// Execute all items through one fused engine operation.
    fn execute_batch(
        &mut self,
        operation: BatchOperation,
        items: BatchItems<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError>;
}

/// Execute a trusted typed request for the equal-security benchmark control.
///
/// This trait is not a wire admission surface. The feature exists only for benchmark binaries.
#[cfg(feature = "benchmark-governed-native")]
pub trait GovernedBatchBackend {
    fn identity(&self) -> BackendIdentity;

    fn execute_governed_batch(
        &mut self,
        operation: BatchOperation,
        items: &[BatchItem],
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError>;
}

/// Record one exclusive component interval for the benchmark profiler.
#[cfg(feature = "benchmark-governed-native")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ComponentTiming {
    pub wall_ns: u64,
    pub cpu_ns: u64,
}

#[cfg(feature = "benchmark-governed-native")]
impl ComponentTiming {
    fn checked_add(self, other: Self) -> Result<Self, ProtocolError> {
        Ok(Self {
            wall_ns: self
                .wall_ns
                .checked_add(other.wall_ns)
                .ok_or(ProtocolError::ClockFailed)?,
            cpu_ns: self
                .cpu_ns
                .checked_add(other.cpu_ns)
                .ok_or(ProtocolError::ClockFailed)?,
        })
    }
}

/// Record backend stages without timing the normal execution path.
#[cfg(feature = "benchmark-governed-native")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackendComponentProfile {
    pub registered_plan_dispatch: ComponentTiming,
    pub database_execution: ComponentTiming,
    pub result_encoding: ComponentTiming,
}

/// Execute one profiled backend request for the component campaign.
#[cfg(feature = "benchmark-governed-native")]
pub trait ProfiledBatchBackend {
    fn identity(&self) -> BackendIdentity;

    fn execute_profiled_batch(
        &mut self,
        operation: BatchOperation,
        items: BatchItems<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<BackendComponentProfile, ProtocolError>;
}

/// Hold one typed request for the equal-security benchmark control.
///
/// The request omits the frame and its authentication tag. The receipt still binds every field.
#[cfg(feature = "benchmark-governed-native")]
pub struct GovernedBatchRequest<'a> {
    generation: u64,
    session: u64,
    context_digest: [u8; 32],
    nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    row_budget: u32,
    operation: BatchOperation,
    items: &'a [BatchItem],
}

/// Prepare and verify trusted typed requests for the benchmark control.
#[cfg(feature = "benchmark-governed-native")]
pub struct GovernedBatchClientSession {
    authority: super::Authority,
    next_nonce: u64,
}

#[cfg(feature = "benchmark-governed-native")]
impl GovernedBatchClientSession {
    pub fn new(authority: super::Authority) -> Self {
        Self {
            authority,
            next_nonce: 1,
        }
    }

    pub fn prepare<'a>(
        &mut self,
        operation: BatchOperation,
        items: &'a [BatchItem],
        result_budget: u32,
        row_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<GovernedBatchRequest<'a>, ProtocolError> {
        batch_frame_bytes(items.len())?;
        if result_budget == 0 || row_budget == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let nonce = self.next_nonce;
        self.next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        Ok(GovernedBatchRequest {
            generation: self.authority.generation,
            session: self.authority.session,
            context_digest: self.authority.context_digest,
            nonce,
            deadline_unix_us,
            result_budget,
            row_budget,
            operation,
            items,
        })
    }

    pub fn verify_receipt(
        &self,
        request: &GovernedBatchRequest<'_>,
        rows: u32,
        bytes: &[u8],
        candidate: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        let expected = digest_receipt(
            &self.authority,
            governed_request_digest(request),
            request.nonce,
            rows,
            *blake3::hash(bytes).as_bytes(),
        );
        if expected.ct_eq(candidate).unwrap_u8() != 1 {
            return Err(ProtocolError::ReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BatchExecution {
    pub operation: BatchOperation,
    pub item_count: u32,
    pub bytes: Vec<u8>,
    pub rows: u32,
    pub receipt: [u8; 32],
}

/// Return one execution and its exclusive server component intervals.
#[cfg(feature = "benchmark-governed-native")]
#[derive(Debug)]
pub struct ProfiledBatchExecution {
    pub execution: BatchExecution,
    pub request_authentication_and_decoding: ComponentTiming,
    pub replay_admission: ComponentTiming,
    pub backend: BackendComponentProfile,
    pub server_result_hashing_and_receipt: ComponentTiming,
}

#[cfg(feature = "benchmark-governed-native")]
#[derive(Clone, Copy)]
struct ComponentStamp {
    wall_ns: u64,
    cpu_ns: u64,
}

#[cfg(feature = "benchmark-governed-native")]
impl ComponentStamp {
    fn now() -> Result<Self, ProtocolError> {
        Ok(Self {
            wall_ns: component_clock_ns(libc::CLOCK_MONOTONIC)?,
            cpu_ns: component_clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID)?,
        })
    }

    fn finish(self) -> Result<ComponentTiming, ProtocolError> {
        let end = Self::now()?;
        let wall_ns = end
            .wall_ns
            .checked_sub(self.wall_ns)
            .ok_or(ProtocolError::ClockFailed)?;
        let cpu_ns = end
            .cpu_ns
            .checked_sub(self.cpu_ns)
            .ok_or(ProtocolError::ClockFailed)?;
        Ok(ComponentTiming { wall_ns, cpu_ns })
    }
}

#[cfg(feature = "benchmark-governed-native")]
fn component_clock_ns(clock: libc::clockid_t) -> Result<u64, ProtocolError> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The pointer is valid for one writable timespec.
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return Err(ProtocolError::ClockFailed);
    }
    let seconds = u64::try_from(value.tv_sec).map_err(|_| ProtocolError::ClockFailed)?;
    let nanoseconds = u64::try_from(value.tv_nsec).map_err(|_| ProtocolError::ClockFailed)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanoseconds))
        .ok_or(ProtocolError::ClockFailed)
}

impl ServerSession {
    /// Execute the equal-security benchmark control without a wire frame.
    ///
    /// Compile this method only into the POC benchmark. Do not expose it to an untrusted caller.
    #[cfg(feature = "benchmark-governed-native")]
    pub fn execute_governed_batch<B: GovernedBatchBackend, R: ReplayStore, C: Clock>(
        &self,
        request: &GovernedBatchRequest<'_>,
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<BatchExecution, ProtocolError> {
        let admitted_unix_us = clock.now_unix_us()?;
        if request.generation != self.authority.generation
            || request.session != self.authority.session
            || request.context_digest != self.authority.context_digest
        {
            return Err(ProtocolError::AuthorityMismatch);
        }
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
        if backend.identity() != self.authority.context.backend() {
            return Err(ProtocolError::BackendIdentityMismatch);
        }
        let previous_nonce = replay.last_nonce(self.authority.replay_key())?;
        if request.nonce
            != previous_nonce
                .checked_add(1)
                .ok_or(ProtocolError::NonceEnded)?
        {
            return Err(ProtocolError::Replay);
        }
        let limits = ExecutionLimits {
            admitted_unix_us,
            deadline_unix_us: request.deadline_unix_us,
            maximum_result_bytes: request.result_budget,
            maximum_rows: request.row_budget,
        };
        let mut output =
            BoundedOutput::new_deferred_digesting(request.result_budget, request.row_budget);
        backend.execute_governed_batch(request.operation, request.items, limits, &mut output)?;
        if clock.now_unix_us()? >= request.deadline_unix_us {
            return Err(ProtocolError::ExpiredDuringExecution);
        }
        replay.commit(self.authority.replay_key(), previous_nonce, request.nonce)?;
        let receipt = digest_receipt(
            &self.authority,
            governed_request_digest(request),
            request.nonce,
            output.rows,
            output.exact_result_digest()?,
        );
        Ok(BatchExecution {
            operation: request.operation,
            item_count: request.items.len() as u32,
            bytes: output.bytes,
            rows: output.rows,
            receipt,
        })
    }

    pub fn execute_batch<B: BatchBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<BatchExecution, ProtocolError> {
        self.execute_batch_inner(frame, backend, replay, clock, false)
    }

    /// Profile the real authenticated path without adding timers to the performance arm.
    #[cfg(feature = "benchmark-governed-native")]
    pub fn execute_profiled_batch<B: ProfiledBatchBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<ProfiledBatchExecution, ProtocolError> {
        let admitted_unix_us = clock.now_unix_us()?;
        let decode_started = ComponentStamp::now()?;
        let decoded = self.decode_batch(frame, admitted_unix_us)?;
        let request_authentication_and_decoding = decode_started.finish()?;
        let replay_started = ComponentStamp::now()?;
        let pending = self.admit_batch_replay(decoded, replay)?;
        let mut replay_admission = replay_started.finish()?;
        let dispatch_started = ComponentStamp::now()?;
        if backend.identity() != self.authority.context.backend() {
            return Err(ProtocolError::BackendIdentityMismatch);
        }
        let identity_dispatch = dispatch_started.finish()?;
        let limits = ExecutionLimits {
            admitted_unix_us,
            deadline_unix_us: pending.deadline_unix_us,
            maximum_result_bytes: pending.result_budget,
            maximum_rows: pending.row_budget,
        };
        let mut output =
            BoundedOutput::new_deferred_digesting(pending.result_budget, pending.row_budget);
        let mut backend_profile = backend.execute_profiled_batch(
            pending.operation,
            pending.items,
            limits,
            &mut output,
        )?;
        backend_profile.registered_plan_dispatch = backend_profile
            .registered_plan_dispatch
            .checked_add(identity_dispatch)?;
        if clock.now_unix_us()? >= pending.deadline_unix_us {
            return Err(ProtocolError::ExpiredDuringExecution);
        }
        let replay_commit_started = ComponentStamp::now()?;
        replay.commit(
            self.authority.replay_key(),
            pending.previous_nonce,
            pending.nonce,
        )?;
        replay_admission = replay_admission.checked_add(replay_commit_started.finish()?)?;
        let receipt_started = ComponentStamp::now()?;
        let receipt = digest_receipt(
            &self.authority,
            *blake3::hash(frame).as_bytes(),
            pending.nonce,
            output.rows,
            output.exact_result_digest()?,
        );
        let server_result_hashing_and_receipt = receipt_started.finish()?;
        Ok(ProfiledBatchExecution {
            execution: BatchExecution {
                operation: pending.operation,
                item_count: pending.item_count,
                bytes: output.bytes,
                rows: output.rows,
                receipt,
            },
            request_authentication_and_decoding,
            replay_admission,
            backend: backend_profile,
            server_result_hashing_and_receipt,
        })
    }

    /// Hash the result while the backend writes it.
    ///
    /// This method uses the v0.2 digest receipt and leaves the v0.1 receipt unchanged.
    pub fn execute_batch_incremental_receipt<B: BatchBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<BatchExecution, ProtocolError> {
        self.execute_batch_inner(frame, backend, replay, clock, true)
    }

    fn execute_batch_inner<B: BatchBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
        incremental_receipt: bool,
    ) -> Result<BatchExecution, ProtocolError> {
        let admitted_unix_us = clock.now_unix_us()?;
        let decoded = self.decode_batch(frame, admitted_unix_us)?;
        let pending = self.admit_batch_replay(decoded, replay)?;
        if backend.identity() != self.authority.context.backend() {
            return Err(ProtocolError::BackendIdentityMismatch);
        }
        let limits = ExecutionLimits {
            admitted_unix_us,
            deadline_unix_us: pending.deadline_unix_us,
            maximum_result_bytes: pending.result_budget,
            maximum_rows: pending.row_budget,
        };
        let mut output = if incremental_receipt {
            BoundedOutput::new_deferred_digesting(pending.result_budget, pending.row_budget)
        } else {
            BoundedOutput::new_deferred(pending.result_budget, pending.row_budget)
        };
        backend.execute_batch(pending.operation, pending.items, limits, &mut output)?;
        if clock.now_unix_us()? >= pending.deadline_unix_us {
            return Err(ProtocolError::ExpiredDuringExecution);
        }
        replay.commit(
            self.authority.replay_key(),
            pending.previous_nonce,
            pending.nonce,
        )?;
        let frame_digest = *blake3::hash(frame).as_bytes();
        let execution_receipt = if incremental_receipt {
            digest_receipt(
                &self.authority,
                frame_digest,
                pending.nonce,
                output.rows,
                output.exact_result_digest()?,
            )
        } else {
            receipt(
                &self.authority,
                frame_digest,
                pending.nonce,
                output.rows,
                &output.bytes,
            )
        };
        Ok(BatchExecution {
            operation: pending.operation,
            item_count: pending.item_count,
            bytes: output.bytes,
            rows: output.rows,
            receipt: execution_receipt,
        })
    }

    fn decode_batch<'a>(
        &self,
        frame: &'a [u8],
        now_unix_us: u64,
    ) -> Result<DecodedBatch<'a>, ProtocolError> {
        let maximum_bytes = batch_frame_bytes(MAX_BATCH_OPERATIONS)?;
        if frame.len() < BATCH_BASE_BYTES + 2 * BATCH_OPERAND_BYTES || frame.len() > maximum_bytes {
            return Err(ProtocolError::LengthMismatch);
        }
        let tag_offset = frame.len() - TAG_BYTES;
        let expected_tag = self
            .authority
            .tag_for(BATCH_FRAME_DOMAIN, &frame[..tag_offset]);
        if expected_tag.ct_eq(&frame[tag_offset..]).unwrap_u8() != 1 {
            return Err(ProtocolError::AuthenticationFailed);
        }
        if frame[0..4] != MAGIC
            || frame[4] != VERSION_MAJOR
            || frame[5] != VERSION_MINOR
            || frame[6] != EXECUTE_BATCH_HANDLE
            || frame[7] != READ_ACCESS
        {
            return Err(ProtocolError::UnsupportedFrame);
        }
        if get_u16(frame, 8) != 0
            || get_u32(frame, 12) as usize != frame.len()
            || get_u32(frame, 68) as usize != BATCH_OPERAND_BYTES
            || frame[76..96].iter().any(|byte| *byte != 0)
        {
            return Err(ProtocolError::NonCanonicalFrame);
        }
        if get_u64(frame, 16) != self.authority.session
            || get_u64(frame, 24) != self.authority.generation
            || frame[96..128] != self.authority.context_digest
        {
            return Err(ProtocolError::AuthorityMismatch);
        }
        let item_count = get_u32(frame, 64);
        let expected_bytes = batch_frame_bytes(item_count as usize)?;
        let payload_bytes = item_count
            .checked_mul(BATCH_OPERAND_BYTES as u32)
            .ok_or(ProtocolError::LengthMismatch)?;
        if expected_bytes != frame.len() || get_u32(frame, 72) != payload_bytes {
            return Err(ProtocolError::NonCanonicalFrame);
        }
        let nonce = get_u64(frame, 32);
        let deadline_unix_us = get_u64(frame, 40);
        let result_budget = get_u32(frame, 48);
        let row_budget = get_u32(frame, 52);
        if deadline_unix_us <= now_unix_us || deadline_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::Expired);
        }
        if result_budget == 0
            || result_budget > self.maximum_result_bytes
            || row_budget == 0
            || row_budget > self.maximum_rows
        {
            return Err(ProtocolError::BudgetExceeded);
        }
        let operation =
            BatchOperation::new(get_u16(frame, 10), get_u32(frame, 56), get_u32(frame, 60))?;
        Ok(DecodedBatch {
            nonce,
            deadline_unix_us,
            result_budget,
            row_budget,
            operation,
            item_count,
            items: BatchItems {
                bytes: &frame[BATCH_HEADER_BYTES..tag_offset],
                index: 0,
            },
        })
    }

    fn admit_batch_replay<'a, R: ReplayStore>(
        &self,
        decoded: DecodedBatch<'a>,
        replay: &R,
    ) -> Result<PendingBatch<'a>, ProtocolError> {
        let previous_nonce = replay.last_nonce(self.authority.replay_key())?;
        if decoded.nonce
            != previous_nonce
                .checked_add(1)
                .ok_or(ProtocolError::NonceEnded)?
        {
            return Err(ProtocolError::Replay);
        }
        Ok(PendingBatch {
            nonce: decoded.nonce,
            previous_nonce,
            deadline_unix_us: decoded.deadline_unix_us,
            result_budget: decoded.result_budget,
            row_budget: decoded.row_budget,
            operation: decoded.operation,
            item_count: decoded.item_count,
            items: decoded.items,
        })
    }
}

#[cfg(feature = "benchmark-governed-native")]
fn governed_request_digest(request: &GovernedBatchRequest<'_>) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(GOVERNED_NATIVE_DOMAIN);
    digest.update(&request.generation.to_le_bytes());
    digest.update(&request.session.to_le_bytes());
    digest.update(&request.context_digest);
    digest.update(&request.nonce.to_le_bytes());
    digest.update(&request.deadline_unix_us.to_le_bytes());
    digest.update(&request.result_budget.to_le_bytes());
    digest.update(&request.row_budget.to_le_bytes());
    digest.update(&request.operation.opcode.to_le_bytes());
    digest.update(&request.operation.plan_handle.to_le_bytes());
    digest.update(&request.operation.result_shape.to_le_bytes());
    digest.update(&(request.items.len() as u32).to_le_bytes());
    for item in request.items {
        digest.update(&item.first.to_le_bytes());
        digest.update(&item.second.to_le_bytes());
        digest.update(&item.third.to_le_bytes());
    }
    *digest.finalize().as_bytes()
}

struct DecodedBatch<'a> {
    nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    row_budget: u32,
    operation: BatchOperation,
    item_count: u32,
    items: BatchItems<'a>,
}

struct PendingBatch<'a> {
    nonce: u64,
    previous_nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    row_budget: u32,
    operation: BatchOperation,
    item_count: u32,
    items: BatchItems<'a>,
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::{digest_label, Authority, AuthorityContext, MemoryReplayStore};

    const NOW: u64 = 1_000_000;
    const DEADLINE: u64 = 2_000_000;

    fn identity(profile: u32) -> BackendIdentity {
        BackendIdentity::new(
            profile + 100,
            profile,
            digest_label(b"schema", &[1]),
            digest_label(b"policy", &[2]),
            digest_label(b"plan", &[3]),
        )
        .expect("identity")
    }

    fn authority(profile: u32) -> Authority {
        let context = AuthorityContext::new([4; 16], [5; 16], 6, [7; 32], identity(profile))
            .expect("context");
        Authority::new_read([8; 32], 9, 10, DEADLINE, context).expect("authority")
    }

    fn operation() -> BatchOperation {
        BatchOperation::new(11, 12, 13).expect("operation")
    }

    fn items() -> [BatchItem; 3] {
        [
            BatchItem::new(14, 15, 16),
            BatchItem::new(17, 18, 19),
            BatchItem::new(20, 21, 22),
        ]
    }

    fn frame() -> Vec<u8> {
        let items = items();
        let mut frame = vec![0; batch_frame_bytes(items.len()).expect("frame bytes")];
        ClientSession::new(authority(20))
            .encode_batch_into(operation(), &items, 64, 4, DEADLINE, &mut frame)
            .expect("frame");
        frame
    }

    struct TestClock {
        calls: Cell<u32>,
    }

    impl Clock for TestClock {
        fn now_unix_us(&self) -> Result<u64, ProtocolError> {
            self.calls.set(self.calls.get() + 1);
            Ok(NOW)
        }
    }

    struct TestBackend {
        identity: BackendIdentity,
        calls: u32,
        received: Vec<BatchItem>,
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
            self.calls += 1;
            self.received.extend(items);
            output.write(&[1, 2, 3])?;
            output.complete_row()
        }
    }

    #[cfg(feature = "benchmark-governed-native")]
    impl GovernedBatchBackend for TestBackend {
        fn identity(&self) -> BackendIdentity {
            self.identity
        }

        fn execute_governed_batch(
            &mut self,
            _operation: BatchOperation,
            items: &[BatchItem],
            _limits: ExecutionLimits,
            output: &mut BoundedOutput,
        ) -> Result<(), ProtocolError> {
            self.calls += 1;
            self.received.extend_from_slice(items);
            output.write(&[1, 2, 3])?;
            output.complete_row()
        }
    }

    #[cfg(feature = "benchmark-governed-native")]
    impl ProfiledBatchBackend for TestBackend {
        fn identity(&self) -> BackendIdentity {
            self.identity
        }

        fn execute_profiled_batch(
            &mut self,
            _operation: BatchOperation,
            items: BatchItems<'_>,
            _limits: ExecutionLimits,
            output: &mut BoundedOutput,
        ) -> Result<BackendComponentProfile, ProtocolError> {
            self.calls += 1;
            self.received.extend(items);
            output.write(&[1, 2, 3])?;
            output.complete_row()?;
            Ok(BackendComponentProfile {
                registered_plan_dispatch: ComponentTiming {
                    wall_ns: 1,
                    cpu_ns: 1,
                },
                database_execution: ComponentTiming {
                    wall_ns: 2,
                    cpu_ns: 2,
                },
                result_encoding: ComponentTiming {
                    wall_ns: 3,
                    cpu_ns: 3,
                },
            })
        }
    }

    fn backend() -> TestBackend {
        TestBackend {
            identity: identity(20),
            calls: 0,
            received: Vec::new(),
        }
    }

    fn clock() -> TestClock {
        TestClock {
            calls: Cell::new(0),
        }
    }

    #[test]
    fn one_batch_frame_dispatches_once_and_decodes_borrowed_items() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let client = ClientSession::new(authority(20));
        let frame = frame();
        let mut backend = backend();
        let execution = server
            .execute_batch(
                &frame,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &clock(),
            )
            .expect("batch execution");
        assert_eq!(backend.calls, 1);
        assert_eq!(backend.received, items());
        assert_eq!(execution.operation, operation());
        assert_eq!(execution.item_count, 3);
        assert_eq!(execution.bytes, [1, 2, 3]);
        assert_eq!(execution.rows, 1);
        assert!(execution.receipt.iter().any(|byte| *byte != 0));
        client
            .verify_execution_receipt(&frame, execution.rows, &execution.bytes, &execution.receipt)
            .expect("valid receipt");
        assert_eq!(
            client
                .verify_execution_receipt(&frame, execution.rows, &execution.bytes, &[9; 32])
                .unwrap_err(),
            ProtocolError::ReceiptMismatch
        );
    }

    #[test]
    fn the_incremental_receipt_binds_every_result_byte_without_a_server_rehash() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let client = ClientSession::new(authority(20));
        let frame = frame();
        let execution = server
            .execute_batch_incremental_receipt(
                &frame,
                &mut backend(),
                &mut MemoryReplayStore::default(),
                &clock(),
            )
            .expect("incremental execution");

        client
            .verify_digest_execution_receipt(
                &frame,
                execution.rows,
                &execution.bytes,
                &execution.receipt,
            )
            .expect("incremental receipt");
        assert_eq!(
            client
                .verify_execution_receipt(
                    &frame,
                    execution.rows,
                    &execution.bytes,
                    &execution.receipt,
                )
                .unwrap_err(),
            ProtocolError::ReceiptMismatch
        );

        let mut changed = execution.bytes.clone();
        changed[1] ^= 1;
        assert_eq!(
            client
                .verify_digest_execution_receipt(
                    &frame,
                    execution.rows,
                    &changed,
                    &execution.receipt,
                )
                .unwrap_err(),
            ProtocolError::ReceiptMismatch
        );
    }

    #[cfg(feature = "benchmark-governed-native")]
    #[test]
    fn the_governed_control_preserves_security_and_exact_results() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let mut client = GovernedBatchClientSession::new(authority(20));
        let items = items();
        let request = client
            .prepare(operation(), &items, 64, 4, DEADLINE)
            .expect("request");
        let mut backend = backend();
        let mut replay = MemoryReplayStore::default();
        let execution = server
            .execute_governed_batch(&request, &mut backend, &mut replay, &clock())
            .expect("governed execution");

        assert_eq!(execution.bytes, [1, 2, 3]);
        assert_eq!(execution.rows, 1);
        client
            .verify_receipt(
                &request,
                execution.rows,
                &execution.bytes,
                &execution.receipt,
            )
            .expect("receipt");
        assert_eq!(
            server
                .execute_governed_batch(&request, &mut backend, &mut replay, &clock())
                .unwrap_err(),
            ProtocolError::Replay
        );
        assert_eq!(backend.calls, 1);
    }

    #[cfg(feature = "benchmark-governed-native")]
    #[test]
    fn the_governed_receipt_binds_each_typed_operand() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let original = items();
        let mut client = GovernedBatchClientSession::new(authority(20));
        let request = client
            .prepare(operation(), &original, 64, 4, DEADLINE)
            .expect("request");
        let execution = server
            .execute_governed_batch(
                &request,
                &mut backend(),
                &mut MemoryReplayStore::default(),
                &clock(),
            )
            .expect("governed execution");
        let mut changed = items();
        changed[1].first += 1;
        let mut changed_client = GovernedBatchClientSession::new(authority(20));
        let changed_request = changed_client
            .prepare(operation(), &changed, 64, 4, DEADLINE)
            .expect("changed request");

        assert_eq!(
            changed_client
                .verify_receipt(
                    &changed_request,
                    execution.rows,
                    &execution.bytes,
                    &execution.receipt,
                )
                .unwrap_err(),
            ProtocolError::ReceiptMismatch
        );
    }

    #[cfg(feature = "benchmark-governed-native")]
    #[test]
    fn the_governed_control_refuses_authority_deadline_budget_and_backend_drift() {
        struct FixedClock(u64);

        impl Clock for FixedClock {
            fn now_unix_us(&self) -> Result<u64, ProtocolError> {
                Ok(self.0)
            }
        }

        let items = items();
        let mut client = GovernedBatchClientSession::new(authority(20));
        let request = client
            .prepare(operation(), &items, 64, 4, DEADLINE)
            .expect("request");

        let mut changed_backend = backend();
        changed_backend.identity = identity(21);
        assert_eq!(
            ServerSession::new(authority(20), 128, 4)
                .expect("server")
                .execute_governed_batch(
                    &request,
                    &mut changed_backend,
                    &mut MemoryReplayStore::default(),
                    &clock(),
                )
                .unwrap_err(),
            ProtocolError::BackendIdentityMismatch
        );
        assert_eq!(changed_backend.calls, 0);

        let mut exact_backend = backend();
        assert_eq!(
            ServerSession::new(authority(20), 32, 4)
                .expect("server")
                .execute_governed_batch(
                    &request,
                    &mut exact_backend,
                    &mut MemoryReplayStore::default(),
                    &clock(),
                )
                .unwrap_err(),
            ProtocolError::BudgetExceeded
        );
        assert_eq!(exact_backend.calls, 0);

        assert_eq!(
            ServerSession::new(authority(20), 128, 4)
                .expect("server")
                .execute_governed_batch(
                    &request,
                    &mut exact_backend,
                    &mut MemoryReplayStore::default(),
                    &FixedClock(DEADLINE),
                )
                .unwrap_err(),
            ProtocolError::Expired
        );
        assert_eq!(exact_backend.calls, 0);

        let mut other_backend = backend();
        other_backend.identity = identity(21);
        assert_eq!(
            ServerSession::new(authority(21), 128, 4)
                .expect("server")
                .execute_governed_batch(
                    &request,
                    &mut other_backend,
                    &mut MemoryReplayStore::default(),
                    &clock(),
                )
                .unwrap_err(),
            ProtocolError::AuthorityMismatch
        );
        assert_eq!(other_backend.calls, 0);
    }

    #[cfg(feature = "benchmark-governed-native")]
    #[test]
    fn the_profiled_path_preserves_execution_and_receipt_semantics() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let client = ClientSession::new(authority(20));
        let frame = frame();
        let profiled = server
            .execute_profiled_batch(
                &frame,
                &mut backend(),
                &mut MemoryReplayStore::default(),
                &clock(),
            )
            .expect("profiled execution");

        assert_eq!(profiled.execution.bytes, [1, 2, 3]);
        assert_eq!(profiled.execution.rows, 1);
        assert!(profiled.request_authentication_and_decoding.wall_ns > 0);
        assert!(profiled.replay_admission.wall_ns > 0);
        assert!(profiled.backend.registered_plan_dispatch.wall_ns >= 1);
        assert_eq!(profiled.backend.database_execution.wall_ns, 2);
        assert_eq!(profiled.backend.result_encoding.wall_ns, 3);
        assert!(profiled.server_result_hashing_and_receipt.wall_ns > 0);
        client
            .verify_digest_execution_receipt(
                &frame,
                profiled.execution.rows,
                &profiled.execution.bytes,
                &profiled.execution.receipt,
            )
            .expect("profiled receipt");
    }

    #[test]
    fn every_batch_frame_bit_is_authenticated() {
        let original = frame();
        for bit in 0..original.len() * 8 {
            let mut changed = original.clone();
            changed[bit / 8] ^= 1 << (bit % 8);
            let result = ServerSession::new(authority(20), 128, 4)
                .expect("server")
                .execute_batch(
                    &changed,
                    &mut backend(),
                    &mut MemoryReplayStore::default(),
                    &clock(),
                );
            assert!(result.is_err(), "accepted bit {bit}");
        }
    }

    #[test]
    fn a_batch_replay_and_a_changed_backend_refuse_before_dispatch() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let frame = frame();
        let mut replay = MemoryReplayStore::default();
        server
            .execute_batch(&frame, &mut backend(), &mut replay, &clock())
            .expect("first execution");
        let mut replay_backend = backend();
        assert_eq!(
            server
                .execute_batch(&frame, &mut replay_backend, &mut replay, &clock())
                .unwrap_err(),
            ProtocolError::Replay
        );
        assert_eq!(replay_backend.calls, 0);
        let mut changed_backend = backend();
        changed_backend.identity = identity(21);
        assert_eq!(
            server
                .execute_batch(
                    &frame,
                    &mut changed_backend,
                    &mut MemoryReplayStore::default(),
                    &clock(),
                )
                .unwrap_err(),
            ProtocolError::BackendIdentityMismatch
        );
        assert_eq!(changed_backend.calls, 0);
    }

    #[test]
    fn batch_encoding_refuses_invalid_sizes_without_consuming_a_nonce() {
        assert_eq!(
            batch_frame_bytes(0).unwrap_err(),
            ProtocolError::BatchTooSmall
        );
        assert_eq!(
            batch_frame_bytes(1).unwrap_err(),
            ProtocolError::BatchTooSmall
        );
        assert_eq!(
            batch_frame_bytes(MAX_BATCH_OPERATIONS + 1).unwrap_err(),
            ProtocolError::BatchLimitExceeded
        );
        let mut client = ClientSession::new(authority(20));
        let mut wrong = [0_u8; 16];
        assert_eq!(
            client
                .encode_batch_into(operation(), &items(), 64, 4, DEADLINE, &mut wrong)
                .unwrap_err(),
            ProtocolError::LengthMismatch
        );
        let mut valid = vec![0; batch_frame_bytes(3).expect("frame bytes")];
        client
            .encode_batch_into(operation(), &items(), 64, 4, DEADLINE, &mut valid)
            .expect("valid frame");
        assert_eq!(get_u64(&valid, 32), 1);
    }
}
