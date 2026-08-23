//! Define one canonical homogeneous batch frame.
//!
//! The frame carries many operand tuples for one registered plan.
//! A backend must execute one fused engine operation or refuse the frame.

use std::fmt;

use subtle::ConstantTimeEq;

use super::{
    get_i64, get_u16, get_u32, get_u64, put_i64, put_u16, put_u32, put_u64, receipt,
    BackendIdentity, BoundedOutput, ClientSession, Clock, ExecutionLimits, ProtocolError,
    ReplayStore, ServerSession, AUTHENTICATED_BYTES, BATCH_FRAME_DOMAIN, MAGIC, READ_ACCESS,
    TAG_BYTES, VERSION_MAJOR, VERSION_MINOR,
};

const EXECUTE_BATCH_HANDLE: u8 = 2;
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

#[derive(Debug)]
pub struct BatchExecution {
    pub operation: BatchOperation,
    pub item_count: u32,
    pub bytes: Vec<u8>,
    pub rows: u32,
    pub receipt: [u8; 32],
}

impl ServerSession {
    pub fn execute_batch<B: BatchBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<BatchExecution, ProtocolError> {
        let admitted_unix_us = clock.now_unix_us()?;
        let pending = self.verify_batch(frame, admitted_unix_us, replay)?;
        if backend.identity() != self.authority.context.backend() {
            return Err(ProtocolError::BackendIdentityMismatch);
        }
        let limits = ExecutionLimits {
            admitted_unix_us,
            deadline_unix_us: pending.deadline_unix_us,
            maximum_result_bytes: pending.result_budget,
            maximum_rows: pending.row_budget,
        };
        let mut output = BoundedOutput::new(pending.result_budget, pending.row_budget);
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
        let execution_receipt = receipt(
            &self.authority,
            frame_digest,
            pending.nonce,
            output.rows,
            &output.bytes,
        );
        Ok(BatchExecution {
            operation: pending.operation,
            item_count: pending.item_count,
            bytes: output.bytes,
            rows: output.rows,
            receipt: execution_receipt,
        })
    }

    fn verify_batch<'a, R: ReplayStore>(
        &self,
        frame: &'a [u8],
        now_unix_us: u64,
        replay: &R,
    ) -> Result<PendingBatch<'a>, ProtocolError> {
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
        let previous_nonce = replay.last_nonce(self.authority.replay_key())?;
        if nonce
            != previous_nonce
                .checked_add(1)
                .ok_or(ProtocolError::NonceEnded)?
        {
            return Err(ProtocolError::Replay);
        }
        let operation =
            BatchOperation::new(get_u16(frame, 10), get_u32(frame, 56), get_u32(frame, 60))?;
        Ok(PendingBatch {
            nonce,
            previous_nonce,
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
        let mut backend = backend();
        let execution = server
            .execute_batch(
                &frame(),
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
