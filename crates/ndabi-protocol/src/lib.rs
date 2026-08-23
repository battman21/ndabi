//! Define the canonical NDABI execute-handle frame.
//!
//! The decoder authenticates a complete fixed frame before it interprets operands.
//! The authority binds the frame to an engine, profile, plan, policy, schema, tenant, principal, and purpose.
//! This protocol version permits reads only. A separate protocol must admit writes.

use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

mod batch;
mod replay;

pub use batch::{
    batch_frame_bytes, BatchBackend, BatchExecution, BatchItem, BatchItems, BatchOperation,
    BATCH_OPERAND_BYTES, MAX_BATCH_OPERATIONS,
};
pub use replay::FileReplayStore;

pub const FRAME_BYTES: usize = 160;
const AUTHENTICATED_BYTES: usize = 128;
const TAG_BYTES: usize = 32;
const MAGIC: [u8; 4] = *b"NDBI";
const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 0;
const EXECUTE_HANDLE: u8 = 1;
const READ_ACCESS: u8 = 1;
const FRAME_DOMAIN: &[u8] = b"ndabi/wire/v1/frame";
const BATCH_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v1/batch-frame";
const CONTEXT_DOMAIN: &[u8] = b"ndabi/wire/v1/context";
const KEY_DOMAIN: &[u8] = b"ndabi/wire/v1/session-key";
const RECEIPT_KEY_DOMAIN: &[u8] = b"ndabi/wire/v1/receipt-key";
const RECEIPT_DOMAIN: &[u8] = b"ndabi/wire/v1/receipt";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BackendIdentity {
    engine: u32,
    profile: u32,
    schema_digest: [u8; 32],
    policy_digest: [u8; 32],
    plan_digest: [u8; 32],
}

impl BackendIdentity {
    pub fn new(
        engine: u32,
        profile: u32,
        schema_digest: [u8; 32],
        policy_digest: [u8; 32],
        plan_digest: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        if engine == 0 || profile == 0 {
            return Err(ProtocolError::ZeroIdentity);
        }
        if is_zero(&schema_digest) || is_zero(&policy_digest) || is_zero(&plan_digest) {
            return Err(ProtocolError::ZeroDigest);
        }
        Ok(Self {
            engine,
            profile,
            schema_digest,
            policy_digest,
            plan_digest,
        })
    }

    pub fn engine(self) -> u32 {
        self.engine
    }

    pub fn profile(self) -> u32 {
        self.profile
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityContext {
    tenant: [u8; 16],
    principal: [u8; 16],
    purpose: u32,
    capability_digest: [u8; 32],
    backend: BackendIdentity,
}

impl AuthorityContext {
    pub fn new(
        tenant: [u8; 16],
        principal: [u8; 16],
        purpose: u32,
        capability_digest: [u8; 32],
        backend: BackendIdentity,
    ) -> Result<Self, ProtocolError> {
        if is_zero(&tenant) || is_zero(&principal) || purpose == 0 {
            return Err(ProtocolError::ZeroIdentity);
        }
        if is_zero(&capability_digest) {
            return Err(ProtocolError::ZeroDigest);
        }
        Ok(Self {
            tenant,
            principal,
            purpose,
            capability_digest,
            backend,
        })
    }

    pub fn backend(self) -> BackendIdentity {
        self.backend
    }

    pub fn digest(self) -> [u8; 32] {
        let mut digest = blake3::Hasher::new();
        digest.update(CONTEXT_DOMAIN);
        digest.update(&self.tenant);
        digest.update(&self.principal);
        digest.update(&self.purpose.to_le_bytes());
        digest.update(&self.capability_digest);
        digest.update(&self.backend.engine.to_le_bytes());
        digest.update(&self.backend.profile.to_le_bytes());
        digest.update(&self.backend.schema_digest);
        digest.update(&self.backend.policy_digest);
        digest.update(&self.backend.plan_digest);
        *digest.finalize().as_bytes()
    }
}

#[derive(Clone)]
pub struct Authority {
    generation: u64,
    session: u64,
    expires_unix_us: u64,
    context: AuthorityContext,
    context_digest: [u8; 32],
    frame_key: Zeroizing<[u8; 32]>,
    receipt_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for Authority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authority")
            .field("generation", &self.generation)
            .field("session", &self.session)
            .field("expires_unix_us", &self.expires_unix_us)
            .field("context", &self.context)
            .field("context_digest", &self.context_digest)
            .field("frame_key", &"[REDACTED]")
            .field("receipt_key", &"[REDACTED]")
            .finish()
    }
}

impl Authority {
    pub fn new_read(
        root_key: [u8; 32],
        generation: u64,
        session: u64,
        expires_unix_us: u64,
        context: AuthorityContext,
    ) -> Result<Self, ProtocolError> {
        if is_zero(&root_key) {
            return Err(ProtocolError::ZeroKey);
        }
        let root_key = Zeroizing::new(root_key);
        if generation == 0 || session == 0 || expires_unix_us == 0 {
            return Err(ProtocolError::ZeroIdentity);
        }
        let context_digest = context.digest();
        let frame_key = derive_key(
            &root_key,
            KEY_DOMAIN,
            generation,
            session,
            expires_unix_us,
            &context_digest,
        );
        let receipt_key = derive_key(
            &root_key,
            RECEIPT_KEY_DOMAIN,
            generation,
            session,
            expires_unix_us,
            &context_digest,
        );
        Ok(Self {
            generation,
            session,
            expires_unix_us,
            context,
            context_digest,
            frame_key: Zeroizing::new(frame_key),
            receipt_key: Zeroizing::new(receipt_key),
        })
    }

    pub fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    fn replay_key(&self) -> ReplayKey {
        ReplayKey {
            context_digest: self.context_digest,
            session: self.session,
            generation: self.generation,
        }
    }

    fn tag(&self, authenticated: &[u8]) -> [u8; TAG_BYTES] {
        self.tag_for(FRAME_DOMAIN, authenticated)
    }

    fn tag_for(&self, domain: &[u8], authenticated: &[u8]) -> [u8; TAG_BYTES] {
        let mut digest = blake3::Hasher::new_keyed(&self.frame_key);
        digest.update(domain);
        digest.update(authenticated);
        let tag = *digest.finalize().as_bytes();
        digest.zeroize();
        tag
    }
}

fn derive_key(
    root_key: &[u8; 32],
    domain: &[u8],
    generation: u64,
    session: u64,
    expires_unix_us: u64,
    context_digest: &[u8; 32],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_keyed(root_key);
    digest.update(domain);
    digest.update(&generation.to_le_bytes());
    digest.update(&session.to_le_bytes());
    digest.update(&expires_unix_us.to_le_bytes());
    digest.update(context_digest);
    let key = *digest.finalize().as_bytes();
    digest.zeroize();
    key
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    pub opcode: u16,
    pub plan_handle: u32,
    pub result_shape: u32,
    pub first: i64,
    pub second: i64,
    pub third: u32,
}

impl Operation {
    pub fn new(
        opcode: u16,
        plan_handle: u32,
        result_shape: u32,
        first: i64,
        second: i64,
        third: u32,
    ) -> Result<Self, ProtocolError> {
        if opcode == 0 || plan_handle == 0 || result_shape == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        Ok(Self {
            opcode,
            plan_handle,
            result_shape,
            first,
            second,
            third,
        })
    }
}

pub struct ClientSession {
    authority: Authority,
    next_nonce: u64,
}

impl ClientSession {
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            next_nonce: 1,
        }
    }

    pub fn resume(authority: Authority, last_accepted_nonce: u64) -> Result<Self, ProtocolError> {
        let next_nonce = last_accepted_nonce
            .checked_add(1)
            .ok_or(ProtocolError::NonceEnded)?;
        Ok(Self {
            authority,
            next_nonce,
        })
    }

    pub fn encode(
        &mut self,
        operation: Operation,
        result_budget: u32,
        row_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<[u8; FRAME_BYTES], ProtocolError> {
        if result_budget == 0 || row_budget == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        let mut frame = [0_u8; FRAME_BYTES];
        frame[0..4].copy_from_slice(&MAGIC);
        frame[4] = VERSION_MAJOR;
        frame[5] = VERSION_MINOR;
        frame[6] = EXECUTE_HANDLE;
        frame[7] = READ_ACCESS;
        put_u16(&mut frame, 8, 0);
        put_u16(&mut frame, 10, operation.opcode);
        put_u32(&mut frame, 12, FRAME_BYTES as u32);
        put_u64(&mut frame, 16, self.authority.session);
        put_u64(&mut frame, 24, self.authority.generation);
        put_u64(&mut frame, 32, nonce);
        put_u64(&mut frame, 40, deadline_unix_us);
        put_u32(&mut frame, 48, result_budget);
        put_u32(&mut frame, 52, row_budget);
        put_u32(&mut frame, 56, operation.plan_handle);
        put_u32(&mut frame, 60, operation.result_shape);
        put_i64(&mut frame, 64, operation.first);
        put_i64(&mut frame, 72, operation.second);
        put_u32(&mut frame, 80, operation.third);
        frame[96..128].copy_from_slice(&self.authority.context_digest);
        let tag = self.authority.tag(&frame[..AUTHENTICATED_BYTES]);
        frame[AUTHENTICATED_BYTES..].copy_from_slice(&tag);
        self.next_nonce = next_nonce;
        Ok(frame)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReplayKey {
    pub(crate) context_digest: [u8; 32],
    pub(crate) session: u64,
    pub(crate) generation: u64,
}

pub trait ReplayStore {
    fn last_nonce(&self, key: ReplayKey) -> Result<u64, ProtocolError>;

    fn commit(
        &mut self,
        key: ReplayKey,
        expected_last: u64,
        accepted: u64,
    ) -> Result<(), ProtocolError>;
}

#[derive(Default)]
pub struct MemoryReplayStore {
    nonces: HashMap<ReplayKey, u64>,
}

impl ReplayStore for MemoryReplayStore {
    fn last_nonce(&self, key: ReplayKey) -> Result<u64, ProtocolError> {
        Ok(self.nonces.get(&key).copied().unwrap_or(0))
    }

    fn commit(
        &mut self,
        key: ReplayKey,
        expected_last: u64,
        accepted: u64,
    ) -> Result<(), ProtocolError> {
        if self.last_nonce(key)? != expected_last || accepted != expected_last.saturating_add(1) {
            return Err(ProtocolError::ReplayConflict);
        }
        self.nonces.insert(key, accepted);
        Ok(())
    }
}

pub trait Clock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_us(&self) -> Result<u64, ProtocolError> {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProtocolError::ClockFailed)?
            .as_micros();
        u64::try_from(micros).map_err(|_| ProtocolError::ClockFailed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLimits {
    pub admitted_unix_us: u64,
    pub deadline_unix_us: u64,
    pub maximum_result_bytes: u32,
    pub maximum_rows: u32,
}

pub trait Backend {
    fn identity(&self) -> BackendIdentity;

    fn execute(
        &mut self,
        operation: Operation,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError>;
}

pub struct BoundedOutput {
    bytes: Vec<u8>,
    maximum_bytes: usize,
    maximum_rows: u32,
    rows: u32,
}

impl BoundedOutput {
    fn new(maximum_bytes: u32, maximum_rows: u32) -> Self {
        Self {
            bytes: Vec::with_capacity((maximum_bytes as usize).min(4_096)),
            maximum_bytes: maximum_bytes as usize,
            maximum_rows,
            rows: 0,
        }
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        if next > self.maximum_bytes {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub fn complete_row(&mut self) -> Result<(), ProtocolError> {
        let rows = self
            .rows
            .checked_add(1)
            .ok_or(ProtocolError::RowBudgetExceeded)?;
        if rows > self.maximum_rows {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        self.rows = rows;
        Ok(())
    }

    pub fn patch_u32(&mut self, offset: usize, value: u32) -> Result<(), ProtocolError> {
        let end = offset.checked_add(4).ok_or(ProtocolError::OutputShape)?;
        let target = self
            .bytes
            .get_mut(offset..end)
            .ok_or(ProtocolError::OutputShape)?;
        target.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub fn rows(&self) -> u32 {
        self.rows
    }
}

pub struct ServerSession {
    authority: Authority,
    maximum_result_bytes: u32,
    maximum_rows: u32,
}

impl ServerSession {
    pub fn new(
        authority: Authority,
        maximum_result_bytes: u32,
        maximum_rows: u32,
    ) -> Result<Self, ProtocolError> {
        if maximum_result_bytes == 0 || maximum_rows == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        Ok(Self {
            authority,
            maximum_result_bytes,
            maximum_rows,
        })
    }

    pub fn execute<B: Backend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<Execution, ProtocolError> {
        let admitted_unix_us = clock.now_unix_us()?;
        let pending = self.verify(frame, admitted_unix_us, replay)?;
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
        backend.execute(pending.operation, limits, &mut output)?;
        if clock.now_unix_us()? >= pending.deadline_unix_us {
            return Err(ProtocolError::ExpiredDuringExecution);
        }
        replay.commit(
            self.authority.replay_key(),
            pending.previous_nonce,
            pending.nonce,
        )?;
        let frame_digest = *blake3::hash(frame).as_bytes();
        let receipt = receipt(
            &self.authority,
            frame_digest,
            pending.nonce,
            output.rows,
            &output.bytes,
        );
        Ok(Execution {
            operation: pending.operation,
            bytes: output.bytes,
            rows: output.rows,
            receipt,
        })
    }

    fn verify<R: ReplayStore>(
        &self,
        frame: &[u8],
        now_unix_us: u64,
        replay: &R,
    ) -> Result<Pending, ProtocolError> {
        if frame.len() != FRAME_BYTES {
            return Err(ProtocolError::LengthMismatch);
        }
        let expected_tag = self.authority.tag(&frame[..AUTHENTICATED_BYTES]);
        if expected_tag
            .ct_eq(&frame[AUTHENTICATED_BYTES..])
            .unwrap_u8()
            != 1
        {
            return Err(ProtocolError::AuthenticationFailed);
        }
        if frame[0..4] != MAGIC
            || frame[4] != VERSION_MAJOR
            || frame[5] != VERSION_MINOR
            || frame[6] != EXECUTE_HANDLE
            || frame[7] != READ_ACCESS
        {
            return Err(ProtocolError::UnsupportedFrame);
        }
        if get_u16(frame, 8) != 0
            || get_u32(frame, 12) != FRAME_BYTES as u32
            || frame[84..96].iter().any(|byte| *byte != 0)
        {
            return Err(ProtocolError::NonCanonicalFrame);
        }
        if get_u64(frame, 16) != self.authority.session
            || get_u64(frame, 24) != self.authority.generation
            || frame[96..128] != self.authority.context_digest
        {
            return Err(ProtocolError::AuthorityMismatch);
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
        let operation = Operation::new(
            get_u16(frame, 10),
            get_u32(frame, 56),
            get_u32(frame, 60),
            get_i64(frame, 64),
            get_i64(frame, 72),
            get_u32(frame, 80),
        )?;
        Ok(Pending {
            nonce,
            previous_nonce,
            deadline_unix_us,
            result_budget,
            row_budget,
            operation,
        })
    }
}

struct Pending {
    nonce: u64,
    previous_nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    row_budget: u32,
    operation: Operation,
}

#[derive(Debug)]
pub struct Execution {
    pub operation: Operation,
    pub bytes: Vec<u8>,
    pub rows: u32,
    pub receipt: [u8; 32],
}

fn receipt(
    authority: &Authority,
    frame_digest: [u8; 32],
    nonce: u64,
    rows: u32,
    bytes: &[u8],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_keyed(&authority.receipt_key);
    digest.update(RECEIPT_DOMAIN);
    digest.update(&authority.context_digest);
    digest.update(&frame_digest);
    digest.update(&nonce.to_le_bytes());
    digest.update(&rows.to_le_bytes());
    digest.update(bytes);
    let receipt = *digest.finalize().as_bytes();
    digest.zeroize();
    receipt
}

pub fn digest_label(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(domain);
    digest.update(value);
    *digest.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    AuthenticationFailed,
    AuthorityMismatch,
    BackendIdentityMismatch,
    BackendRefused,
    BatchLimitExceeded,
    BatchTooSmall,
    BudgetExceeded,
    ClockFailed,
    DeadlineBeyondAuthority,
    Expired,
    ExpiredDuringExecution,
    LengthMismatch,
    NonCanonicalFrame,
    NonceEnded,
    OutputShape,
    Replay,
    ReplayConflict,
    ReplayStoreAuthenticationFailed,
    ReplayStoreInsecure,
    ReplayStoreIo,
    ReplayStoreLockUnavailable,
    ResultBudgetExceeded,
    RowBudgetExceeded,
    UnsupportedFrame,
    ZeroBudget,
    ZeroDigest,
    ZeroIdentity,
    ZeroKey,
    ZeroOperationField,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProtocolError {}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0_u8, |state, byte| state | byte) == 0
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("fixed frame"))
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed frame"))
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed frame"))
}

fn get_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed frame"))
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

fn put_i64(bytes: &mut [u8], offset: usize, value: i64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const NOW: u64 = 1_000_000;
    const DEADLINE: u64 = 2_000_000;

    fn identity(profile: u32) -> BackendIdentity {
        BackendIdentity::new(profile + 10, profile, [1; 32], [2; 32], [3; 32]).expect("identity")
    }

    fn authority(profile: u32) -> Authority {
        let context = AuthorityContext::new([4; 16], [5; 16], 6, [7; 32], identity(profile))
            .expect("context");
        Authority::new_read([8; 32], 9, 10, DEADLINE, context).expect("authority")
    }

    fn operation() -> Operation {
        Operation::new(11, 12, 13, 14, 15, 16).expect("operation")
    }

    fn frame() -> [u8; FRAME_BYTES] {
        ClientSession::new(authority(20))
            .encode(operation(), 64, 2, DEADLINE)
            .expect("frame")
    }

    struct TestClock {
        first: u64,
        second: u64,
        calls: Cell<u32>,
    }

    impl TestClock {
        fn fixed(now: u64) -> Self {
            Self {
                first: now,
                second: now,
                calls: Cell::new(0),
            }
        }
    }

    impl Clock for TestClock {
        fn now_unix_us(&self) -> Result<u64, ProtocolError> {
            let call = self.calls.get();
            self.calls.set(call + 1);
            Ok(if call == 0 { self.first } else { self.second })
        }
    }

    struct TestBackend {
        identity: BackendIdentity,
        bytes: Vec<u8>,
        rows: u32,
        calls: u32,
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
            self.calls += 1;
            output.write(&self.bytes)?;
            for _ in 0..self.rows {
                output.complete_row()?;
            }
            Ok(())
        }
    }

    fn backend() -> TestBackend {
        TestBackend {
            identity: identity(20),
            bytes: vec![1, 2, 3],
            rows: 1,
            calls: 0,
        }
    }

    #[test]
    fn the_frame_executes_with_exact_context_and_a_keyed_receipt() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let mut backend = backend();
        let mut replay = MemoryReplayStore::default();
        let result = server
            .execute(&frame(), &mut backend, &mut replay, &TestClock::fixed(NOW))
            .expect("execution");
        assert_eq!(result.operation, operation());
        assert_eq!(result.bytes, [1, 2, 3]);
        assert_eq!(result.rows, 1);
        assert!(result.receipt.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn every_frame_bit_is_authenticated() {
        let original = frame();
        for bit in 0..FRAME_BYTES * 8 {
            let mut changed = original;
            changed[bit / 8] ^= 1 << (bit % 8);
            let server = ServerSession::new(authority(20), 128, 4).expect("server");
            let result = server.execute(
                &changed,
                &mut backend(),
                &mut MemoryReplayStore::default(),
                &TestClock::fixed(NOW),
            );
            assert!(result.is_err(), "accepted bit {bit}");
        }
    }

    #[test]
    fn a_backend_context_change_refuses_before_dispatch() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let mut backend = backend();
        backend.identity = identity(21);
        let result = server.execute(
            &frame(),
            &mut backend,
            &mut MemoryReplayStore::default(),
            &TestClock::fixed(NOW),
        );
        assert_eq!(result.unwrap_err(), ProtocolError::BackendIdentityMismatch);
        assert_eq!(backend.calls, 0);
    }

    #[test]
    fn byte_and_row_budgets_refuse_during_output() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let mut oversized = backend();
        oversized.bytes = vec![0; 65];
        assert_eq!(
            server
                .execute(
                    &frame(),
                    &mut oversized,
                    &mut MemoryReplayStore::default(),
                    &TestClock::fixed(NOW),
                )
                .unwrap_err(),
            ProtocolError::ResultBudgetExceeded
        );
        let mut excessive_rows = backend();
        excessive_rows.rows = 3;
        assert_eq!(
            server
                .execute(
                    &frame(),
                    &mut excessive_rows,
                    &mut MemoryReplayStore::default(),
                    &TestClock::fixed(NOW),
                )
                .unwrap_err(),
            ProtocolError::RowBudgetExceeded
        );
    }

    #[test]
    fn replay_and_completion_after_the_deadline_refuse() {
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let mut replay = MemoryReplayStore::default();
        server
            .execute(
                &frame(),
                &mut backend(),
                &mut replay,
                &TestClock::fixed(NOW),
            )
            .expect("first execution");
        assert_eq!(
            server
                .execute(
                    &frame(),
                    &mut backend(),
                    &mut replay,
                    &TestClock::fixed(NOW)
                )
                .unwrap_err(),
            ProtocolError::Replay
        );
        let late_clock = TestClock {
            first: NOW,
            second: DEADLINE,
            calls: Cell::new(0),
        };
        assert_eq!(
            server
                .execute(
                    &ClientSession::new(authority(20))
                        .encode(operation(), 64, 2, DEADLINE)
                        .expect("frame"),
                    &mut backend(),
                    &mut MemoryReplayStore::default(),
                    &late_clock,
                )
                .unwrap_err(),
            ProtocolError::ExpiredDuringExecution
        );
    }

    #[test]
    fn a_file_replay_store_refuses_after_restart_and_accepts_the_next_nonce() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let path = directory.path().join("replay.ndr");
        let server = ServerSession::new(authority(20), 128, 4).expect("server");
        let first_frame = frame();
        {
            let mut replay = FileReplayStore::open(&path, [21; 32]).expect("replay store");
            server
                .execute(
                    &first_frame,
                    &mut backend(),
                    &mut replay,
                    &TestClock::fixed(NOW),
                )
                .expect("first execution");
        }
        let mut restored = FileReplayStore::open(&path, [21; 32]).expect("restored store");
        assert_eq!(
            server
                .execute(
                    &first_frame,
                    &mut backend(),
                    &mut restored,
                    &TestClock::fixed(NOW),
                )
                .unwrap_err(),
            ProtocolError::Replay
        );
        let next_frame = ClientSession::resume(authority(20), 1)
            .expect("resumed client")
            .encode(operation(), 64, 2, DEADLINE)
            .expect("next frame");
        server
            .execute(
                &next_frame,
                &mut backend(),
                &mut restored,
                &TestClock::fixed(NOW),
            )
            .expect("next execution");
    }
}
