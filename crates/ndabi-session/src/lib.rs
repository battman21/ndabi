//! Authenticate a finite NDABI operation before a backend interprets its operands.
//!
//! The session binds authority, replay state, deadlines, result budgets, and receipts.
//! A backend owns every operation meaning and must refuse unsupported opcodes.

use std::fmt;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const FRAME_BYTES: usize = 76;
const AUTHENTICATED_BYTES: usize = 60;
const TAG_BYTES: usize = 16;
const MAGIC: [u8; 4] = *b"NDA2";
const VERSION: u8 = 1;
const READ_FLAGS: u16 = 0b0101;
const WRITE_FLAGS: u16 = 0b1010;
const RECEIPT_DOMAIN: &[u8] = b"ndabi/session/receipt/v3";
const KEY_DOMAIN: &[u8] = b"ndabi/session/key/v1";
const RECEIPT_KEY_DOMAIN: &[u8] = b"ndabi/session/receipt-key/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessClass {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawOperation {
    pub opcode: u8,
    pub first: i64,
    pub second: i64,
    pub third: u32,
}

impl RawOperation {
    pub fn new(opcode: u8, first: i64, second: i64, third: u32) -> Result<Self, SessionError> {
        if opcode == 0 {
            return Err(SessionError::new("the operation opcode is zero"));
        }
        Ok(Self {
            opcode,
            first,
            second,
            third,
        })
    }
}

#[derive(Clone)]
pub struct Authority {
    generation: u64,
    session: u32,
    expires_unix_us: u64,
    capability: u32,
    schema: u32,
    plan: u32,
    flags: u16,
    access_class: AccessClass,
    frame_key: Zeroizing<[u8; 32]>,
    receipt_key: Zeroizing<[u8; 32]>,
}

impl Authority {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root_key: [u8; 32],
        generation: u64,
        session: u32,
        expires_unix_us: u64,
        capability: u32,
        schema: u32,
        plan: u32,
    ) -> Result<Self, SessionError> {
        Self::new_with_flags(
            root_key,
            generation,
            session,
            expires_unix_us,
            capability,
            schema,
            plan,
            READ_FLAGS,
            AccessClass::Read,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_write(
        root_key: [u8; 32],
        generation: u64,
        session: u32,
        expires_unix_us: u64,
        capability: u32,
        schema: u32,
        plan: u32,
    ) -> Result<Self, SessionError> {
        Self::new_with_flags(
            root_key,
            generation,
            session,
            expires_unix_us,
            capability,
            schema,
            plan,
            WRITE_FLAGS,
            AccessClass::Write,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_flags(
        root_key: [u8; 32],
        generation: u64,
        session: u32,
        expires_unix_us: u64,
        capability: u32,
        schema: u32,
        plan: u32,
        flags: u16,
        access_class: AccessClass,
    ) -> Result<Self, SessionError> {
        if generation == 0 || session == 0 || expires_unix_us == 0 {
            return Err(SessionError::new("the authority contains a zero identity"));
        }
        if capability == 0 || schema == 0 || plan == 0 {
            return Err(SessionError::new("the authority contains a zero handle"));
        }
        let root_key = Zeroizing::new(root_key);
        if root_key.ct_eq(&[0; 32]).unwrap_u8() == 1 {
            return Err(SessionError::new("the root key is zero"));
        }
        let frame_key = derive_key(
            &root_key,
            KEY_DOMAIN,
            generation,
            session,
            expires_unix_us,
            capability,
            schema,
            plan,
            flags,
        );
        let receipt_key = derive_key(
            &root_key,
            RECEIPT_KEY_DOMAIN,
            generation,
            session,
            expires_unix_us,
            capability,
            schema,
            plan,
            flags,
        );
        Ok(Self {
            generation,
            session,
            expires_unix_us,
            capability,
            schema,
            plan,
            flags,
            access_class,
            frame_key: Zeroizing::new(frame_key),
            receipt_key: Zeroizing::new(receipt_key),
        })
    }

    fn tag(&self, authenticated: &[u8]) -> [u8; TAG_BYTES] {
        let digest = blake3::keyed_hash(&self.frame_key, authenticated);
        let mut tag = [0; TAG_BYTES];
        tag.copy_from_slice(&digest.as_bytes()[..TAG_BYTES]);
        tag
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_key(
    root_key: &[u8; 32],
    domain: &[u8],
    generation: u64,
    session: u32,
    expires_unix_us: u64,
    capability: u32,
    schema: u32,
    plan: u32,
    flags: u16,
) -> [u8; 32] {
    let mut derivation = blake3::Hasher::new_keyed(root_key);
    derivation.update(domain);
    derivation.update(&generation.to_le_bytes());
    derivation.update(&session.to_le_bytes());
    derivation.update(&expires_unix_us.to_le_bytes());
    derivation.update(&capability.to_le_bytes());
    derivation.update(&schema.to_le_bytes());
    derivation.update(&plan.to_le_bytes());
    derivation.update(&flags.to_le_bytes());
    let key = *derivation.finalize().as_bytes();
    derivation.zeroize();
    key
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

    pub fn encode(
        &mut self,
        operation: RawOperation,
        result_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<[u8; FRAME_BYTES], SessionError> {
        if result_budget == 0 {
            return Err(SessionError::new("the result budget is zero"));
        }
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(SessionError::new(
                "the frame deadline exceeds the authority",
            ));
        }
        let nonce = self.next_nonce;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or_else(|| SessionError::new("the client nonce space ended"))?;
        let mut frame = [0; FRAME_BYTES];
        frame[0..4].copy_from_slice(&MAGIC);
        frame[4] = VERSION;
        frame[5] = operation.opcode;
        frame[6..8].copy_from_slice(&self.authority.flags.to_le_bytes());
        frame[8..12].copy_from_slice(&self.authority.session.to_le_bytes());
        frame[12..20].copy_from_slice(&self.authority.generation.to_le_bytes());
        frame[20..28].copy_from_slice(&nonce.to_le_bytes());
        frame[28..36].copy_from_slice(&deadline_unix_us.to_le_bytes());
        frame[36..40].copy_from_slice(&result_budget.to_le_bytes());
        frame[40..48].copy_from_slice(&operation.first.to_le_bytes());
        frame[48..56].copy_from_slice(&operation.second.to_le_bytes());
        frame[56..60].copy_from_slice(&operation.third.to_le_bytes());
        let tag = self.authority.tag(&frame[..AUTHENTICATED_BYTES]);
        frame[AUTHENTICATED_BYTES..].copy_from_slice(&tag);
        Ok(frame)
    }

    /// Verify that the authority authenticated one exact request and result pair.
    pub fn verify_execution_receipt(
        &self,
        frame: &[u8],
        bytes: &[u8],
        candidate: &[u8; 32],
    ) -> Result<(), SessionError> {
        if frame.len() != FRAME_BYTES {
            return Err(SessionError::new("the receipt frame length is invalid"));
        }
        let expected = receipt(
            &self.authority,
            get_u64(frame, 20),
            *blake3::hash(frame).as_bytes(),
            bytes,
        );
        if expected.ct_eq(candidate).unwrap_u8() != 1 {
            return Err(SessionError::new(
                "the execution receipt authentication failed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Pending {
    nonce: u64,
    operation: RawOperation,
    result_budget: u32,
    frame_digest: [u8; 32],
}

pub struct ServerSession {
    authority: Authority,
    next_nonce: u64,
    maximum_result_bytes: u32,
}

impl ServerSession {
    pub fn new(authority: Authority, maximum_result_bytes: u32) -> Result<Self, SessionError> {
        if maximum_result_bytes == 0 {
            return Err(SessionError::new("the maximum result budget is zero"));
        }
        Ok(Self {
            authority,
            next_nonce: 1,
            maximum_result_bytes,
        })
    }

    pub fn execute<B: Backend>(
        &mut self,
        frame: &[u8],
        now_unix_us: u64,
        backend: &mut B,
    ) -> Result<Execution, SessionError> {
        if self.authority.access_class != backend.access_class() {
            return Err(SessionError::new(
                "the backend access class does not match the authority",
            ));
        }
        let pending = self.verify_pending(frame, now_unix_us)?;
        let bytes = backend.execute(pending.operation)?;
        if bytes.len() > pending.result_budget as usize {
            return Err(SessionError::new(
                "the result exceeded the authenticated budget",
            ));
        }
        self.commit(pending)?;
        Ok(Execution {
            operation: pending.operation,
            receipt: receipt(&self.authority, pending.nonce, pending.frame_digest, &bytes),
            bytes,
        })
    }

    fn verify_pending(&self, frame: &[u8], now_unix_us: u64) -> Result<Pending, SessionError> {
        if frame.len() != FRAME_BYTES {
            return Err(SessionError::new("the frame length is invalid"));
        }
        let expected_tag = self.authority.tag(&frame[..AUTHENTICATED_BYTES]);
        if expected_tag
            .ct_eq(&frame[AUTHENTICATED_BYTES..])
            .unwrap_u8()
            != 1
        {
            return Err(SessionError::new("the frame authentication failed"));
        }
        if frame[0..4] != MAGIC
            || frame[4] != VERSION
            || get_u16(frame, 6) != self.authority.flags
            || get_u32(frame, 8) != self.authority.session
            || get_u64(frame, 12) != self.authority.generation
        {
            return Err(SessionError::new("the frame authority is invalid"));
        }
        let nonce = get_u64(frame, 20);
        let deadline = get_u64(frame, 28);
        let result_budget = get_u32(frame, 36);
        if nonce != self.next_nonce {
            return Err(SessionError::new("the frame nonce is stale"));
        }
        if now_unix_us >= deadline || deadline > self.authority.expires_unix_us {
            return Err(SessionError::new("the frame deadline is invalid"));
        }
        if result_budget == 0 || result_budget > self.maximum_result_bytes {
            return Err(SessionError::new("the frame result budget is invalid"));
        }
        let operation = RawOperation::new(
            frame[5],
            get_i64(frame, 40),
            get_i64(frame, 48),
            get_u32(frame, 56),
        )?;
        Ok(Pending {
            nonce,
            operation,
            result_budget,
            frame_digest: *blake3::hash(frame).as_bytes(),
        })
    }

    fn commit(&mut self, pending: Pending) -> Result<(), SessionError> {
        if pending.nonce != self.next_nonce {
            return Err(SessionError::new("the pending execution is stale"));
        }
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or_else(|| SessionError::new("the server nonce space ended"))?;
        Ok(())
    }
}

pub trait Backend {
    fn access_class(&self) -> AccessClass {
        AccessClass::Read
    }

    fn execute(&mut self, operation: RawOperation) -> Result<Vec<u8>, SessionError>;
}

pub struct Execution {
    pub operation: RawOperation,
    pub bytes: Vec<u8>,
    pub receipt: [u8; 32],
}

fn receipt(authority: &Authority, nonce: u64, frame_digest: [u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_keyed(&authority.receipt_key);
    digest.update(RECEIPT_DOMAIN);
    digest.update(&authority.generation.to_le_bytes());
    digest.update(&authority.session.to_le_bytes());
    digest.update(&authority.capability.to_le_bytes());
    digest.update(&authority.schema.to_le_bytes());
    digest.update(&authority.plan.to_le_bytes());
    digest.update(&authority.flags.to_le_bytes());
    digest.update(&nonce.to_le_bytes());
    digest.update(&frame_digest);
    digest.update(bytes);
    let receipt = *digest.finalize().as_bytes();
    digest.zeroize();
    receipt
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionError {
    message: &'static str,
}

impl SessionError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }

    /// Refuse an operation which the selected backend profile cannot represent.
    pub fn profile_refused(message: &'static str) -> Self {
        Self::new(message)
    }

    pub fn backend_refused() -> Self {
        Self::new("the backend refused the operation")
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for SessionError {}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("a fixed field"))
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("a fixed field"))
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("a fixed field"))
}

fn get_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("a fixed field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;

    fn authority(session: u32) -> Authority {
        Authority::new([9; 32], 10, session, 2_000, 12, 13, 14).expect("authority")
    }

    struct TestBackend {
        fail: bool,
    }

    impl Backend for TestBackend {
        fn execute(&mut self, operation: RawOperation) -> Result<Vec<u8>, SessionError> {
            if self.fail || operation.opcode != 7 {
                Err(SessionError::backend_refused())
            } else {
                Ok(vec![operation.opcode, operation.third as u8])
            }
        }
    }

    fn frame() -> [u8; FRAME_BYTES] {
        ClientSession::new(authority(21))
            .encode(RawOperation::new(7, 1, 2, 3).expect("operation"), 32, 1_500)
            .expect("frame")
    }

    #[test]
    fn a_backend_neutral_operation_round_trips() {
        let client = ClientSession::new(authority(21));
        let frame = frame();
        let mut server = ServerSession::new(authority(21), 64).expect("server");
        let result = server
            .execute(&frame, NOW, &mut TestBackend { fail: false })
            .expect("execute");
        assert_eq!(
            result.operation,
            RawOperation::new(7, 1, 2, 3).expect("operation")
        );
        assert_eq!(result.bytes, [7, 3]);
        client
            .verify_execution_receipt(&frame, &result.bytes, &result.receipt)
            .expect("authenticated receipt");
    }

    #[test]
    fn changed_execution_evidence_refuses() {
        let client = ClientSession::new(authority(21));
        let frame = frame();
        let mut server = ServerSession::new(authority(21), 64).expect("server");
        let result = server
            .execute(&frame, NOW, &mut TestBackend { fail: false })
            .expect("execute");

        let mut changed_frame = frame;
        changed_frame[40] ^= 1;
        assert!(client
            .verify_execution_receipt(&changed_frame, &result.bytes, &result.receipt)
            .is_err());

        let mut changed_bytes = result.bytes.clone();
        changed_bytes[0] ^= 1;
        assert!(client
            .verify_execution_receipt(&frame, &changed_bytes, &result.receipt)
            .is_err());

        let mut changed_receipt = result.receipt;
        changed_receipt[0] ^= 1;
        assert!(client
            .verify_execution_receipt(&frame, &result.bytes, &changed_receipt)
            .is_err());

        let other_client = ClientSession::new(
            Authority::new([8; 32], 10, 21, 2_000, 12, 13, 14).expect("other authority"),
        );
        assert!(other_client
            .verify_execution_receipt(&frame, &result.bytes, &result.receipt)
            .is_err());
    }

    #[test]
    fn every_changed_frame_bit_refuses() {
        let original = frame();
        for bit in 0..FRAME_BYTES * 8 {
            let mut changed = original;
            changed[bit / 8] ^= 1 << (bit % 8);
            let mut server = ServerSession::new(authority(21), 64).expect("server");
            assert!(server
                .execute(&changed, NOW, &mut TestBackend { fail: false })
                .is_err());
        }
    }

    #[test]
    fn replay_and_exact_deadline_refuse() {
        let mut server = ServerSession::new(authority(21), 64).expect("server");
        server
            .execute(&frame(), NOW, &mut TestBackend { fail: false })
            .expect("first");
        assert!(server
            .execute(&frame(), NOW, &mut TestBackend { fail: false })
            .is_err());
        let mut deadline_server = ServerSession::new(authority(21), 64).expect("server");
        assert!(deadline_server
            .execute(&frame(), 1_500, &mut TestBackend { fail: false })
            .is_err());
    }

    #[test]
    fn backend_failure_does_not_commit_replay_state() {
        let mut server = ServerSession::new(authority(21), 64).expect("server");
        assert!(server
            .execute(&frame(), NOW, &mut TestBackend { fail: true })
            .is_err());
        assert!(server
            .execute(&frame(), NOW, &mut TestBackend { fail: false })
            .is_ok());
    }

    #[test]
    fn read_and_write_authorities_are_not_interchangeable() {
        let read = authority(21);
        let write =
            Authority::new_write([9; 32], 10, 21, 2_000, 12, 13, 14).expect("write authority");
        let mut client = ClientSession::new(write);
        let frame = client
            .encode(RawOperation::new(7, 1, 0, 2).expect("operation"), 32, 1_500)
            .expect("frame");
        let mut server = ServerSession::new(read, 64).expect("server");
        assert!(server
            .execute(&frame, NOW, &mut TestBackend { fail: false })
            .is_err());
    }

    #[test]
    fn a_read_authority_cannot_be_paired_with_a_write_backend() {
        struct WriteBackend {
            executions: u32,
        }

        impl Backend for WriteBackend {
            fn access_class(&self) -> AccessClass {
                AccessClass::Write
            }

            fn execute(&mut self, _operation: RawOperation) -> Result<Vec<u8>, SessionError> {
                self.executions += 1;
                Ok(vec![1])
            }
        }

        let mut server = ServerSession::new(authority(21), 64).expect("server");
        let mut backend = WriteBackend { executions: 0 };
        assert!(server.execute(&frame(), NOW, &mut backend).is_err());
        assert_eq!(backend.executions, 0);
    }
}
