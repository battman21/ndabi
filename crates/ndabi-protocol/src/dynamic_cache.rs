//! Promote verified dynamic programs and execute compact authenticated handles.
//!
//! The store binds each handle to one authority scope and immutable program digest.
//! Cached execution authenticates the handle, compact operands, budgets, and deadline.

use std::collections::HashMap;

use ndabi_isa::{
    verify_compact_operands, verify_program, OwnedVerifiedProgram, VerifiedOperands,
    VerifiedProgram, VerifyLimits, MAX_CACHE_ENTRIES, MAX_PROGRAM_BYTES,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::dynamic::{validate_dynamic_backend, DynamicBackend};
use super::{
    get_u16, get_u32, get_u64, put_u16, put_u32, put_u64, receipt, Authority, BoundedOutput,
    ClientSession, Clock, ExecutionLimits, ProtocolError, ReplayStore, ServerSession, MAGIC,
    READ_ACCESS, TAG_BYTES, VERSION_MAJOR, VERSION_MINOR,
};

const REGISTER_DYNAMIC_PROGRAM: u8 = 6;
const EXECUTE_CACHED_DYNAMIC: u8 = 7;
const REGISTRATION_DOMAIN: &[u8] = b"ndabi/wire/v1/register-dynamic-program";
const CACHED_EXECUTION_DOMAIN: &[u8] = b"ndabi/wire/v1/cached-dynamic-frame";
const ACCEPTANCE_DOMAIN: &[u8] = b"ndabi/wire/v1/dynamic-program-accepted";
const HEADER_BYTES: usize = 128;
const BASE_BYTES: usize = HEADER_BYTES + TAG_BYTES;
const CACHED_HEADER_BYTES: usize = 64;
const CACHED_BASE_BYTES: usize = CACHED_HEADER_BYTES + TAG_BYTES;

pub const MAX_DYNAMIC_PROGRAM_REGISTRATION_BYTES: usize = BASE_BYTES + MAX_PROGRAM_BYTES;
pub const MAX_CACHED_DYNAMIC_FRAME_BYTES: usize = CACHED_BASE_BYTES + MAX_PROGRAM_BYTES;

pub fn dynamic_program_registration_bytes(program_bytes: usize) -> Result<usize, ProtocolError> {
    if program_bytes > MAX_PROGRAM_BYTES {
        return Err(ProtocolError::DynamicProgramLimitExceeded);
    }
    BASE_BYTES
        .checked_add(program_bytes)
        .ok_or(ProtocolError::DynamicProgramLimitExceeded)
}

pub fn cached_dynamic_frame_bytes(operand_bytes: usize) -> Result<usize, ProtocolError> {
    if operand_bytes > MAX_PROGRAM_BYTES {
        return Err(ProtocolError::RequestLimitExceeded);
    }
    CACHED_BASE_BYTES
        .checked_add(operand_bytes)
        .ok_or(ProtocolError::RequestLimitExceeded)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicProgramAccepted {
    pub handle: u32,
    pub program_digest: [u8; 32],
    pub expiry_unix_us: u64,
    pub inserted: bool,
    pub receipt: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDynamicProgramHandle {
    handle: u32,
    program_digest: [u8; 32],
    expiry_unix_us: u64,
}

impl VerifiedDynamicProgramHandle {
    pub fn handle(self) -> u32 {
        self.handle
    }

    pub fn program_digest(self) -> [u8; 32] {
        self.program_digest
    }

    pub fn expiry_unix_us(self) -> u64 {
        self.expiry_unix_us
    }
}

impl ClientSession {
    pub fn encode_dynamic_program_registration(
        &mut self,
        program: &VerifiedProgram<'_>,
        expiry_unix_us: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        if expiry_unix_us == 0 || expiry_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        let total = dynamic_program_registration_bytes(program.bytes().len())?;
        let mut frame = vec![0_u8; total];
        frame[0..4].copy_from_slice(&MAGIC);
        frame[4] = VERSION_MAJOR;
        frame[5] = VERSION_MINOR;
        frame[6] = REGISTER_DYNAMIC_PROGRAM;
        frame[7] = READ_ACCESS;
        put_u16(&mut frame, 8, 0);
        put_u16(&mut frame, 10, 0);
        put_u32(
            &mut frame,
            12,
            u32::try_from(total).map_err(|_| ProtocolError::DynamicProgramLimitExceeded)?,
        );
        put_u64(&mut frame, 16, self.authority.session);
        put_u64(&mut frame, 24, self.authority.generation);
        put_u64(&mut frame, 32, nonce);
        put_u64(&mut frame, 40, expiry_unix_us);
        put_u32(
            &mut frame,
            56,
            u32::try_from(program.bytes().len())
                .map_err(|_| ProtocolError::DynamicProgramLimitExceeded)?,
        );
        frame[96..128].copy_from_slice(&self.authority.context_digest);
        let tag_offset = total - TAG_BYTES;
        frame[HEADER_BYTES..tag_offset].copy_from_slice(program.bytes());
        let tag = self
            .authority
            .tag_for(REGISTRATION_DOMAIN, &frame[..tag_offset]);
        frame[tag_offset..].copy_from_slice(&tag);
        self.next_nonce = next_nonce;
        Ok(frame)
    }

    pub fn verify_dynamic_program_accepted(
        &self,
        registration_frame: &[u8],
        accepted: &DynamicProgramAccepted,
    ) -> Result<VerifiedDynamicProgramHandle, ProtocolError> {
        if accepted.handle == 0 || registration_frame.len() < BASE_BYTES {
            return Err(ProtocolError::DynamicProgramNotFound);
        }
        let expected = program_acceptance(
            &self.authority,
            *blake3::hash(registration_frame).as_bytes(),
            get_u64(registration_frame, 32),
            accepted.handle,
            accepted.program_digest,
            accepted.expiry_unix_us,
            accepted.inserted,
        );
        if expected.ct_eq(&accepted.receipt).unwrap_u8() != 1 {
            return Err(ProtocolError::ReceiptMismatch);
        }
        Ok(VerifiedDynamicProgramHandle {
            handle: accepted.handle,
            program_digest: accepted.program_digest,
            expiry_unix_us: accepted.expiry_unix_us,
        })
    }

    pub fn encode_cached_dynamic(
        &mut self,
        program: VerifiedDynamicProgramHandle,
        operands: &VerifiedOperands<'_>,
        result_budget: u32,
        row_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        if operands.program_digest() != program.program_digest {
            return Err(ProtocolError::DynamicOperandsInvalid);
        }
        if result_budget == 0 || row_budget == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        if deadline_unix_us == 0
            || deadline_unix_us > self.authority.expires_unix_us
            || deadline_unix_us > program.expiry_unix_us
        {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        let compact_operands = operands.compact_bytes();
        let total = cached_dynamic_frame_bytes(compact_operands.len())?;
        let mut frame = vec![0_u8; total];
        frame[0..4].copy_from_slice(&MAGIC);
        frame[4] = VERSION_MAJOR;
        frame[5] = VERSION_MINOR;
        frame[6] = EXECUTE_CACHED_DYNAMIC;
        frame[7] = READ_ACCESS;
        put_u16(&mut frame, 8, 0);
        put_u16(&mut frame, 10, 0);
        put_u32(
            &mut frame,
            12,
            u32::try_from(total).map_err(|_| ProtocolError::RequestLimitExceeded)?,
        );
        put_u64(&mut frame, 16, self.authority.session);
        put_u64(&mut frame, 24, self.authority.generation);
        put_u64(&mut frame, 32, nonce);
        put_u64(&mut frame, 40, deadline_unix_us);
        put_u32(&mut frame, 48, result_budget);
        put_u32(&mut frame, 52, row_budget);
        put_u32(&mut frame, 56, program.handle);
        put_u32(
            &mut frame,
            60,
            u32::try_from(compact_operands.len())
                .map_err(|_| ProtocolError::RequestLimitExceeded)?,
        );
        let tag_offset = total - TAG_BYTES;
        frame[CACHED_HEADER_BYTES..tag_offset].copy_from_slice(compact_operands);
        let tag = self
            .authority
            .tag_for(CACHED_EXECUTION_DOMAIN, &frame[..tag_offset]);
        frame[tag_offset..].copy_from_slice(&tag);
        self.next_nonce = next_nonce;
        Ok(frame)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoreScope {
    session: u64,
    generation: u64,
    context_digest: [u8; 32],
}

struct StoredProgram {
    digest: [u8; 32],
    expiry_unix_us: u64,
    program: OwnedVerifiedProgram,
}

pub struct DynamicProgramStore {
    maximum_programs: usize,
    maximum_program_bytes: usize,
    maximum_total_bytes: usize,
    total_bytes: usize,
    next_handle: u32,
    scope: Option<StoreScope>,
    by_digest: HashMap<[u8; 32], u32>,
    programs: HashMap<u32, StoredProgram>,
}

impl DynamicProgramStore {
    pub fn new(
        maximum_programs: usize,
        maximum_program_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<Self, ProtocolError> {
        if maximum_programs == 0
            || maximum_programs > MAX_CACHE_ENTRIES
            || maximum_program_bytes == 0
            || maximum_program_bytes > MAX_PROGRAM_BYTES
            || maximum_total_bytes < maximum_program_bytes
        {
            return Err(ProtocolError::DynamicProgramLimitExceeded);
        }
        Ok(Self {
            maximum_programs,
            maximum_program_bytes,
            maximum_total_bytes,
            total_bytes: 0,
            next_handle: 1,
            scope: None,
            by_digest: HashMap::new(),
            programs: HashMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.programs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }

    fn authorise(&mut self, authority: &Authority) -> Result<(), ProtocolError> {
        let candidate = StoreScope {
            session: authority.session,
            generation: authority.generation,
            context_digest: authority.context_digest,
        };
        match self.scope {
            None => {
                self.scope = Some(candidate);
                Ok(())
            }
            Some(scope) if scope == candidate => Ok(()),
            Some(_) => Err(ProtocolError::DynamicProgramScopeMismatch),
        }
    }

    fn insert(
        &mut self,
        program: &VerifiedProgram<'_>,
        expiry_unix_us: u64,
        now_unix_us: u64,
    ) -> Result<(u32, u64, bool), ProtocolError> {
        if let Some(handle) = self.by_digest.get(&program.digest()).copied() {
            let expired = self
                .programs
                .get(&handle)
                .is_none_or(|stored| stored.expiry_unix_us <= now_unix_us);
            if !expired {
                let stored = self
                    .programs
                    .get(&handle)
                    .ok_or(ProtocolError::DynamicProgramNotFound)?;
                return Ok((handle, stored.expiry_unix_us, false));
            }
            self.remove(handle);
        }
        let next_total = self
            .total_bytes
            .checked_add(program.bytes().len())
            .ok_or(ProtocolError::DynamicProgramLimitExceeded)?;
        if self.programs.len() >= self.maximum_programs
            || program.bytes().len() > self.maximum_program_bytes
            || next_total > self.maximum_total_bytes
        {
            return Err(ProtocolError::DynamicProgramLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(ProtocolError::DynamicProgramLimitExceeded)?;
        let owned = OwnedVerifiedProgram::from_verified(program)
            .map_err(|_| ProtocolError::DynamicProgramLimitExceeded)?;
        self.by_digest.insert(program.digest(), handle);
        self.programs.insert(
            handle,
            StoredProgram {
                digest: program.digest(),
                expiry_unix_us,
                program: owned,
            },
        );
        self.total_bytes = next_total;
        Ok((handle, expiry_unix_us, true))
    }

    fn resolve(
        &mut self,
        handle: u32,
        now_unix_us: u64,
    ) -> Result<VerifiedProgram<'_>, ProtocolError> {
        let expired = self
            .programs
            .get(&handle)
            .is_some_and(|stored| stored.expiry_unix_us <= now_unix_us);
        if expired {
            self.remove(handle);
            return Err(ProtocolError::Expired);
        }
        let stored = self
            .programs
            .get(&handle)
            .ok_or(ProtocolError::DynamicProgramNotFound)?;
        Ok(stored.program.as_verified())
    }

    fn remove(&mut self, handle: u32) {
        if let Some(stored) = self.programs.remove(&handle) {
            self.by_digest.remove(&stored.digest);
            self.total_bytes = self.total_bytes.saturating_sub(stored.program.len());
        }
    }
}

#[derive(Debug)]
pub struct CachedDynamicExecution {
    pub handle: u32,
    pub program_digest: [u8; 32],
    pub operand_digest: [u8; 32],
    pub bytes: Vec<u8>,
    pub rows: u32,
    pub receipt: [u8; 32],
}

struct AuthenticatedRegistration<'a> {
    nonce: u64,
    expiry_unix_us: u64,
    program: &'a [u8],
}

struct AuthenticatedCachedExecution<'a> {
    nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    row_budget: u32,
    handle: u32,
    operands: &'a [u8],
}

impl ServerSession {
    pub fn register_dynamic_program<B: DynamicBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        store: &mut DynamicProgramStore,
        backend: &B,
        replay: &mut R,
        clock: &C,
    ) -> Result<DynamicProgramAccepted, ProtocolError> {
        let now_unix_us = clock.now_unix_us()?;
        let request = authenticate_registration(&self.authority, frame)?;
        if request.expiry_unix_us <= now_unix_us
            || request.expiry_unix_us > self.authority.expires_unix_us
        {
            return Err(ProtocolError::Expired);
        }
        let previous_nonce = next_nonce(replay, &self.authority, request.nonce)?;
        validate_dynamic_backend(&self.authority, backend, request.expiry_unix_us)?;
        let program = verify_program(
            request.program,
            backend.schema(),
            backend.granted_capabilities(),
            VerifyLimits::default(),
        )
        .map_err(|_| ProtocolError::DynamicProgramInvalid)?;
        store.authorise(&self.authority)?;
        let (handle, expiry_unix_us, inserted) =
            store.insert(&program, request.expiry_unix_us, now_unix_us)?;
        if clock.now_unix_us()? >= expiry_unix_us {
            if inserted {
                store.remove(handle);
            }
            return Err(ProtocolError::ExpiredDuringExecution);
        }
        if let Err(error) =
            replay.commit(self.authority.replay_key(), previous_nonce, request.nonce)
        {
            if inserted {
                store.remove(handle);
            }
            return Err(error);
        }
        let receipt = program_acceptance(
            &self.authority,
            *blake3::hash(frame).as_bytes(),
            request.nonce,
            handle,
            program.digest(),
            expiry_unix_us,
            inserted,
        );
        Ok(DynamicProgramAccepted {
            handle,
            program_digest: program.digest(),
            expiry_unix_us,
            inserted,
            receipt,
        })
    }

    pub fn execute_cached_dynamic<B: DynamicBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        store: &mut DynamicProgramStore,
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<CachedDynamicExecution, ProtocolError> {
        let admitted_unix_us = clock.now_unix_us()?;
        let request = authenticate_cached_execution(&self.authority, frame)?;
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
        let previous_nonce = next_nonce(replay, &self.authority, request.nonce)?;
        validate_dynamic_backend(&self.authority, backend, request.deadline_unix_us)?;
        store.authorise(&self.authority)?;
        let program = store.resolve(request.handle, admitted_unix_us)?;
        let operands = verify_compact_operands(request.operands, &program)
            .map_err(|_| ProtocolError::DynamicOperandsInvalid)?;
        // Start the database budget after handle and operand verification consume their time.
        let dispatched_unix_us = clock.now_unix_us()?;
        if dispatched_unix_us >= request.deadline_unix_us {
            return Err(ProtocolError::Expired);
        }
        let limits = ExecutionLimits {
            admitted_unix_us: dispatched_unix_us,
            deadline_unix_us: request.deadline_unix_us,
            maximum_result_bytes: request.result_budget,
            maximum_rows: request.row_budget,
        };
        let mut output = BoundedOutput::new_deferred(request.result_budget, request.row_budget);
        backend.execute_dynamic(&program, &operands, limits, &mut output)?;
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
        Ok(CachedDynamicExecution {
            handle: request.handle,
            program_digest: program.digest(),
            operand_digest: operands.digest(),
            bytes: output.bytes,
            rows: output.rows,
            receipt,
        })
    }
}

fn authenticate_registration<'a>(
    authority: &Authority,
    frame: &'a [u8],
) -> Result<AuthenticatedRegistration<'a>, ProtocolError> {
    if frame.len() < BASE_BYTES || frame.len() > MAX_DYNAMIC_PROGRAM_REGISTRATION_BYTES {
        return Err(ProtocolError::LengthMismatch);
    }
    let tag_offset = frame.len() - TAG_BYTES;
    let expected = authority.tag_for(REGISTRATION_DOMAIN, &frame[..tag_offset]);
    if expected.ct_eq(&frame[tag_offset..]).unwrap_u8() != 1 {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if frame[0..4] != MAGIC
        || frame[4] != VERSION_MAJOR
        || frame[5] != VERSION_MINOR
        || frame[6] != REGISTER_DYNAMIC_PROGRAM
        || frame[7] != READ_ACCESS
    {
        return Err(ProtocolError::UnsupportedFrame);
    }
    let program_bytes = get_u32(frame, 56) as usize;
    if get_u16(frame, 8) != 0
        || get_u16(frame, 10) != 0
        || get_u32(frame, 12) as usize != frame.len()
        || frame[48..56].iter().any(|byte| *byte != 0)
        || frame[60..96].iter().any(|byte| *byte != 0)
        || dynamic_program_registration_bytes(program_bytes)? != frame.len()
    {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    validate_authority(authority, frame)?;
    Ok(AuthenticatedRegistration {
        nonce: get_u64(frame, 32),
        expiry_unix_us: get_u64(frame, 40),
        program: &frame[HEADER_BYTES..tag_offset],
    })
}

fn authenticate_cached_execution<'a>(
    authority: &Authority,
    frame: &'a [u8],
) -> Result<AuthenticatedCachedExecution<'a>, ProtocolError> {
    if frame.len() < CACHED_BASE_BYTES || frame.len() > MAX_CACHED_DYNAMIC_FRAME_BYTES {
        return Err(ProtocolError::LengthMismatch);
    }
    let tag_offset = frame.len() - TAG_BYTES;
    let expected = authority.tag_for(CACHED_EXECUTION_DOMAIN, &frame[..tag_offset]);
    if expected.ct_eq(&frame[tag_offset..]).unwrap_u8() != 1 {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if frame[0..4] != MAGIC
        || frame[4] != VERSION_MAJOR
        || frame[5] != VERSION_MINOR
        || frame[6] != EXECUTE_CACHED_DYNAMIC
        || frame[7] != READ_ACCESS
    {
        return Err(ProtocolError::UnsupportedFrame);
    }
    let operand_bytes = get_u32(frame, 60) as usize;
    if get_u16(frame, 8) != 0
        || get_u16(frame, 10) != 0
        || get_u32(frame, 12) as usize != frame.len()
        || get_u32(frame, 56) == 0
        || cached_dynamic_frame_bytes(operand_bytes)? != frame.len()
    {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    if get_u64(frame, 16) != authority.session || get_u64(frame, 24) != authority.generation {
        return Err(ProtocolError::AuthorityMismatch);
    }
    Ok(AuthenticatedCachedExecution {
        nonce: get_u64(frame, 32),
        deadline_unix_us: get_u64(frame, 40),
        result_budget: get_u32(frame, 48),
        row_budget: get_u32(frame, 52),
        handle: get_u32(frame, 56),
        operands: &frame[CACHED_HEADER_BYTES..tag_offset],
    })
}

fn validate_authority(authority: &Authority, frame: &[u8]) -> Result<(), ProtocolError> {
    if get_u64(frame, 16) != authority.session
        || get_u64(frame, 24) != authority.generation
        || frame[96..128] != authority.context_digest
    {
        return Err(ProtocolError::AuthorityMismatch);
    }
    Ok(())
}

fn next_nonce<R: ReplayStore>(
    replay: &R,
    authority: &Authority,
    nonce: u64,
) -> Result<u64, ProtocolError> {
    let previous_nonce = replay.last_nonce(authority.replay_key())?;
    if nonce
        != previous_nonce
            .checked_add(1)
            .ok_or(ProtocolError::NonceEnded)?
    {
        return Err(ProtocolError::Replay);
    }
    Ok(previous_nonce)
}

#[allow(clippy::too_many_arguments)]
fn program_acceptance(
    authority: &Authority,
    request_digest: [u8; 32],
    nonce: u64,
    handle: u32,
    program_digest: [u8; 32],
    expiry_unix_us: u64,
    inserted: bool,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_keyed(&authority.receipt_key);
    digest.update(ACCEPTANCE_DOMAIN);
    digest.update(&authority.context_digest);
    digest.update(&request_digest);
    digest.update(&nonce.to_le_bytes());
    digest.update(&handle.to_le_bytes());
    digest.update(&program_digest);
    digest.update(&expiry_unix_us.to_le_bytes());
    digest.update(&[u8::from(inserted)]);
    let output = *digest.finalize().as_bytes();
    digest.zeroize();
    output
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use ndabi_isa::{
        capability_digest, verify_operands, verify_program, Comparison, Field, OperandBuilder,
        ParameterDescriptor, ParameterValue, ProgramBuilder, Relation, ScalarType, Schema,
        VerifyLimits,
    };

    use super::*;
    use crate::{digest_label, AuthorityContext, BackendIdentity, MemoryReplayStore};

    const NOW: u64 = 1_000_000;
    const DEADLINE: u64 = 2_000_000;
    const CAPABILITY: u64 = 1;

    struct TestClock;

    impl Clock for TestClock {
        fn now_unix_us(&self) -> Result<u64, ProtocolError> {
            Ok(NOW)
        }
    }

    struct DeadlineAtDispatchClock(Cell<u8>);

    impl Clock for DeadlineAtDispatchClock {
        fn now_unix_us(&self) -> Result<u64, ProtocolError> {
            let call = self.0.get();
            self.0.set(call.saturating_add(1));
            Ok(if call == 0 { NOW } else { DEADLINE })
        }
    }

    fn schema() -> Schema {
        Schema::new(vec![Relation::new(
            1,
            CAPABILITY,
            vec![Field::new(2, ScalarType::I64, false, CAPABILITY).expect("field")],
        )
        .expect("relation")])
        .expect("schema")
    }

    fn program_bytes(schema: &Schema) -> Vec<u8> {
        let mut builder = ProgramBuilder::new(schema.digest(), 4).expect("builder");
        let parameter = builder
            .parameter(ParameterDescriptor::new(ScalarType::I64, 8).expect("parameter"))
            .expect("parameter index");
        let scan = builder.scan(1).expect("scan");
        let filter = builder
            .filter(scan, 2, Comparison::Greater, parameter)
            .expect("filter");
        builder.return_result(filter).expect("return");
        builder.finish().expect("program")
    }

    fn authority(schema: &Schema) -> Authority {
        let identity = BackendIdentity::new(
            11,
            12,
            schema.digest(),
            digest_label(b"policy", &[1]),
            digest_label(b"profile", &[2]),
        )
        .expect("identity");
        let context =
            AuthorityContext::new([3; 16], [4; 16], 5, capability_digest(CAPABILITY), identity)
                .expect("context");
        Authority::new_read([6; 32], 7, 8, DEADLINE, context).expect("authority")
    }

    struct Backend {
        identity: crate::BackendIdentity,
        schema: Schema,
        calls: Cell<u32>,
    }

    impl DynamicBackend for Backend {
        fn identity(&self) -> crate::BackendIdentity {
            self.identity
        }

        fn schema(&self) -> &Schema {
            &self.schema
        }

        fn granted_capabilities(&self) -> u64 {
            CAPABILITY
        }

        fn execute_dynamic(
            &mut self,
            _program: &VerifiedProgram<'_>,
            operands: &VerifiedOperands<'_>,
            _limits: ExecutionLimits,
            output: &mut BoundedOutput,
        ) -> Result<(), ProtocolError> {
            self.calls.set(self.calls.get() + 1);
            let ParameterValue::I64(value) = operands
                .value(0)
                .map_err(|_| ProtocolError::DynamicOperandsInvalid)?
            else {
                return Err(ProtocolError::DynamicOperandsInvalid);
            };
            output.write(&value.to_le_bytes())?;
            output.complete_row()
        }
    }

    fn backend(schema: Schema) -> Backend {
        Backend {
            identity: authority(&schema).context.backend(),
            schema,
            calls: Cell::new(0),
        }
    }

    #[test]
    fn a_verified_program_promotes_and_executes_as_a_compact_handle() {
        let schema = schema();
        let bytes = program_bytes(&schema);
        let program =
            verify_program(&bytes, &schema, CAPABILITY, VerifyLimits::default()).expect("program");
        let mut operands = OperandBuilder::new(&program);
        operands.push(ParameterValue::I64(17)).expect("operand");
        let operand_bytes = operands.finish().expect("operand bytes");
        let operands = verify_operands(&operand_bytes, &program).expect("operands");
        let authority = authority(&schema);
        let mut client = ClientSession::new(authority.clone());
        let server = ServerSession::new(authority, 128, 2).expect("server");
        let mut backend = backend(schema);
        let mut store = DynamicProgramStore::new(8, 1_024, 8_192).expect("store");
        let mut replay = MemoryReplayStore::default();

        let registration = client
            .encode_dynamic_program_registration(&program, DEADLINE)
            .expect("registration");
        let accepted = server
            .register_dynamic_program(&registration, &mut store, &backend, &mut replay, &TestClock)
            .expect("accepted");
        let handle = client
            .verify_dynamic_program_accepted(&registration, &accepted)
            .expect("verified handle");
        let cached = client
            .encode_cached_dynamic(handle, &operands, 128, 2, DEADLINE)
            .expect("cached frame");
        let full = client
            .encode_dynamic(&program, &operands, 128, 2, DEADLINE)
            .expect("full frame");
        assert!(cached.len() < full.len());

        let execution = server
            .execute_cached_dynamic(&cached, &mut store, &mut backend, &mut replay, &TestClock)
            .expect("execution");
        assert_eq!(execution.handle, accepted.handle);
        assert_eq!(execution.bytes, 17_i64.to_le_bytes());
        assert_eq!(execution.rows, 1);
        client
            .verify_execution_receipt(
                &cached,
                execution.rows,
                &execution.bytes,
                &execution.receipt,
            )
            .expect("execution receipt");
        assert_eq!(backend.calls.get(), 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn changed_cached_operands_fail_authentication_before_dispatch() {
        let schema = schema();
        let bytes = program_bytes(&schema);
        let program =
            verify_program(&bytes, &schema, CAPABILITY, VerifyLimits::default()).expect("program");
        let mut operand_builder = OperandBuilder::new(&program);
        operand_builder
            .push(ParameterValue::I64(17))
            .expect("operand");
        let operand_bytes = operand_builder.finish().expect("operand bytes");
        let operands = verify_operands(&operand_bytes, &program).expect("operands");
        let authority = authority(&schema);
        let mut client = ClientSession::new(authority.clone());
        let server = ServerSession::new(authority, 128, 2).expect("server");
        let mut backend = backend(schema);
        let mut store = DynamicProgramStore::new(8, 1_024, 8_192).expect("store");
        let mut replay = MemoryReplayStore::default();
        let registration = client
            .encode_dynamic_program_registration(&program, DEADLINE)
            .expect("registration");
        let accepted = server
            .register_dynamic_program(&registration, &mut store, &backend, &mut replay, &TestClock)
            .expect("accepted");
        let handle = client
            .verify_dynamic_program_accepted(&registration, &accepted)
            .expect("handle");
        let mut cached = client
            .encode_cached_dynamic(handle, &operands, 128, 2, DEADLINE)
            .expect("cached");
        cached[CACHED_HEADER_BYTES] ^= 1;
        assert!(matches!(
            server.execute_cached_dynamic(
                &cached,
                &mut store,
                &mut backend,
                &mut replay,
                &TestClock,
            ),
            Err(ProtocolError::AuthenticationFailed)
        ));
        assert_eq!(backend.calls.get(), 0);
    }

    #[test]
    fn cached_verification_time_consumes_the_database_deadline() {
        let schema = schema();
        let bytes = program_bytes(&schema);
        let program =
            verify_program(&bytes, &schema, CAPABILITY, VerifyLimits::default()).expect("program");
        let mut operand_builder = OperandBuilder::new(&program);
        operand_builder
            .push(ParameterValue::I64(17))
            .expect("operand");
        let operand_bytes = operand_builder.finish().expect("operand bytes");
        let operands = verify_operands(&operand_bytes, &program).expect("operands");
        let authority = authority(&schema);
        let mut client = ClientSession::new(authority.clone());
        let server = ServerSession::new(authority, 128, 2).expect("server");
        let mut backend = backend(schema);
        let mut store = DynamicProgramStore::new(8, 1_024, 8_192).expect("store");
        let mut replay = MemoryReplayStore::default();
        let registration = client
            .encode_dynamic_program_registration(&program, DEADLINE)
            .expect("registration");
        let accepted = server
            .register_dynamic_program(&registration, &mut store, &backend, &mut replay, &TestClock)
            .expect("accepted");
        let handle = client
            .verify_dynamic_program_accepted(&registration, &accepted)
            .expect("handle");
        let cached = client
            .encode_cached_dynamic(handle, &operands, 128, 2, DEADLINE)
            .expect("cached");

        assert!(matches!(
            server.execute_cached_dynamic(
                &cached,
                &mut store,
                &mut backend,
                &mut replay,
                &DeadlineAtDispatchClock(Cell::new(0)),
            ),
            Err(ProtocolError::Expired)
        ));
        assert_eq!(backend.calls.get(), 0);
    }
}
