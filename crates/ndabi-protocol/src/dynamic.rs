//! Carry one verified dynamic ISA program through an authenticated NDABI request.
//!
//! Authenticate the complete frame before parsing the program or operands.
//! Bind the admitted schema and capability set to the session authority and backend.

use ndabi_isa::{
    capability_digest, verify_operands, verify_program, Schema, VerifiedOperands, VerifiedProgram,
    VerifyLimits, MAX_PROGRAM_BYTES,
};
use subtle::ConstantTimeEq;

use super::{
    get_u16, get_u32, get_u64, put_u16, put_u32, put_u64, receipt, Authority, BackendIdentity,
    BoundedOutput, ClientSession, Clock, ExecutionLimits, ProtocolError, ReplayStore,
    ServerSession, MAGIC, READ_ACCESS, TAG_BYTES, VERSION_MAJOR, VERSION_MINOR,
};

const EXECUTE_DYNAMIC_PROGRAM: u8 = 5;
const DYNAMIC_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v1/dynamic-frame";
const DYNAMIC_HEADER_BYTES: usize = 128;
const DYNAMIC_BASE_BYTES: usize = DYNAMIC_HEADER_BYTES + TAG_BYTES;

pub const MAX_DYNAMIC_FRAME_BYTES: usize = DYNAMIC_BASE_BYTES + (2 * MAX_PROGRAM_BYTES);

pub fn dynamic_frame_bytes(
    program_bytes: usize,
    operand_bytes: usize,
) -> Result<usize, ProtocolError> {
    if program_bytes > MAX_PROGRAM_BYTES || operand_bytes > MAX_PROGRAM_BYTES {
        return Err(ProtocolError::RequestLimitExceeded);
    }
    DYNAMIC_BASE_BYTES
        .checked_add(program_bytes)
        .and_then(|bytes| bytes.checked_add(operand_bytes))
        .ok_or(ProtocolError::RequestLimitExceeded)
}

impl ClientSession {
    pub fn encode_dynamic(
        &mut self,
        program: &VerifiedProgram<'_>,
        operands: &VerifiedOperands<'_>,
        result_budget: u32,
        row_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        if operands.program_digest() != program.digest() {
            return Err(ProtocolError::DynamicOperandsInvalid);
        }
        let operand_block = operands
            .complete_block_bytes()
            .ok_or(ProtocolError::DynamicOperandsInvalid)?;
        if result_budget == 0 || row_budget == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        let total = dynamic_frame_bytes(program.bytes().len(), operand_block.len())?;
        let total_u32 = u32::try_from(total).map_err(|_| ProtocolError::RequestLimitExceeded)?;
        let program_u32 = u32::try_from(program.bytes().len())
            .map_err(|_| ProtocolError::RequestLimitExceeded)?;
        let operands_u32 =
            u32::try_from(operand_block.len()).map_err(|_| ProtocolError::RequestLimitExceeded)?;
        let mut frame = vec![0_u8; total];
        frame[0..4].copy_from_slice(&MAGIC);
        frame[4] = VERSION_MAJOR;
        frame[5] = VERSION_MINOR;
        frame[6] = EXECUTE_DYNAMIC_PROGRAM;
        frame[7] = READ_ACCESS;
        put_u16(&mut frame, 8, 0);
        put_u16(&mut frame, 10, 0);
        put_u32(&mut frame, 12, total_u32);
        put_u64(&mut frame, 16, self.authority.session);
        put_u64(&mut frame, 24, self.authority.generation);
        put_u64(&mut frame, 32, nonce);
        put_u64(&mut frame, 40, deadline_unix_us);
        put_u32(&mut frame, 48, result_budget);
        put_u32(&mut frame, 52, row_budget);
        put_u32(&mut frame, 56, program_u32);
        put_u32(&mut frame, 60, operands_u32);
        frame[96..128].copy_from_slice(&self.authority.context_digest);
        let program_end = DYNAMIC_HEADER_BYTES + program.bytes().len();
        frame[DYNAMIC_HEADER_BYTES..program_end].copy_from_slice(program.bytes());
        let tag_offset = total - TAG_BYTES;
        frame[program_end..tag_offset].copy_from_slice(operand_block);
        let tag = self
            .authority
            .tag_for(DYNAMIC_FRAME_DOMAIN, &frame[..tag_offset]);
        frame[tag_offset..].copy_from_slice(&tag);
        self.next_nonce = next_nonce;
        Ok(frame)
    }
}

pub trait DynamicBackend {
    fn identity(&self) -> BackendIdentity;

    fn schema(&self) -> &Schema;

    fn granted_capabilities(&self) -> u64;

    fn required_tenant(&self) -> Option<[u8; 16]> {
        None
    }

    fn required_principal(&self) -> Option<[u8; 16]> {
        None
    }

    fn maximum_deadline_unix_us(&self) -> Option<u64> {
        None
    }

    fn execute_dynamic(
        &mut self,
        program: &VerifiedProgram<'_>,
        operands: &VerifiedOperands<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError>;
}

/// Hold one verified typed request for the equal-security benchmark control.
///
/// This type is not a wire admission surface. The feature exists only for benchmark binaries.
#[cfg(feature = "benchmark-governed-native")]
pub struct GovernedDynamicRequest<'a> {
    generation: u64,
    session: u64,
    context_digest: [u8; 32],
    nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    row_budget: u32,
    program: &'a VerifiedProgram<'a>,
    operands: &'a VerifiedOperands<'a>,
}

/// Prepare trusted typed requests for the equal-security benchmark control.
#[cfg(feature = "benchmark-governed-native")]
pub struct GovernedDynamicClientSession {
    authority: Authority,
    next_nonce: u64,
}

#[cfg(feature = "benchmark-governed-native")]
impl GovernedDynamicClientSession {
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            next_nonce: 1,
        }
    }

    pub fn prepare<'a>(
        &mut self,
        program: &'a VerifiedProgram<'a>,
        operands: &'a VerifiedOperands<'a>,
        result_budget: u32,
        row_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<GovernedDynamicRequest<'a>, ProtocolError> {
        if operands.program_digest() != program.digest() {
            return Err(ProtocolError::DynamicOperandsInvalid);
        }
        if result_budget == 0 || row_budget == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let nonce = self.next_nonce;
        self.next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        Ok(GovernedDynamicRequest {
            generation: self.authority.generation,
            session: self.authority.session,
            context_digest: self.authority.context_digest,
            nonce,
            deadline_unix_us,
            result_budget,
            row_budget,
            program,
            operands,
        })
    }

    pub fn verify_receipt(
        &self,
        request: &GovernedDynamicRequest<'_>,
        rows: u32,
        bytes: &[u8],
        candidate: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        let expected = receipt(
            &self.authority,
            governed_dynamic_request_digest(request),
            request.nonce,
            rows,
            bytes,
        );
        if expected.ct_eq(candidate).unwrap_u8() != 1 {
            return Err(ProtocolError::ReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DynamicExecution {
    pub program_digest: [u8; 32],
    pub operand_digest: [u8; 32],
    pub bytes: Vec<u8>,
    pub rows: u32,
    pub receipt: [u8; 32],
}

struct AuthenticatedDynamic<'a> {
    nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    row_budget: u32,
    program: &'a [u8],
    operands: &'a [u8],
}

impl ServerSession {
    /// Execute the equal-security benchmark control without a wire frame.
    ///
    /// Compile this method only into benchmark binaries. Do not expose it to an untrusted caller.
    #[cfg(feature = "benchmark-governed-native")]
    pub fn execute_governed_dynamic<B: DynamicBackend, R: ReplayStore, C: Clock>(
        &self,
        request: &GovernedDynamicRequest<'_>,
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<DynamicExecution, ProtocolError> {
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
        validate_dynamic_backend(&self.authority, backend, request.deadline_unix_us)?;
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
        let mut output = BoundedOutput::new_deferred(request.result_budget, request.row_budget);
        backend.execute_dynamic(request.program, request.operands, limits, &mut output)?;
        if clock.now_unix_us()? >= request.deadline_unix_us {
            return Err(ProtocolError::ExpiredDuringExecution);
        }
        replay.commit(self.authority.replay_key(), previous_nonce, request.nonce)?;
        let receipt = receipt(
            &self.authority,
            governed_dynamic_request_digest(request),
            request.nonce,
            output.rows,
            &output.bytes,
        );
        Ok(DynamicExecution {
            program_digest: request.program.digest(),
            operand_digest: request.operands.digest(),
            bytes: output.bytes,
            rows: output.rows,
            receipt,
        })
    }

    pub fn execute_dynamic<B: DynamicBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<DynamicExecution, ProtocolError> {
        let admitted_unix_us = clock.now_unix_us()?;
        let request = authenticate_dynamic(&self.authority, frame)?;
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
        validate_dynamic_backend(&self.authority, backend, request.deadline_unix_us)?;
        let program = verify_program(
            request.program,
            backend.schema(),
            backend.granted_capabilities(),
            VerifyLimits::default(),
        )
        .map_err(|_| ProtocolError::DynamicProgramInvalid)?;
        let operands = verify_operands(request.operands, &program)
            .map_err(|_| ProtocolError::DynamicOperandsInvalid)?;
        // Start the database budget after authentication and verification consume their time.
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
        Ok(DynamicExecution {
            program_digest: program.digest(),
            operand_digest: operands.digest(),
            bytes: output.bytes,
            rows: output.rows,
            receipt,
        })
    }
}

#[cfg(feature = "benchmark-governed-native")]
fn governed_dynamic_request_digest(request: &GovernedDynamicRequest<'_>) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"ndabi/benchmark/v1/governed-dynamic");
    digest.update(&request.generation.to_le_bytes());
    digest.update(&request.session.to_le_bytes());
    digest.update(&request.context_digest);
    digest.update(&request.nonce.to_le_bytes());
    digest.update(&request.deadline_unix_us.to_le_bytes());
    digest.update(&request.result_budget.to_le_bytes());
    digest.update(&request.row_budget.to_le_bytes());
    digest.update(&request.program.digest());
    digest.update(&request.operands.digest());
    *digest.finalize().as_bytes()
}

pub(super) fn validate_dynamic_backend<B: DynamicBackend>(
    authority: &Authority,
    backend: &B,
    deadline_unix_us: u64,
) -> Result<(), ProtocolError> {
    if backend.identity() != authority.context.backend()
        || backend.schema().digest() != authority.context.backend.schema_digest
    {
        return Err(ProtocolError::BackendIdentityMismatch);
    }
    if capability_digest(backend.granted_capabilities()) != authority.context.capability_digest {
        return Err(ProtocolError::CapabilityMismatch);
    }
    if backend
        .required_tenant()
        .is_some_and(|tenant| tenant != authority.context.tenant())
        || backend
            .required_principal()
            .is_some_and(|principal| principal != authority.context.principal())
    {
        return Err(ProtocolError::AuthorityMismatch);
    }
    if backend
        .maximum_deadline_unix_us()
        .is_some_and(|maximum| deadline_unix_us > maximum)
    {
        return Err(ProtocolError::Expired);
    }
    Ok(())
}

fn authenticate_dynamic<'a>(
    authority: &Authority,
    frame: &'a [u8],
) -> Result<AuthenticatedDynamic<'a>, ProtocolError> {
    if frame.len() < DYNAMIC_BASE_BYTES || frame.len() > MAX_DYNAMIC_FRAME_BYTES {
        return Err(ProtocolError::LengthMismatch);
    }
    let tag_offset = frame.len() - TAG_BYTES;
    let expected = authority.tag_for(DYNAMIC_FRAME_DOMAIN, &frame[..tag_offset]);
    if expected.ct_eq(&frame[tag_offset..]).unwrap_u8() != 1 {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if frame[0..4] != MAGIC
        || frame[4] != VERSION_MAJOR
        || frame[5] != VERSION_MINOR
        || frame[6] != EXECUTE_DYNAMIC_PROGRAM
        || frame[7] != READ_ACCESS
    {
        return Err(ProtocolError::UnsupportedFrame);
    }
    let program_bytes = get_u32(frame, 56) as usize;
    let operand_bytes = get_u32(frame, 60) as usize;
    if get_u16(frame, 8) != 0
        || get_u16(frame, 10) != 0
        || get_u32(frame, 12) as usize != frame.len()
        || frame[64..96].iter().any(|byte| *byte != 0)
        || dynamic_frame_bytes(program_bytes, operand_bytes)? != frame.len()
    {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    if get_u64(frame, 16) != authority.session
        || get_u64(frame, 24) != authority.generation
        || frame[96..128] != authority.context_digest
    {
        return Err(ProtocolError::AuthorityMismatch);
    }
    let program_end = DYNAMIC_HEADER_BYTES
        .checked_add(program_bytes)
        .ok_or(ProtocolError::RequestLimitExceeded)?;
    Ok(AuthenticatedDynamic {
        nonce: get_u64(frame, 32),
        deadline_unix_us: get_u64(frame, 40),
        result_budget: get_u32(frame, 48),
        row_budget: get_u32(frame, 52),
        program: &frame[DYNAMIC_HEADER_BYTES..program_end],
        operands: &frame[program_end..tag_offset],
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use ndabi_isa::{
        verify_operands, verify_program, Comparison, Field, OperandBuilder, ParameterDescriptor,
        ParameterValue, ProgramBuilder, Relation, ScalarType, VerifyLimits,
    };

    use super::*;
    use crate::{digest_label, AuthorityContext, MemoryReplayStore};

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
            41,
            43,
            schema.digest(),
            digest_label(b"policy", &[1]),
            digest_label(b"dynamic-profile", &[2]),
        )
        .expect("identity");
        let context =
            AuthorityContext::new([3; 16], [4; 16], 5, capability_digest(CAPABILITY), identity)
                .expect("context");
        Authority::new_read([6; 32], 7, 8, DEADLINE, context).expect("authority")
    }

    fn frame(schema: &Schema) -> Vec<u8> {
        let program_bytes = program_bytes(schema);
        let program = verify_program(&program_bytes, schema, CAPABILITY, VerifyLimits::default())
            .expect("verified program");
        let mut operands = OperandBuilder::new(&program);
        operands.push(ParameterValue::I64(17)).expect("operand");
        let operand_bytes = operands.finish().expect("operands");
        let operands = verify_operands(&operand_bytes, &program).expect("verified operands");
        ClientSession::new(authority(schema))
            .encode_dynamic(&program, &operands, 128, 2, DEADLINE)
            .expect("frame")
    }

    struct TestBackend {
        identity: BackendIdentity,
        schema: Schema,
        calls: Cell<u32>,
    }

    impl DynamicBackend for TestBackend {
        fn identity(&self) -> BackendIdentity {
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

    fn backend(schema: Schema) -> TestBackend {
        let authority = authority(&schema);
        TestBackend {
            identity: authority.context.backend(),
            schema,
            calls: Cell::new(0),
        }
    }

    #[test]
    fn an_authenticated_dynamic_program_executes_with_an_exact_receipt() {
        let schema = schema();
        let frame = frame(&schema);
        let authority = authority(&schema);
        let client = ClientSession::new(authority.clone());
        let server = ServerSession::new(authority, 128, 2).expect("server");
        let mut backend = backend(schema);
        let mut replay = MemoryReplayStore::default();
        let execution = server
            .execute_dynamic(&frame, &mut backend, &mut replay, &TestClock)
            .expect("execution");
        assert_eq!(execution.bytes, 17_i64.to_le_bytes());
        assert_eq!(execution.rows, 1);
        client
            .verify_execution_receipt(&frame, execution.rows, &execution.bytes, &execution.receipt)
            .expect("receipt");
        assert_eq!(backend.calls.get(), 1);
    }

    #[test]
    fn changed_program_bytes_fail_authentication_before_execution() {
        let schema = schema();
        let mut frame = frame(&schema);
        frame[DYNAMIC_HEADER_BYTES] ^= 1;
        let server = ServerSession::new(authority(&schema), 128, 2).expect("server");
        let mut backend = backend(schema);
        assert!(matches!(
            server.execute_dynamic(
                &frame,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &TestClock,
            ),
            Err(ProtocolError::AuthenticationFailed)
        ));
        assert_eq!(backend.calls.get(), 0);
    }

    #[test]
    fn authenticated_invalid_programs_fail_before_execution_and_replay_commit() {
        let schema = schema();
        let authority = authority(&schema);
        let mut frame = frame(&schema);
        frame[DYNAMIC_HEADER_BYTES] ^= 1;
        let tag_offset = frame.len() - TAG_BYTES;
        let tag = authority.tag_for(DYNAMIC_FRAME_DOMAIN, &frame[..tag_offset]);
        frame[tag_offset..].copy_from_slice(&tag);
        let server = ServerSession::new(authority, 128, 2).expect("server");
        let mut backend = backend(schema);
        let mut replay = MemoryReplayStore::default();
        assert!(matches!(
            server.execute_dynamic(&frame, &mut backend, &mut replay, &TestClock),
            Err(ProtocolError::DynamicProgramInvalid)
        ));
        assert_eq!(backend.calls.get(), 0);
        assert_eq!(replay.last_nonce(server.authority.replay_key()), Ok(0));
    }

    #[test]
    fn verification_time_consumes_the_database_deadline() {
        let schema = schema();
        let frame = frame(&schema);
        let server = ServerSession::new(authority(&schema), 128, 2).expect("server");
        let mut backend = backend(schema);
        let mut replay = MemoryReplayStore::default();
        assert!(matches!(
            server.execute_dynamic(
                &frame,
                &mut backend,
                &mut replay,
                &DeadlineAtDispatchClock(Cell::new(0)),
            ),
            Err(ProtocolError::Expired)
        ));
        assert_eq!(backend.calls.get(), 0);
        assert_eq!(replay.last_nonce(server.authority.replay_key()), Ok(0));
    }

    #[cfg(feature = "benchmark-governed-native")]
    #[test]
    fn the_governed_control_executes_verified_types_and_verifies_its_receipt() {
        let schema = schema();
        let program_bytes = program_bytes(&schema);
        let program = verify_program(&program_bytes, &schema, CAPABILITY, VerifyLimits::default())
            .expect("verified program");
        let mut operand_builder = OperandBuilder::new(&program);
        operand_builder
            .push(ParameterValue::I64(17))
            .expect("operand");
        let operand_bytes = operand_builder.finish().expect("operands");
        let operands = verify_operands(&operand_bytes, &program).expect("verified operands");
        let authority = authority(&schema);
        let mut client = GovernedDynamicClientSession::new(authority.clone());
        let request = client
            .prepare(&program, &operands, 128, 2, DEADLINE)
            .expect("request");
        let server = ServerSession::new(authority, 128, 2).expect("server");
        let mut backend = backend(schema);
        let execution = server
            .execute_governed_dynamic(
                &request,
                &mut backend,
                &mut MemoryReplayStore::default(),
                &TestClock,
            )
            .expect("execution");
        assert_eq!(execution.bytes, 17_i64.to_le_bytes());
        assert_eq!(execution.rows, 1);
        client
            .verify_receipt(
                &request,
                execution.rows,
                &execution.bytes,
                &execution.receipt,
            )
            .expect("receipt");
        assert_eq!(backend.calls.get(), 1);
    }
}
