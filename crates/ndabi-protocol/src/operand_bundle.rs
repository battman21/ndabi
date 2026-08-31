//! Reuse canonical graph operands inside one authenticated authority session.
//!
//! The registry fixes every slot before registration. The store retains only immutable values.
//! Each execution authenticates its dynamic values and returns an operand-bound receipt.

use std::collections::{HashMap, HashSet};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::graph::{GraphOperation, GraphRegistry, MAX_GRAPH_PARAMETER_BYTES};
use super::{
    get_u16, get_u32, get_u64, put_u16, put_u32, put_u64, Authority, BackendIdentity,
    BoundedOutput, ClientSession, Clock, ExecutionLimits, ProtocolError, ReplayStore,
    ServerSession, MAGIC, READ_ACCESS, TAG_BYTES, VERSION_MAJOR, VERSION_MINOR,
};

const REGISTER_BUNDLE: u8 = 5;
const EXECUTE_BUNDLE: u8 = 6;
const REMOVE_BUNDLE: u8 = 7;
const HEADER_BYTES: usize = 128;
const BASE_BYTES: usize = HEADER_BYTES + TAG_BYTES;
const LAYOUT_DOMAIN: &[u8] = b"ndabi/wire/v1/operand-layout";
const BUNDLE_DOMAIN: &[u8] = b"ndabi/wire/v1/operand-bundle";
const EXECUTION_VALUES_DOMAIN: &[u8] = b"ndabi/wire/v1/execution-operands";
const EFFECTIVE_OPERANDS_DOMAIN: &[u8] = b"ndabi/wire/v1/effective-operands";
const REGISTER_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v1/register-operand-bundle";
const EXECUTE_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v1/execute-bundled-graph";
const REMOVE_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v1/drop-operand-bundle";
const RECEIPT_DOMAIN: &[u8] = b"ndabi/wire/v3/bundled-execution-receipt";
const MAX_SLOTS: usize = 4_096;

pub fn operand_bundle_frame_bytes(payload_bytes: usize) -> Result<usize, ProtocolError> {
    if payload_bytes > MAX_GRAPH_PARAMETER_BYTES {
        return Err(ProtocolError::ParameterLimitExceeded);
    }
    BASE_BYTES
        .checked_add(payload_bytes)
        .ok_or(ProtocolError::ParameterLimitExceeded)
}

/// Retain one immutable bundled execution frame across authenticated executions.
pub struct PreparedBundledGraphFrame {
    bytes: Vec<u8>,
}

impl PreparedBundledGraphFrame {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for PreparedBundledGraphFrame {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperandStorage {
    Bundle = 1,
    Execution = 2,
}

impl TryFrom<u8> for OperandStorage {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Bundle),
            2 => Ok(Self::Execution),
            _ => Err(ProtocolError::OperandLayoutInvalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperandType {
    Bool = 1,
    I64 = 2,
    U64 = 3,
    I128 = 4,
    F64 = 5,
    TimestampUs = 6,
    Uuid = 7,
    Bytes = 8,
    Utf8 = 9,
}

impl OperandType {
    fn fixed_bytes(self) -> Option<u32> {
        match self {
            Self::Bool => Some(1),
            Self::I64 | Self::U64 | Self::F64 | Self::TimestampUs => Some(8),
            Self::I128 | Self::Uuid => Some(16),
            Self::Bytes | Self::Utf8 => None,
        }
    }

    fn validate(self, value: &[u8]) -> Result<(), ProtocolError> {
        if self
            .fixed_bytes()
            .is_some_and(|width| value.len() != width as usize)
        {
            return Err(ProtocolError::OperandValueInvalid);
        }
        match self {
            Self::Bool if !matches!(value, [0] | [1]) => Err(ProtocolError::OperandValueInvalid),
            Self::F64 => {
                let bytes: [u8; 8] = value
                    .try_into()
                    .map_err(|_| ProtocolError::OperandValueInvalid)?;
                if f64::from_bits(u64::from_le_bytes(bytes)).is_finite() {
                    Ok(())
                } else {
                    Err(ProtocolError::OperandValueInvalid)
                }
            }
            Self::Utf8 if std::str::from_utf8(value).is_err() => {
                Err(ProtocolError::OperandValueInvalid)
            }
            _ => Ok(()),
        }
    }
}

impl TryFrom<u8> for OperandType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Bool),
            2 => Ok(Self::I64),
            3 => Ok(Self::U64),
            4 => Ok(Self::I128),
            5 => Ok(Self::F64),
            6 => Ok(Self::TimestampUs),
            7 => Ok(Self::Uuid),
            8 => Ok(Self::Bytes),
            9 => Ok(Self::Utf8),
            _ => Err(ProtocolError::OperandValueInvalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperandSlot {
    id: u16,
    storage: OperandStorage,
    value_type: OperandType,
    nullable: bool,
    maximum_bytes: u32,
}

impl OperandSlot {
    pub fn new(
        id: u16,
        storage: OperandStorage,
        value_type: OperandType,
        nullable: bool,
        maximum_bytes: u32,
    ) -> Result<Self, ProtocolError> {
        if id == 0 || maximum_bytes == 0 {
            return Err(ProtocolError::OperandLayoutInvalid);
        }
        if value_type
            .fixed_bytes()
            .is_some_and(|width| width != maximum_bytes)
        {
            return Err(ProtocolError::OperandLayoutInvalid);
        }
        Ok(Self {
            id,
            storage,
            value_type,
            nullable,
            maximum_bytes,
        })
    }

    pub fn id(self) -> u16 {
        self.id
    }

    pub fn storage(self) -> OperandStorage {
        self.storage
    }

    pub fn value_type(self) -> OperandType {
        self.value_type
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperandLayout {
    slots: Vec<OperandSlot>,
    digest: [u8; 32],
    maximum_value_bytes: u32,
    maximum_record_bytes: u32,
}

impl OperandLayout {
    pub fn new(slots: impl IntoIterator<Item = OperandSlot>) -> Result<Self, ProtocolError> {
        let mut slots = slots.into_iter().collect::<Vec<_>>();
        if slots.is_empty() || slots.len() > MAX_SLOTS {
            return Err(ProtocolError::OperandLayoutInvalid);
        }
        slots.sort_unstable_by_key(|slot| slot.id);
        if slots.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(ProtocolError::OperandLayoutInvalid);
        }
        let maximum_value_bytes = slots.iter().try_fold(0_u32, |total, slot| {
            total
                .checked_add(slot.maximum_bytes)
                .ok_or(ProtocolError::OperandLayoutInvalid)
        })?;
        let record_overhead = (slots.len() as u32)
            .checked_mul(8)
            .ok_or(ProtocolError::OperandLayoutInvalid)?;
        let maximum_record_bytes = maximum_value_bytes
            .checked_add(record_overhead)
            .ok_or(ProtocolError::OperandLayoutInvalid)?;
        if maximum_record_bytes as usize > MAX_GRAPH_PARAMETER_BYTES {
            return Err(ProtocolError::OperandLayoutInvalid);
        }
        let mut digest = blake3::Hasher::new();
        digest.update(LAYOUT_DOMAIN);
        digest.update(&(slots.len() as u32).to_le_bytes());
        for slot in &slots {
            digest.update(&slot.id.to_le_bytes());
            digest.update(&[slot.storage as u8, slot.value_type as u8]);
            digest.update(&(if slot.nullable { 1_u16 } else { 0_u16 }).to_le_bytes());
            digest.update(&slot.maximum_bytes.to_le_bytes());
        }
        Ok(Self {
            slots,
            digest: *digest.finalize().as_bytes(),
            maximum_value_bytes,
            maximum_record_bytes,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn slots(&self) -> &[OperandSlot] {
        &self.slots
    }

    pub fn maximum_value_bytes(&self) -> u32 {
        self.maximum_value_bytes
    }

    pub fn maximum_record_bytes(&self) -> u32 {
        self.maximum_record_bytes
    }

    pub fn slot_count(&self, storage: OperandStorage) -> u32 {
        self.slots
            .iter()
            .filter(|slot| slot.storage == storage)
            .count() as u32
    }

    pub fn encode_values(
        &self,
        storage: OperandStorage,
        values: &[OperandValue<'_>],
    ) -> Result<Vec<u8>, ProtocolError> {
        let required = self.slots.iter().filter(|slot| slot.storage == storage);
        if required.clone().count() != values.len() {
            return Err(ProtocolError::OperandValueInvalid);
        }
        let record_bytes = values.iter().try_fold(0_usize, |total, value| {
            total
                .checked_add(8)
                .and_then(|value_total| value_total.checked_add(value.value.map_or(0, <[u8]>::len)))
                .ok_or(ProtocolError::OperandBundleLimitExceeded)
        })?;
        if record_bytes > self.maximum_record_bytes as usize {
            return Err(ProtocolError::OperandBundleLimitExceeded);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(record_bytes)
            .map_err(|_| ProtocolError::OperandBundleLimitExceeded)?;
        for (slot, value) in required.zip(values) {
            if value.slot_id != slot.id {
                return Err(ProtocolError::NonCanonicalFrame);
            }
            encode_value(slot, value.value, &mut bytes)?;
        }
        Ok(bytes)
    }

    pub fn validate_values<'a>(
        &'a self,
        storage: OperandStorage,
        records: &'a [u8],
    ) -> Result<OperandValues<'a>, ProtocolError> {
        let mut offset = 0_usize;
        for slot in self.slots.iter().filter(|slot| slot.storage == storage) {
            let header = records
                .get(offset..offset + 8)
                .ok_or(ProtocolError::OperandValueInvalid)?;
            if get_u16(header, 0) != slot.id
                || OperandType::try_from(header[2])? != slot.value_type
                || header[3] & !1 != 0
            {
                return Err(ProtocolError::OperandValueInvalid);
            }
            let is_null = header[3] == 1;
            let length = get_u32(header, 4) as usize;
            let value = records
                .get(offset + 8..offset + 8 + length)
                .ok_or(ProtocolError::OperandValueInvalid)?;
            validate_value(slot, is_null, value)?;
            offset = offset
                .checked_add(8 + length)
                .ok_or(ProtocolError::OperandValueInvalid)?;
        }
        if offset != records.len() {
            return Err(ProtocolError::NonCanonicalFrame);
        }
        Ok(OperandValues { records })
    }
}

#[derive(Clone, Copy)]
pub struct OperandValue<'a> {
    pub slot_id: u16,
    pub value: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
pub struct OperandValueRef<'a> {
    pub slot_id: u16,
    pub value_type: OperandType,
    pub value: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
pub struct OperandValues<'a> {
    records: &'a [u8],
}

impl<'a> OperandValues<'a> {
    pub fn records(self) -> &'a [u8] {
        self.records
    }

    pub fn iter(self) -> OperandValueIter<'a> {
        OperandValueIter {
            records: self.records,
            offset: 0,
        }
    }
}

pub struct OperandValueIter<'a> {
    records: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for OperandValueIter<'a> {
    type Item = OperandValueRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let header = self.records.get(self.offset..self.offset + 8)?;
        let length = get_u32(header, 4) as usize;
        let value = self
            .records
            .get(self.offset + 8..self.offset + 8 + length)?;
        self.offset += 8 + length;
        Some(OperandValueRef {
            slot_id: get_u16(header, 0),
            value_type: OperandType::try_from(header[2]).expect("validated operand type"),
            value: (header[3] == 0).then_some(value),
        })
    }
}

fn encode_value(
    slot: &OperandSlot,
    value: Option<&[u8]>,
    output: &mut Vec<u8>,
) -> Result<(), ProtocolError> {
    let (flags, value) = match value {
        Some(value) => (0_u8, value),
        None if slot.nullable => (1_u8, &[][..]),
        None => return Err(ProtocolError::OperandValueInvalid),
    };
    validate_value(slot, flags == 1, value)?;
    output.extend_from_slice(&slot.id.to_le_bytes());
    output.push(slot.value_type as u8);
    output.push(flags);
    output.extend_from_slice(&(value.len() as u32).to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn validate_value(slot: &OperandSlot, is_null: bool, value: &[u8]) -> Result<(), ProtocolError> {
    if is_null {
        return if slot.nullable && value.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::OperandValueInvalid)
        };
    }
    if value.len() > slot.maximum_bytes as usize {
        return Err(ProtocolError::OperandValueInvalid);
    }
    slot.value_type.validate(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleAccepted {
    pub bundle_handle: u32,
    pub graph_handle: u32,
    pub expiry_unix_us: u64,
    pub bundle_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleRemoved {
    pub bundle_handle: u32,
    pub graph_handle: u32,
}

struct StoredBundle {
    session: u64,
    generation: u64,
    context_digest: [u8; 32],
    graph_handle: u32,
    result_shape: u32,
    schema_digest: [u8; 32],
    expiry_unix_us: u64,
    digest: [u8; 32],
    values: Zeroizing<Vec<u8>>,
}

pub struct OperandBundleStore {
    session: u64,
    generation: u64,
    context_digest: [u8; 32],
    maximum_bundles: usize,
    maximum_total_bytes: usize,
    maximum_bundle_bytes: usize,
    total_bytes: usize,
    bundles: HashMap<u32, StoredBundle>,
    retired: HashSet<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundledOperandContext {
    pub bundle_handle: u32,
    pub bundle_expiry_unix_us: u64,
    pub bundle_digest: [u8; 32],
}

impl OperandBundleStore {
    pub fn new(
        authority: &Authority,
        maximum_bundles: usize,
        maximum_total_bytes: usize,
        maximum_bundle_bytes: usize,
    ) -> Result<Self, ProtocolError> {
        if maximum_bundles == 0
            || maximum_total_bytes == 0
            || maximum_bundle_bytes == 0
            || maximum_bundle_bytes > MAX_GRAPH_PARAMETER_BYTES
            || maximum_bundle_bytes > maximum_total_bytes
        {
            return Err(ProtocolError::OperandBundleLimitExceeded);
        }
        Ok(Self {
            session: authority.session,
            generation: authority.generation,
            context_digest: authority.context_digest,
            maximum_bundles,
            maximum_total_bytes,
            maximum_bundle_bytes,
            total_bytes: 0,
            bundles: HashMap::new(),
            retired: HashSet::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    pub fn evict(&mut self, bundle_handle: u32) -> Result<(), ProtocolError> {
        let bundle = self
            .bundles
            .remove(&bundle_handle)
            .ok_or(ProtocolError::OperandBundleNotFound)?;
        self.total_bytes = self
            .total_bytes
            .checked_sub(bundle.values.len())
            .ok_or(ProtocolError::OperandBundleLimitExceeded)?;
        self.retired.insert(bundle_handle);
        Ok(())
    }

    fn authorise(&self, authority: &Authority) -> Result<(), ProtocolError> {
        if self.session != authority.session
            || self.generation != authority.generation
            || self.context_digest != authority.context_digest
        {
            return Err(ProtocolError::AuthorityMismatch);
        }
        Ok(())
    }
}

pub trait BundledGraphBackend {
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

    fn execute_bundled_graph(
        &mut self,
        operation: GraphOperation,
        bundle_context: BundledOperandContext,
        bundle_values: OperandValues<'_>,
        execution_values: OperandValues<'_>,
        limits: ExecutionLimits,
        output: &mut BoundedOutput,
    ) -> Result<(), ProtocolError>;
}

impl ClientSession {
    pub fn encode_operand_bundle_registration(
        &mut self,
        operation: GraphOperation,
        layout: &OperandLayout,
        bundle_handle: u32,
        bundle_expiry_unix_us: u64,
        values: &[OperandValue<'_>],
    ) -> Result<Vec<u8>, ProtocolError> {
        validate_operation(operation)?;
        if bundle_handle == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        if bundle_expiry_unix_us == 0 || bundle_expiry_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let records = layout.encode_values(OperandStorage::Bundle, values)?;
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        let mut frame = allocate_frame(records.len())?;
        initialise_header(
            &mut frame,
            REGISTER_BUNDLE,
            operation,
            &self.authority,
            nonce,
            bundle_expiry_unix_us,
        )?;
        put_u32(&mut frame, 48, to_u32(records.len())?);
        put_u32(&mut frame, 52, layout.slot_count(OperandStorage::Bundle));
        put_u32(&mut frame, 64, bundle_handle);
        finish_frame(&mut frame, &records, &self.authority, REGISTER_FRAME_DOMAIN);
        self.next_nonce = next_nonce;
        Ok(frame)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encode_bundled_graph(
        &mut self,
        operation: GraphOperation,
        layout: &OperandLayout,
        bundle_handle: u32,
        values: &[OperandValue<'_>],
        result_budget: u32,
        row_budget: u32,
        deadline_unix_us: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let records = layout.encode_values(OperandStorage::Execution, values)?;
        let mut frame = allocate_frame(records.len())?;
        self.prepare_bundled_graph_into(
            operation,
            layout,
            bundle_handle,
            &records,
            result_budget,
            row_budget,
            &mut frame,
        )?;
        self.sign_prepared_bundled_graph(&mut frame, deadline_unix_us)?;
        Ok(frame)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_bundled_graph_frame(
        &self,
        operation: GraphOperation,
        layout: &OperandLayout,
        bundle_handle: u32,
        values: &[OperandValue<'_>],
        result_budget: u32,
        row_budget: u32,
    ) -> Result<PreparedBundledGraphFrame, ProtocolError> {
        let records = layout.encode_values(OperandStorage::Execution, values)?;
        let mut bytes = allocate_frame(records.len())?;
        self.prepare_bundled_graph_into(
            operation,
            layout,
            bundle_handle,
            &records,
            result_budget,
            row_budget,
            &mut bytes,
        )?;
        Ok(PreparedBundledGraphFrame { bytes })
    }

    pub fn encode_prepared_bundled_graph<'a>(
        &mut self,
        prepared: &'a mut PreparedBundledGraphFrame,
        deadline_unix_us: u64,
    ) -> Result<&'a [u8], ProtocolError> {
        if prepared.bytes.len() < BASE_BYTES {
            return Err(ProtocolError::LengthMismatch);
        }
        if get_u64(&prepared.bytes, 16) != self.authority.session
            || get_u64(&prepared.bytes, 24) != self.authority.generation
            || prepared.bytes[96..128] != self.authority.context_digest
        {
            return Err(ProtocolError::AuthorityMismatch);
        }
        self.sign_prepared_bundled_graph(&mut prepared.bytes, deadline_unix_us)?;
        Ok(&prepared.bytes)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_bundled_graph_into(
        &self,
        operation: GraphOperation,
        layout: &OperandLayout,
        bundle_handle: u32,
        records: &[u8],
        result_budget: u32,
        row_budget: u32,
        frame: &mut [u8],
    ) -> Result<(), ProtocolError> {
        validate_operation(operation)?;
        if bundle_handle == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        if result_budget == 0 || row_budget == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        if frame.len() != operand_bundle_frame_bytes(records.len())? {
            return Err(ProtocolError::LengthMismatch);
        }
        frame.fill(0);
        frame[0..4].copy_from_slice(&MAGIC);
        frame[4] = VERSION_MAJOR;
        frame[5] = VERSION_MINOR;
        frame[6] = EXECUTE_BUNDLE;
        frame[7] = READ_ACCESS;
        put_u16(frame, 10, operation.opcode);
        put_u32(frame, 12, to_u32(frame.len())?);
        put_u64(frame, 16, self.authority.session);
        put_u64(frame, 24, self.authority.generation);
        put_u32(frame, 48, result_budget);
        put_u32(frame, 52, row_budget);
        put_u32(frame, 56, operation.graph_handle);
        put_u32(frame, 60, operation.result_shape);
        put_u32(frame, 64, bundle_handle);
        put_u32(frame, 68, to_u32(records.len())?);
        put_u32(frame, 72, layout.slot_count(OperandStorage::Execution));
        frame[96..128].copy_from_slice(&self.authority.context_digest);
        let tag_offset = frame.len() - TAG_BYTES;
        frame[HEADER_BYTES..tag_offset].copy_from_slice(records);
        Ok(())
    }

    fn sign_prepared_bundled_graph(
        &mut self,
        frame: &mut [u8],
        deadline_unix_us: u64,
    ) -> Result<(), ProtocolError> {
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        put_u64(frame, 32, nonce);
        put_u64(frame, 40, deadline_unix_us);
        let tag_offset = frame.len() - TAG_BYTES;
        let tag = self
            .authority
            .tag_for(EXECUTE_FRAME_DOMAIN, &frame[..tag_offset]);
        frame[tag_offset..].copy_from_slice(&tag);
        self.next_nonce = next_nonce;
        Ok(())
    }

    pub fn encode_operand_bundle_removal(
        &mut self,
        operation: GraphOperation,
        bundle_handle: u32,
        deadline_unix_us: u64,
    ) -> Result<[u8; BASE_BYTES], ProtocolError> {
        validate_operation(operation)?;
        if bundle_handle == 0 {
            return Err(ProtocolError::ZeroOperationField);
        }
        if deadline_unix_us == 0 || deadline_unix_us > self.authority.expires_unix_us {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(ProtocolError::NonceEnded)?;
        let mut frame = [0_u8; BASE_BYTES];
        initialise_header(
            &mut frame,
            REMOVE_BUNDLE,
            operation,
            &self.authority,
            nonce,
            deadline_unix_us,
        )?;
        put_u32(&mut frame, 64, bundle_handle);
        let tag = self
            .authority
            .tag_for(REMOVE_FRAME_DOMAIN, &frame[..HEADER_BYTES]);
        frame[HEADER_BYTES..].copy_from_slice(&tag);
        self.next_nonce = next_nonce;
        Ok(frame)
    }

    pub fn verify_bundled_execution_receipt(
        &self,
        frame: &[u8],
        bundle_digest: [u8; 32],
        parameter_schema_digest: [u8; 32],
        rows: u32,
        result: &[u8],
        candidate: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        if frame.len() < BASE_BYTES || frame[6] != EXECUTE_BUNDLE {
            return Err(ProtocolError::LengthMismatch);
        }
        let tag_offset = frame.len() - TAG_BYTES;
        let execution_values = frame
            .get(HEADER_BYTES..tag_offset)
            .ok_or(ProtocolError::LengthMismatch)?;
        let operand_digest = effective_operand_digest(
            bundle_digest,
            execution_value_digest(parameter_schema_digest, execution_values),
        );
        let expected = bundled_receipt(
            &self.authority,
            *blake3::hash(frame).as_bytes(),
            operand_digest,
            get_u64(frame, 32),
            rows,
            *blake3::hash(result).as_bytes(),
        );
        if expected.ct_eq(candidate).unwrap_u8() != 1 {
            return Err(ProtocolError::ReceiptMismatch);
        }
        Ok(())
    }
}

impl ServerSession {
    #[allow(clippy::too_many_arguments)]
    pub fn register_operand_bundle<R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        registry: &GraphRegistry,
        layout: &OperandLayout,
        store: &mut OperandBundleStore,
        replay: &mut R,
        clock: &C,
    ) -> Result<BundleAccepted, ProtocolError> {
        let now = clock.now_unix_us()?;
        let request = authenticate_registration(&self.authority, frame)?;
        store.authorise(&self.authority)?;
        if request.expiry_unix_us <= now || request.expiry_unix_us > self.authority.expires_unix_us
        {
            return Err(ProtocolError::Expired);
        }
        let previous_nonce = next_nonce(replay, &self.authority, request.nonce)?;
        let graph = validate_graph(registry, &self.authority, request.operation, layout)?;
        if request.bundle_slot_count != layout.slot_count(OperandStorage::Bundle)
            || request.values.len() > graph.maximum_parameter_bytes() as usize
        {
            return Err(ProtocolError::OperandValueInvalid);
        }
        layout.validate_values(OperandStorage::Bundle, request.values)?;
        if store.bundles.contains_key(&request.bundle_handle)
            || store.retired.contains(&request.bundle_handle)
        {
            return Err(ProtocolError::OperandBundleCollision);
        }
        let next_total = store
            .total_bytes
            .checked_add(request.values.len())
            .ok_or(ProtocolError::OperandBundleLimitExceeded)?;
        if store.bundles.len() >= store.maximum_bundles
            || request.values.len() > store.maximum_bundle_bytes
            || next_total > store.maximum_total_bytes
        {
            return Err(ProtocolError::OperandBundleLimitExceeded);
        }
        let digest = bundle_digest(
            &self.authority,
            request.operation.graph_handle,
            layout.digest(),
            request.bundle_handle,
            request.expiry_unix_us,
            request.values,
        );
        let mut values = Vec::new();
        values
            .try_reserve_exact(request.values.len())
            .map_err(|_| ProtocolError::OperandBundleLimitExceeded)?;
        values.extend_from_slice(request.values);
        let stored = StoredBundle {
            session: self.authority.session,
            generation: self.authority.generation,
            context_digest: self.authority.context_digest,
            graph_handle: request.operation.graph_handle,
            result_shape: request.operation.result_shape,
            schema_digest: layout.digest(),
            expiry_unix_us: request.expiry_unix_us,
            digest,
            values: Zeroizing::new(values),
        };
        if clock.now_unix_us()? >= request.expiry_unix_us {
            return Err(ProtocolError::Expired);
        }
        store
            .bundles
            .try_reserve(1)
            .map_err(|_| ProtocolError::OperandBundleLimitExceeded)?;
        store.bundles.insert(request.bundle_handle, stored);
        if let Err(error) =
            replay.commit(self.authority.replay_key(), previous_nonce, request.nonce)
        {
            store.bundles.remove(&request.bundle_handle);
            return Err(error);
        }
        store.total_bytes = next_total;
        Ok(BundleAccepted {
            bundle_handle: request.bundle_handle,
            graph_handle: request.operation.graph_handle,
            expiry_unix_us: request.expiry_unix_us,
            bundle_digest: digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_bundled_graph<B: BundledGraphBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        registry: &GraphRegistry,
        layout: &OperandLayout,
        store: &mut OperandBundleStore,
        backend: &mut B,
        replay: &mut R,
        clock: &C,
    ) -> Result<BundledGraphExecution, ProtocolError> {
        if frame.len() < BASE_BYTES {
            return Err(ProtocolError::LengthMismatch);
        }
        let result_budget = get_u32(frame, 48);
        let row_budget = get_u32(frame, 52);
        let mut output = BoundedOutput::new_deferred(result_budget, row_budget);
        let (operation, rows, operand_digest, receipt) = self.execute_bundled_graph_into(
            frame,
            registry,
            layout,
            store,
            backend,
            replay,
            clock,
            &mut output,
        )?;
        Ok(BundledGraphExecution {
            operation,
            bytes: output.bytes,
            rows,
            operand_digest,
            receipt,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_bundled_graph_reusing<'a, B: BundledGraphBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        registry: &GraphRegistry,
        layout: &OperandLayout,
        store: &mut OperandBundleStore,
        backend: &mut B,
        replay: &mut R,
        clock: &C,
        result_buffer: &'a mut Vec<u8>,
    ) -> Result<BorrowedBundledGraphExecution<'a>, ProtocolError> {
        if frame.len() < BASE_BYTES {
            return Err(ProtocolError::LengthMismatch);
        }
        let result_budget = get_u32(frame, 48);
        let row_budget = get_u32(frame, 52);
        let reusable = std::mem::take(result_buffer);
        let mut output = BoundedOutput::new_reusing(reusable, result_budget, row_budget);
        let result = self.execute_bundled_graph_into(
            frame,
            registry,
            layout,
            store,
            backend,
            replay,
            clock,
            &mut output,
        );
        *result_buffer = output.bytes;
        let (operation, rows, operand_digest, receipt) = result?;
        Ok(BorrowedBundledGraphExecution {
            operation,
            bytes: result_buffer.as_slice(),
            rows,
            operand_digest,
            receipt,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_bundled_graph_into<B: BundledGraphBackend, R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        registry: &GraphRegistry,
        layout: &OperandLayout,
        store: &mut OperandBundleStore,
        backend: &mut B,
        replay: &mut R,
        clock: &C,
        output: &mut BoundedOutput,
    ) -> Result<(GraphOperation, u32, [u8; 32], [u8; 32]), ProtocolError> {
        let now = clock.now_unix_us()?;
        let request = authenticate_execution(&self.authority, frame)?;
        store.authorise(&self.authority)?;
        if request.deadline_unix_us <= now
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
        let graph = validate_graph(registry, &self.authority, request.operation, layout)?;
        if request.result_budget > graph.maximum_result_bytes()
            || request.row_budget > graph.maximum_rows()
        {
            return Err(ProtocolError::PlanLimitExceeded);
        }
        validate_backend(backend, &self.authority, request.deadline_unix_us)?;
        if request.execution_slot_count != layout.slot_count(OperandStorage::Execution) {
            return Err(ProtocolError::OperandValueInvalid);
        }
        let execution_values = layout.validate_values(OperandStorage::Execution, request.values)?;
        if store
            .bundles
            .get(&request.bundle_handle)
            .is_some_and(|bundle| bundle.expiry_unix_us <= now)
        {
            store.evict(request.bundle_handle)?;
            return Err(ProtocolError::OperandBundleNotFound);
        }
        let bundle = store
            .bundles
            .get(&request.bundle_handle)
            .ok_or(ProtocolError::OperandBundleNotFound)?;
        if bundle.session != self.authority.session
            || bundle.generation != self.authority.generation
            || bundle.context_digest != self.authority.context_digest
        {
            return Err(ProtocolError::AuthorityMismatch);
        }
        if bundle.graph_handle != request.operation.graph_handle
            || bundle.result_shape != request.operation.result_shape
            || bundle.schema_digest != layout.digest()
        {
            return Err(ProtocolError::PlanShapeMismatch);
        }
        let parameter_bytes = bundle
            .values
            .len()
            .checked_add(request.values.len())
            .ok_or(ProtocolError::ParameterLimitExceeded)?;
        if parameter_bytes > graph.maximum_parameter_bytes() as usize {
            return Err(ProtocolError::ParameterLimitExceeded);
        }
        let limits = ExecutionLimits {
            admitted_unix_us: now,
            deadline_unix_us: request.deadline_unix_us,
            maximum_result_bytes: request.result_budget,
            maximum_rows: request.row_budget,
        };
        // Registration validated and copied these immutable records.
        // The schema-digest check above proves that this execution uses the same layout.
        // Rescanning the static records would repeat work proportional to the bundle size.
        let bundle_values = OperandValues {
            records: &bundle.values,
        };
        let operand_digest = effective_operand_digest(
            bundle.digest,
            execution_value_digest(layout.digest(), request.values),
        );
        backend.execute_bundled_graph(
            request.operation,
            BundledOperandContext {
                bundle_handle: request.bundle_handle,
                bundle_expiry_unix_us: bundle.expiry_unix_us,
                bundle_digest: bundle.digest,
            },
            bundle_values,
            execution_values,
            limits,
            output,
        )?;
        if clock.now_unix_us()? >= request.deadline_unix_us {
            return Err(ProtocolError::ExpiredDuringExecution);
        }
        replay.commit(self.authority.replay_key(), previous_nonce, request.nonce)?;
        let receipt = bundled_receipt(
            &self.authority,
            *blake3::hash(frame).as_bytes(),
            operand_digest,
            request.nonce,
            output.rows,
            *blake3::hash(&output.bytes).as_bytes(),
        );
        Ok((request.operation, output.rows, operand_digest, receipt))
    }

    pub fn remove_operand_bundle<R: ReplayStore, C: Clock>(
        &self,
        frame: &[u8],
        registry: &GraphRegistry,
        store: &mut OperandBundleStore,
        replay: &mut R,
        clock: &C,
    ) -> Result<BundleRemoved, ProtocolError> {
        let now = clock.now_unix_us()?;
        let request = authenticate_removal(&self.authority, frame)?;
        store.authorise(&self.authority)?;
        if request.deadline_unix_us <= now
            || request.deadline_unix_us > self.authority.expires_unix_us
        {
            return Err(ProtocolError::Expired);
        }
        let previous_nonce = next_nonce(replay, &self.authority, request.nonce)?;
        let graph = registry
            .graph(request.operation.graph_handle)
            .ok_or(ProtocolError::PlanNotRegistered)?;
        if registry.identity() != self.authority.context.backend() {
            return Err(ProtocolError::PlanRegistryMismatch);
        }
        if graph.opcode() != request.operation.opcode
            || graph.result_shape() != request.operation.result_shape
        {
            return Err(ProtocolError::PlanShapeMismatch);
        }
        let bundle = store
            .bundles
            .remove(&request.bundle_handle)
            .ok_or(ProtocolError::OperandBundleNotFound)?;
        if bundle.session != self.authority.session
            || bundle.generation != self.authority.generation
            || bundle.graph_handle != request.operation.graph_handle
            || bundle.result_shape != request.operation.result_shape
            || bundle.context_digest != self.authority.context_digest
        {
            store.bundles.insert(request.bundle_handle, bundle);
            return Err(ProtocolError::AuthorityMismatch);
        }
        let next_total = store
            .total_bytes
            .checked_sub(bundle.values.len())
            .ok_or(ProtocolError::OperandBundleLimitExceeded)?;
        store.retired.insert(request.bundle_handle);
        if let Err(error) =
            replay.commit(self.authority.replay_key(), previous_nonce, request.nonce)
        {
            store.retired.remove(&request.bundle_handle);
            store.bundles.insert(request.bundle_handle, bundle);
            return Err(error);
        }
        store.total_bytes = next_total;
        Ok(BundleRemoved {
            bundle_handle: request.bundle_handle,
            graph_handle: request.operation.graph_handle,
        })
    }
}

#[derive(Debug)]
pub struct BundledGraphExecution {
    pub operation: GraphOperation,
    pub bytes: Vec<u8>,
    pub rows: u32,
    pub operand_digest: [u8; 32],
    pub receipt: [u8; 32],
}

#[derive(Debug)]
pub struct BorrowedBundledGraphExecution<'a> {
    pub operation: GraphOperation,
    pub bytes: &'a [u8],
    pub rows: u32,
    pub operand_digest: [u8; 32],
    pub receipt: [u8; 32],
}

struct AuthenticatedRegistration<'a> {
    nonce: u64,
    expiry_unix_us: u64,
    operation: GraphOperation,
    bundle_handle: u32,
    bundle_slot_count: u32,
    values: &'a [u8],
}

struct AuthenticatedExecution<'a> {
    nonce: u64,
    deadline_unix_us: u64,
    result_budget: u32,
    row_budget: u32,
    operation: GraphOperation,
    bundle_handle: u32,
    execution_slot_count: u32,
    values: &'a [u8],
}

struct AuthenticatedRemoval {
    nonce: u64,
    deadline_unix_us: u64,
    operation: GraphOperation,
    bundle_handle: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BundleControlKind {
    Registration,
    Removal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BundleControlMetadata {
    pub kind: BundleControlKind,
    pub nonce: u64,
    pub graph_handle: u32,
    pub result_shape: u32,
    pub bundle_handle: u32,
    pub expiry_unix_us: Option<u64>,
}

pub(crate) fn authenticate_bundle_control(
    authority: &Authority,
    frame: &[u8],
) -> Result<BundleControlMetadata, ProtocolError> {
    match frame.get(6).copied() {
        Some(REGISTER_BUNDLE) => {
            let request = authenticate_registration(authority, frame)?;
            if request.expiry_unix_us == 0 || request.expiry_unix_us > authority.expires_unix_us {
                return Err(ProtocolError::DeadlineBeyondAuthority);
            }
            Ok(BundleControlMetadata {
                kind: BundleControlKind::Registration,
                nonce: request.nonce,
                graph_handle: request.operation.graph_handle,
                result_shape: request.operation.result_shape,
                bundle_handle: request.bundle_handle,
                expiry_unix_us: Some(request.expiry_unix_us),
            })
        }
        Some(REMOVE_BUNDLE) => {
            let request = authenticate_removal(authority, frame)?;
            if request.deadline_unix_us == 0 || request.deadline_unix_us > authority.expires_unix_us
            {
                return Err(ProtocolError::DeadlineBeyondAuthority);
            }
            Ok(BundleControlMetadata {
                kind: BundleControlKind::Removal,
                nonce: request.nonce,
                graph_handle: request.operation.graph_handle,
                result_shape: request.operation.result_shape,
                bundle_handle: request.bundle_handle,
                expiry_unix_us: None,
            })
        }
        _ => Err(ProtocolError::UnsupportedFrame),
    }
}

fn authenticate_registration<'a>(
    authority: &Authority,
    frame: &'a [u8],
) -> Result<AuthenticatedRegistration<'a>, ProtocolError> {
    authenticate_common(authority, frame, REGISTER_BUNDLE, REGISTER_FRAME_DOMAIN)?;
    let tag_offset = frame.len() - TAG_BYTES;
    if frame[68..96].iter().any(|byte| *byte != 0)
        || get_u32(frame, 48) as usize != tag_offset - HEADER_BYTES
    {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    Ok(AuthenticatedRegistration {
        nonce: get_u64(frame, 32),
        expiry_unix_us: get_u64(frame, 40),
        operation: graph_operation(frame)?,
        bundle_handle: nonzero_handle(get_u32(frame, 64))?,
        bundle_slot_count: get_u32(frame, 52),
        values: &frame[HEADER_BYTES..tag_offset],
    })
}

fn authenticate_execution<'a>(
    authority: &Authority,
    frame: &'a [u8],
) -> Result<AuthenticatedExecution<'a>, ProtocolError> {
    authenticate_common(authority, frame, EXECUTE_BUNDLE, EXECUTE_FRAME_DOMAIN)?;
    let tag_offset = frame.len() - TAG_BYTES;
    if frame[76..96].iter().any(|byte| *byte != 0)
        || get_u32(frame, 68) as usize != tag_offset - HEADER_BYTES
    {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    Ok(AuthenticatedExecution {
        nonce: get_u64(frame, 32),
        deadline_unix_us: get_u64(frame, 40),
        result_budget: get_u32(frame, 48),
        row_budget: get_u32(frame, 52),
        operation: graph_operation(frame)?,
        bundle_handle: nonzero_handle(get_u32(frame, 64))?,
        execution_slot_count: get_u32(frame, 72),
        values: &frame[HEADER_BYTES..tag_offset],
    })
}

fn authenticate_removal(
    authority: &Authority,
    frame: &[u8],
) -> Result<AuthenticatedRemoval, ProtocolError> {
    authenticate_common(authority, frame, REMOVE_BUNDLE, REMOVE_FRAME_DOMAIN)?;
    if frame.len() != BASE_BYTES
        || frame[48..56].iter().any(|byte| *byte != 0)
        || frame[68..96].iter().any(|byte| *byte != 0)
    {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    Ok(AuthenticatedRemoval {
        nonce: get_u64(frame, 32),
        deadline_unix_us: get_u64(frame, 40),
        operation: graph_operation(frame)?,
        bundle_handle: nonzero_handle(get_u32(frame, 64))?,
    })
}

fn authenticate_common(
    authority: &Authority,
    frame: &[u8],
    kind: u8,
    domain: &[u8],
) -> Result<(), ProtocolError> {
    if frame.len() < BASE_BYTES || frame.len() > BASE_BYTES + MAX_GRAPH_PARAMETER_BYTES {
        return Err(ProtocolError::LengthMismatch);
    }
    let tag_offset = frame.len() - TAG_BYTES;
    let expected = authority.tag_for(domain, &frame[..tag_offset]);
    if expected.ct_eq(&frame[tag_offset..]).unwrap_u8() != 1 {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if frame[0..4] != MAGIC
        || frame[4] != VERSION_MAJOR
        || frame[5] != VERSION_MINOR
        || frame[6] != kind
        || frame[7] != READ_ACCESS
    {
        return Err(ProtocolError::UnsupportedFrame);
    }
    if get_u16(frame, 8) != 0 || get_u32(frame, 12) as usize != frame.len() {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    if get_u64(frame, 16) != authority.session
        || get_u64(frame, 24) != authority.generation
        || frame[96..128] != authority.context_digest
    {
        return Err(ProtocolError::AuthorityMismatch);
    }
    Ok(())
}

fn graph_operation(frame: &[u8]) -> Result<GraphOperation, ProtocolError> {
    GraphOperation::new(get_u16(frame, 10), get_u32(frame, 56), get_u32(frame, 60))
}

fn nonzero_handle(handle: u32) -> Result<u32, ProtocolError> {
    if handle == 0 {
        Err(ProtocolError::ZeroOperationField)
    } else {
        Ok(handle)
    }
}

fn validate_operation(operation: GraphOperation) -> Result<(), ProtocolError> {
    GraphOperation::new(
        operation.opcode,
        operation.graph_handle,
        operation.result_shape,
    )?;
    Ok(())
}

fn allocate_frame(payload_bytes: usize) -> Result<Vec<u8>, ProtocolError> {
    let length = operand_bundle_frame_bytes(payload_bytes)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(length)
        .map_err(|_| ProtocolError::ParameterLimitExceeded)?;
    frame.resize(length, 0);
    Ok(frame)
}

fn initialise_header(
    frame: &mut [u8],
    kind: u8,
    operation: GraphOperation,
    authority: &Authority,
    nonce: u64,
    deadline_or_expiry: u64,
) -> Result<(), ProtocolError> {
    frame[0..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION_MAJOR;
    frame[5] = VERSION_MINOR;
    frame[6] = kind;
    frame[7] = READ_ACCESS;
    put_u16(frame, 8, 0);
    put_u16(frame, 10, operation.opcode);
    put_u32(frame, 12, to_u32(frame.len())?);
    put_u64(frame, 16, authority.session);
    put_u64(frame, 24, authority.generation);
    put_u64(frame, 32, nonce);
    put_u64(frame, 40, deadline_or_expiry);
    put_u32(frame, 56, operation.graph_handle);
    put_u32(frame, 60, operation.result_shape);
    frame[96..128].copy_from_slice(&authority.context_digest);
    Ok(())
}

fn finish_frame(frame: &mut [u8], records: &[u8], authority: &Authority, domain: &[u8]) {
    let tag_offset = frame.len() - TAG_BYTES;
    frame[HEADER_BYTES..tag_offset].copy_from_slice(records);
    let tag = authority.tag_for(domain, &frame[..tag_offset]);
    frame[tag_offset..].copy_from_slice(&tag);
}

fn validate_graph<'a>(
    registry: &'a GraphRegistry,
    authority: &Authority,
    operation: GraphOperation,
    layout: &OperandLayout,
) -> Result<&'a super::graph::RegisteredGraph, ProtocolError> {
    if registry.identity() != authority.context.backend() {
        return Err(ProtocolError::PlanRegistryMismatch);
    }
    let graph = registry
        .graph(operation.graph_handle)
        .ok_or(ProtocolError::PlanNotRegistered)?;
    if graph.opcode() != operation.opcode || graph.result_shape() != operation.result_shape {
        return Err(ProtocolError::PlanShapeMismatch);
    }
    if graph.parameter_schema_digest() != layout.digest() {
        return Err(ProtocolError::PlanShapeMismatch);
    }
    if layout.maximum_record_bytes() > graph.maximum_parameter_bytes() {
        return Err(ProtocolError::PlanLimitExceeded);
    }
    Ok(graph)
}

fn validate_backend<B: BundledGraphBackend>(
    backend: &B,
    authority: &Authority,
    deadline_unix_us: u64,
) -> Result<(), ProtocolError> {
    if backend.identity() != authority.context.backend() {
        return Err(ProtocolError::BackendIdentityMismatch);
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

fn next_nonce<R: ReplayStore>(
    replay: &R,
    authority: &Authority,
    nonce: u64,
) -> Result<u64, ProtocolError> {
    let previous = replay.last_nonce(authority.replay_key())?;
    if nonce != previous.checked_add(1).ok_or(ProtocolError::NonceEnded)? {
        return Err(ProtocolError::Replay);
    }
    Ok(previous)
}

fn bundle_digest(
    authority: &Authority,
    graph_handle: u32,
    schema_digest: [u8; 32],
    bundle_handle: u32,
    expiry_unix_us: u64,
    values: &[u8],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(BUNDLE_DOMAIN);
    digest.update(&authority.context_digest);
    digest.update(&graph_handle.to_le_bytes());
    digest.update(&schema_digest);
    digest.update(&bundle_handle.to_le_bytes());
    digest.update(&expiry_unix_us.to_le_bytes());
    digest.update(values);
    *digest.finalize().as_bytes()
}

fn execution_value_digest(schema_digest: [u8; 32], values: &[u8]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(EXECUTION_VALUES_DOMAIN);
    digest.update(&schema_digest);
    digest.update(values);
    *digest.finalize().as_bytes()
}

fn effective_operand_digest(bundle: [u8; 32], execution: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(EFFECTIVE_OPERANDS_DOMAIN);
    digest.update(&bundle);
    digest.update(&execution);
    *digest.finalize().as_bytes()
}

fn bundled_receipt(
    authority: &Authority,
    request_digest: [u8; 32],
    operand_digest: [u8; 32],
    nonce: u64,
    rows: u32,
    result_digest: [u8; 32],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_keyed(&authority.receipt_key);
    digest.update(RECEIPT_DOMAIN);
    digest.update(&authority.context_digest);
    digest.update(&request_digest);
    digest.update(&operand_digest);
    digest.update(&nonce.to_le_bytes());
    digest.update(&rows.to_le_bytes());
    digest.update(&result_digest);
    let output = *digest.finalize().as_bytes();
    digest.zeroize();
    output
}

fn to_u32(value: usize) -> Result<u32, ProtocolError> {
    u32::try_from(value).map_err(|_| ProtocolError::LengthMismatch)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::{
        digest_label, AuthorityContext, CapabilityManifest, GraphNode, MemoryReplayStore,
        RegisteredGraph, SingleSessionReplayStore, CAPABILITY_GRAPH, CAPABILITY_QUERY,
    };

    const NOW: u64 = 1_000_000;
    const DEADLINE: u64 = 2_000_000;

    struct TestClock {
        calls: Cell<u32>,
    }

    impl Clock for TestClock {
        fn now_unix_us(&self) -> Result<u64, ProtocolError> {
            self.calls.set(self.calls.get() + 1);
            Ok(NOW)
        }
    }

    fn clock() -> TestClock {
        TestClock {
            calls: Cell::new(0),
        }
    }

    fn layout() -> OperandLayout {
        OperandLayout::new([
            OperandSlot::new(1, OperandStorage::Bundle, OperandType::Bytes, false, 16)
                .expect("bundle slot"),
            OperandSlot::new(2, OperandStorage::Execution, OperandType::I64, false, 8)
                .expect("execution slot"),
        ])
        .expect("layout")
    }

    fn registry(layout: &OperandLayout) -> GraphRegistry {
        let graph = RegisteredGraph::new_read(
            11,
            17,
            13,
            256,
            256,
            4,
            CAPABILITY_QUERY | CAPABILITY_GRAPH,
            layout.digest(),
            digest_label(b"implementation", b"bundle-test"),
            [
                GraphNode::new(19, 23, []).expect("first node"),
                GraphNode::new(29, 31, [0]).expect("second node"),
            ],
        )
        .expect("graph");
        GraphRegistry::new(
            37,
            41,
            digest_label(b"schema", b"bundle-test"),
            digest_label(b"policy", b"read-only"),
            CapabilityManifest::new(CAPABILITY_QUERY | CAPABILITY_GRAPH).expect("manifest"),
            [graph],
        )
        .expect("registry")
    }

    fn authority_with_session(registry: &GraphRegistry, session: u64) -> Authority {
        let context = AuthorityContext::new(
            [43; 16],
            [47; 16],
            53,
            digest_label(b"capability", b"bundle-test"),
            registry.identity(),
        )
        .expect("context");
        Authority::new_read([59; 32], 61, session, DEADLINE, context).expect("authority")
    }

    fn authority(registry: &GraphRegistry) -> Authority {
        authority_with_session(registry, 67)
    }

    fn operation() -> GraphOperation {
        GraphOperation::new(11, 17, 13).expect("operation")
    }

    struct TestBackend {
        identity: BackendIdentity,
        calls: u32,
    }

    impl BundledGraphBackend for TestBackend {
        fn identity(&self) -> BackendIdentity {
            self.identity
        }

        fn execute_bundled_graph(
            &mut self,
            _operation: GraphOperation,
            _bundle_context: BundledOperandContext,
            bundle_values: OperandValues<'_>,
            execution_values: OperandValues<'_>,
            _limits: ExecutionLimits,
            output: &mut BoundedOutput,
        ) -> Result<(), ProtocolError> {
            self.calls += 1;
            for value in bundle_values.iter().chain(execution_values.iter()) {
                output.write(value.value.ok_or(ProtocolError::OperandValueInvalid)?)?;
            }
            output.complete_row()
        }
    }

    #[test]
    fn a_bundle_registers_executes_verifies_and_removes() {
        let layout = layout();
        let registry = registry(&layout);
        let authority = authority(&registry);
        let mut client = ClientSession::new(authority.clone());
        let mut store = OperandBundleStore::new(&authority, 4, 1_024, 256).expect("store");
        let server = ServerSession::new(authority, 256, 4).expect("server");
        let mut replay = MemoryReplayStore::default();
        let clock = clock();
        let registration = client
            .encode_operand_bundle_registration(
                operation(),
                &layout,
                71,
                DEADLINE,
                &[OperandValue {
                    slot_id: 1,
                    value: Some(b"static"),
                }],
            )
            .expect("registration");
        let accepted = server
            .register_operand_bundle(
                &registration,
                &registry,
                &layout,
                &mut store,
                &mut replay,
                &clock,
            )
            .expect("accepted bundle");
        assert_eq!(accepted.bundle_handle, 71);
        assert_eq!(store.len(), 1);

        let dynamic = 73_i64.to_le_bytes();
        let execution_frame = client
            .encode_bundled_graph(
                operation(),
                &layout,
                71,
                &[OperandValue {
                    slot_id: 2,
                    value: Some(&dynamic),
                }],
                256,
                4,
                DEADLINE,
            )
            .expect("execution frame");
        let mut backend = TestBackend {
            identity: registry.identity(),
            calls: 0,
        };
        let execution = server
            .execute_bundled_graph(
                &execution_frame,
                &registry,
                &layout,
                &mut store,
                &mut backend,
                &mut replay,
                &clock,
            )
            .expect("execution");
        assert_eq!(backend.calls, 1);
        assert_eq!(&execution.bytes[..6], b"static");
        assert_eq!(&execution.bytes[6..], &dynamic);
        client
            .verify_bundled_execution_receipt(
                &execution_frame,
                accepted.bundle_digest,
                layout.digest(),
                execution.rows,
                &execution.bytes,
                &execution.receipt,
            )
            .expect("receipt");
        let mut changed_receipt = execution.receipt;
        changed_receipt[0] ^= 1;
        assert_eq!(
            client
                .verify_bundled_execution_receipt(
                    &execution_frame,
                    accepted.bundle_digest,
                    layout.digest(),
                    execution.rows,
                    &execution.bytes,
                    &changed_receipt,
                )
                .expect_err("changed receipt"),
            ProtocolError::ReceiptMismatch,
        );

        let removal = client
            .encode_operand_bundle_removal(operation(), 71, DEADLINE)
            .expect("removal");
        server
            .remove_operand_bundle(&removal, &registry, &mut store, &mut replay, &clock)
            .expect("removed bundle");
        assert!(store.is_empty());
        assert!(store.retired.contains(&71));
    }

    #[test]
    fn a_prepared_bundle_reuses_request_and_result_storage() {
        let layout = layout();
        let registry = registry(&layout);
        let authority = authority(&registry);
        let mut client = ClientSession::new(authority.clone());
        let mut store = OperandBundleStore::new(&authority, 1, 1_024, 256).expect("store");
        let server = ServerSession::new(authority, 256, 4).expect("server");
        let mut replay = SingleSessionReplayStore::default();
        let mut empty_result = Vec::new();
        let mut refusing_backend = TestBackend {
            identity: registry.identity(),
            calls: 0,
        };
        assert_eq!(
            server
                .execute_bundled_graph_reusing(
                    &[],
                    &registry,
                    &layout,
                    &mut store,
                    &mut refusing_backend,
                    &mut replay,
                    &clock(),
                    &mut empty_result,
                )
                .expect_err("short frame"),
            ProtocolError::LengthMismatch,
        );
        let registration = client
            .encode_operand_bundle_registration(
                operation(),
                &layout,
                71,
                DEADLINE,
                &[OperandValue {
                    slot_id: 1,
                    value: Some(b"static"),
                }],
            )
            .expect("registration");
        let accepted = server
            .register_operand_bundle(
                &registration,
                &registry,
                &layout,
                &mut store,
                &mut replay,
                &clock(),
            )
            .expect("accepted bundle");
        let dynamic = 73_i64.to_le_bytes();
        let mut prepared = client
            .prepare_bundled_graph_frame(
                operation(),
                &layout,
                accepted.bundle_handle,
                &[OperandValue {
                    slot_id: 2,
                    value: Some(&dynamic),
                }],
                256,
                4,
            )
            .expect("prepared frame");
        let mut backend = TestBackend {
            identity: registry.identity(),
            calls: 0,
        };
        let mut result = Vec::with_capacity(256);
        let result_pointer = result.as_ptr();
        let request_pointer = prepared.as_bytes().as_ptr();

        for _ in 0..2 {
            let frame = client
                .encode_prepared_bundled_graph(&mut prepared, DEADLINE)
                .expect("signed frame");
            let execution = server
                .execute_bundled_graph_reusing(
                    frame,
                    &registry,
                    &layout,
                    &mut store,
                    &mut backend,
                    &mut replay,
                    &clock(),
                    &mut result,
                )
                .expect("execution");
            client
                .verify_bundled_execution_receipt(
                    frame,
                    accepted.bundle_digest,
                    layout.digest(),
                    execution.rows,
                    execution.bytes,
                    &execution.receipt,
                )
                .expect("receipt");
        }

        assert_eq!(backend.calls, 2);
        assert_eq!(prepared.as_bytes().as_ptr(), request_pointer);
        assert_eq!(result.as_ptr(), result_pointer);
    }

    #[test]
    fn a_changed_registration_fails_before_storage_and_replay() {
        let layout = layout();
        let registry = registry(&layout);
        let authority = authority(&registry);
        let mut client = ClientSession::new(authority.clone());
        let mut store = OperandBundleStore::new(&authority, 4, 1_024, 256).expect("store");
        let server = ServerSession::new(authority, 256, 4).expect("server");
        let mut frame = client
            .encode_operand_bundle_registration(
                operation(),
                &layout,
                71,
                DEADLINE,
                &[OperandValue {
                    slot_id: 1,
                    value: Some(b"static"),
                }],
            )
            .expect("registration");
        frame[HEADER_BYTES + 8] ^= 1;
        let mut replay = MemoryReplayStore::default();

        assert_eq!(
            server
                .register_operand_bundle(
                    &frame,
                    &registry,
                    &layout,
                    &mut store,
                    &mut replay,
                    &clock(),
                )
                .expect_err("changed frame"),
            ProtocolError::AuthenticationFailed,
        );
        assert!(store.is_empty());
        assert_eq!(
            replay
                .last_nonce(server.authority.replay_key())
                .expect("nonce"),
            0
        );
    }

    #[test]
    fn canonical_values_refuse_order_type_width_and_null_drift() {
        let layout = layout();
        let wrong_slot = layout.encode_values(
            OperandStorage::Bundle,
            &[OperandValue {
                slot_id: 2,
                value: Some(b"static"),
            }],
        );
        assert_eq!(
            wrong_slot.expect_err("slot order"),
            ProtocolError::NonCanonicalFrame
        );

        let short = [1_u8; 7];
        let wrong_width = layout.encode_values(
            OperandStorage::Execution,
            &[OperandValue {
                slot_id: 2,
                value: Some(&short),
            }],
        );
        assert_eq!(
            wrong_width.expect_err("fixed width"),
            ProtocolError::OperandValueInvalid,
        );
        let null = layout.encode_values(
            OperandStorage::Bundle,
            &[OperandValue {
                slot_id: 1,
                value: None,
            }],
        );
        assert_eq!(
            null.expect_err("non-nullable"),
            ProtocolError::OperandValueInvalid,
        );
    }

    #[test]
    fn a_bundle_store_refuses_another_authority_session() {
        let layout = layout();
        let registry = registry(&layout);
        let original = authority_with_session(&registry, 67);
        let changed = authority_with_session(&registry, 68);
        let mut store = OperandBundleStore::new(&original, 4, 1_024, 256).expect("store");
        let mut client = ClientSession::new(changed.clone());
        let server = ServerSession::new(changed, 256, 4).expect("server");
        let registration = client
            .encode_operand_bundle_registration(
                operation(),
                &layout,
                71,
                DEADLINE,
                &[OperandValue {
                    slot_id: 1,
                    value: Some(b"static"),
                }],
            )
            .expect("registration");
        let mut replay = MemoryReplayStore::default();

        assert_eq!(
            server
                .register_operand_bundle(
                    &registration,
                    &registry,
                    &layout,
                    &mut store,
                    &mut replay,
                    &clock(),
                )
                .expect_err("session drift"),
            ProtocolError::AuthorityMismatch,
        );
        assert!(store.is_empty());
    }
}
