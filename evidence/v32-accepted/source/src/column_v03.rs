//! Define the homogeneous column-batch profile for NDABI core version 1.2.
//!
//! One descriptor replaces repeated operation records for one prepared plan.
//! The verifier authenticates and validates a borrowed parameter column without allocation.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: [u8; 4] = *b"NDBI";
const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 2;
const KIND_COLUMN_BATCH: u8 = 4;
const HEADER_BYTES: usize = 96;
const TAG_BYTES: usize = 16;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 4_096;
const MAX_ROW_BYTES: usize = 4_096;
const MAC_DOMAIN: &[u8] = b"ndabi-core-v1.2-column-batch";

pub const FRAME_ATOMIC: u8 = 1 << 0;
pub const FRAME_ALLOW_PARTIAL: u8 = 1 << 1;
const FRAME_FLAG_MASK: u8 = FRAME_ATOMIC | FRAME_ALLOW_PARTIAL;

pub const OPERATION_READ: u16 = 1 << 0;
pub const OPERATION_WRITE: u16 = 1 << 1;
pub const OPERATION_IDEMPOTENT: u16 = 1 << 2;
const OPERATION_FLAG_MASK: u16 = OPERATION_READ | OPERATION_WRITE | OPERATION_IDEMPOTENT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColumnBinding {
    pub session_handle: u32,
    pub capability_handle: u32,
    pub schema_handle: u32,
    pub generation: u64,
    key: [u8; 32],
}

impl ColumnBinding {
    pub fn new(
        session_handle: u32,
        capability_handle: u32,
        schema_handle: u32,
        generation: u64,
        key: [u8; 32],
    ) -> Result<Self, ColumnError> {
        if session_handle == 0 || capability_handle == 0 || schema_handle == 0 || generation == 0 {
            return Err(ColumnError::ZeroBinding);
        }
        Ok(Self {
            session_handle,
            capability_handle,
            schema_handle,
            generation,
            key,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnBatchFrame {
    pub flags: u8,
    pub session_handle: u32,
    pub capability_handle: u32,
    pub schema_handle: u32,
    pub generation: u64,
    pub nonce: u64,
    pub deadline_unix_us: u64,
    pub result_budget: u32,
    pub plan_handle: u32,
    pub result_shape: u32,
    pub transaction_group: u32,
    pub operation_flags: u16,
    pub rows: u16,
    pub columns: u16,
    pub row_bytes: u16,
    pub parameters: Vec<u8>,
}

impl ColumnBatchFrame {
    pub fn encode(&self, binding: &ColumnBinding) -> Result<Vec<u8>, ColumnError> {
        validate_fields(self)?;
        if self.session_handle != binding.session_handle
            || self.capability_handle != binding.capability_handle
            || self.schema_handle != binding.schema_handle
        {
            return Err(ColumnError::BindingMismatch);
        }
        if self.generation != binding.generation {
            return Err(ColumnError::GenerationMismatch);
        }
        let total_bytes = HEADER_BYTES
            .checked_add(self.parameters.len())
            .ok_or(ColumnError::Bounds)?;
        if total_bytes > MAX_FRAME_BYTES {
            return Err(ColumnError::Bounds);
        }
        let mut bytes = vec![0u8; total_bytes];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = VERSION_MAJOR;
        bytes[5] = VERSION_MINOR;
        bytes[6] = KIND_COLUMN_BATCH;
        bytes[7] = self.flags;
        put_u32(&mut bytes, 8, to_u32(total_bytes)?);
        put_u32(&mut bytes, 12, self.session_handle);
        put_u32(&mut bytes, 16, self.capability_handle);
        put_u32(&mut bytes, 20, self.schema_handle);
        put_u16(&mut bytes, 24, self.rows);
        put_u16(&mut bytes, 26, self.columns);
        put_u64(&mut bytes, 28, self.generation);
        put_u64(&mut bytes, 36, self.nonce);
        put_u64(&mut bytes, 44, self.deadline_unix_us);
        put_u32(&mut bytes, 52, self.result_budget);
        put_u32(&mut bytes, 56, self.plan_handle);
        put_u32(&mut bytes, 60, self.result_shape);
        put_u32(&mut bytes, 64, self.transaction_group);
        put_u16(&mut bytes, 68, self.operation_flags);
        put_u16(&mut bytes, 70, self.row_bytes);
        put_u32(&mut bytes, 72, to_u32(self.parameters.len())?);
        bytes[HEADER_BYTES..].copy_from_slice(&self.parameters);
        apply_tag(&mut bytes, &binding.key);
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColumnBatchView<'a> {
    rows: usize,
    columns: u16,
    row_bytes: usize,
    result_budget: u32,
    plan_handle: u32,
    result_shape: u32,
    transaction_group: u32,
    operation_flags: u16,
    nonce: u64,
    deadline_unix_us: u64,
    parameters: &'a [u8],
}

impl<'a> ColumnBatchView<'a> {
    pub fn rows(self) -> usize {
        self.rows
    }

    pub fn columns(self) -> u16 {
        self.columns
    }

    pub fn row_bytes(self) -> usize {
        self.row_bytes
    }

    pub fn result_budget(self) -> u32 {
        self.result_budget
    }

    pub fn plan_handle(self) -> u32 {
        self.plan_handle
    }

    pub fn result_shape(self) -> u32 {
        self.result_shape
    }

    pub fn transaction_group(self) -> u32 {
        self.transaction_group
    }

    pub fn operation_flags(self) -> u16 {
        self.operation_flags
    }

    pub fn parameters(self) -> &'a [u8] {
        self.parameters
    }

    pub fn row(self, index: usize) -> Result<&'a [u8], ColumnError> {
        if index >= self.rows {
            return Err(ColumnError::Bounds);
        }
        let start = index
            .checked_mul(self.row_bytes)
            .ok_or(ColumnError::Bounds)?;
        Ok(&self.parameters[start..start + self.row_bytes])
    }
}

pub struct ColumnVerifier {
    binding: ColumnBinding,
    last_nonce: u64,
}

impl ColumnVerifier {
    pub fn new(binding: ColumnBinding) -> Self {
        Self {
            binding,
            last_nonce: 0,
        }
    }

    pub fn verify<'a>(&mut self, bytes: &'a [u8]) -> Result<ColumnBatchView<'a>, ColumnError> {
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ColumnError::Expired)?
            .as_micros();
        self.verify_at(bytes, u64::try_from(now_us).unwrap_or(u64::MAX))
    }

    pub fn verify_at<'a>(
        &mut self,
        bytes: &'a [u8],
        now_unix_us: u64,
    ) -> Result<ColumnBatchView<'a>, ColumnError> {
        let view = decode(bytes, &self.binding)?;
        if view.deadline_unix_us < now_unix_us {
            return Err(ColumnError::Expired);
        }
        if view.nonce <= self.last_nonce {
            return Err(ColumnError::Replay);
        }
        self.last_nonce = view.nonce;
        Ok(view)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ColumnError {
    AtomicPartialConflict,
    AuthenticationFailed,
    BindingMismatch,
    Bounds,
    Expired,
    GenerationMismatch,
    InvalidFlags,
    InvalidShape,
    InvalidTransactionGroup,
    LengthMismatch,
    Replay,
    ReservedBytes,
    UnsupportedVersion(u8, u8),
    ZeroBinding,
    ZeroBudget,
    ZeroDeadline,
    ZeroHandle,
    ZeroNonce,
}

impl fmt::Display for ColumnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ColumnError {}

fn decode<'a>(
    bytes: &'a [u8],
    binding: &ColumnBinding,
) -> Result<ColumnBatchView<'a>, ColumnError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_FRAME_BYTES {
        return Err(ColumnError::Bounds);
    }
    if bytes[0..4] != MAGIC || bytes[6] != KIND_COLUMN_BATCH {
        return Err(ColumnError::AuthenticationFailed);
    }
    if bytes[4] != VERSION_MAJOR || bytes[5] != VERSION_MINOR {
        return Err(ColumnError::UnsupportedVersion(bytes[4], bytes[5]));
    }
    if to_usize(get_u32(bytes, 8)) != bytes.len()
        || to_usize(get_u32(bytes, 72)) != bytes.len() - HEADER_BYTES
    {
        return Err(ColumnError::LengthMismatch);
    }
    if bytes[76..80] != [0; 4] {
        return Err(ColumnError::ReservedBytes);
    }
    if get_u32(bytes, 12) != binding.session_handle
        || get_u32(bytes, 16) != binding.capability_handle
        || get_u32(bytes, 20) != binding.schema_handle
    {
        return Err(ColumnError::BindingMismatch);
    }
    if get_u64(bytes, 28) != binding.generation {
        return Err(ColumnError::GenerationMismatch);
    }
    if !tag_matches(bytes, &binding.key) {
        return Err(ColumnError::AuthenticationFailed);
    }

    let flags = bytes[7];
    let operation_flags = get_u16(bytes, 68);
    let access = operation_flags & (OPERATION_READ | OPERATION_WRITE);
    if flags & !FRAME_FLAG_MASK != 0
        || operation_flags & !OPERATION_FLAG_MASK != 0
        || (access != OPERATION_READ && access != OPERATION_WRITE)
    {
        return Err(ColumnError::InvalidFlags);
    }
    if flags & FRAME_ATOMIC != 0 && flags & FRAME_ALLOW_PARTIAL != 0 {
        return Err(ColumnError::AtomicPartialConflict);
    }
    let transaction_group = get_u32(bytes, 64);
    if transaction_group != 0 && flags & FRAME_ATOMIC == 0 {
        return Err(ColumnError::InvalidTransactionGroup);
    }
    let rows = usize::from(get_u16(bytes, 24));
    let columns = get_u16(bytes, 26);
    let row_bytes = usize::from(get_u16(bytes, 70));
    let parameters = &bytes[HEADER_BYTES..];
    if !(2..=MAX_ROWS).contains(&rows)
        || columns == 0
        || row_bytes == 0
        || row_bytes > MAX_ROW_BYTES
        || rows.checked_mul(row_bytes) != Some(parameters.len())
    {
        return Err(ColumnError::InvalidShape);
    }
    let plan_handle = get_u32(bytes, 56);
    let result_shape = get_u32(bytes, 60);
    if plan_handle == 0 || result_shape == 0 {
        return Err(ColumnError::ZeroHandle);
    }
    let nonce = get_u64(bytes, 36);
    let deadline_unix_us = get_u64(bytes, 44);
    let result_budget = get_u32(bytes, 52);
    if nonce == 0 {
        return Err(ColumnError::ZeroNonce);
    }
    if deadline_unix_us == 0 {
        return Err(ColumnError::ZeroDeadline);
    }
    if result_budget == 0 {
        return Err(ColumnError::ZeroBudget);
    }
    Ok(ColumnBatchView {
        rows,
        columns,
        row_bytes,
        result_budget,
        plan_handle,
        result_shape,
        transaction_group,
        operation_flags,
        nonce,
        deadline_unix_us,
        parameters,
    })
}

fn validate_fields(frame: &ColumnBatchFrame) -> Result<(), ColumnError> {
    if frame.flags & !FRAME_FLAG_MASK != 0 {
        return Err(ColumnError::InvalidFlags);
    }
    if frame.flags & FRAME_ATOMIC != 0 && frame.flags & FRAME_ALLOW_PARTIAL != 0 {
        return Err(ColumnError::AtomicPartialConflict);
    }
    let access = frame.operation_flags & (OPERATION_READ | OPERATION_WRITE);
    if frame.operation_flags & !OPERATION_FLAG_MASK != 0
        || (access != OPERATION_READ && access != OPERATION_WRITE)
    {
        return Err(ColumnError::InvalidFlags);
    }
    if frame.transaction_group != 0 && frame.flags & FRAME_ATOMIC == 0 {
        return Err(ColumnError::InvalidTransactionGroup);
    }
    if frame.session_handle == 0 || frame.capability_handle == 0 || frame.schema_handle == 0 {
        return Err(ColumnError::ZeroBinding);
    }
    if frame.generation == 0 {
        return Err(ColumnError::GenerationMismatch);
    }
    if frame.nonce == 0 {
        return Err(ColumnError::ZeroNonce);
    }
    if frame.deadline_unix_us == 0 {
        return Err(ColumnError::ZeroDeadline);
    }
    if frame.result_budget == 0 {
        return Err(ColumnError::ZeroBudget);
    }
    if frame.plan_handle == 0 || frame.result_shape == 0 {
        return Err(ColumnError::ZeroHandle);
    }
    let rows = usize::from(frame.rows);
    let row_bytes = usize::from(frame.row_bytes);
    if !(2..=MAX_ROWS).contains(&rows)
        || frame.columns == 0
        || row_bytes == 0
        || row_bytes > MAX_ROW_BYTES
        || rows.checked_mul(row_bytes) != Some(frame.parameters.len())
    {
        return Err(ColumnError::InvalidShape);
    }
    Ok(())
}

fn apply_tag(bytes: &mut [u8], key: &[u8; 32]) {
    let tag = calculate_tag(bytes, key);
    bytes[80..80 + TAG_BYTES].copy_from_slice(&tag);
}

fn tag_matches(bytes: &[u8], key: &[u8; 32]) -> bool {
    let expected = calculate_tag(bytes, key);
    let mut difference = 0u8;
    for (actual, wanted) in bytes[80..80 + TAG_BYTES].iter().zip(expected.iter()) {
        difference |= actual ^ wanted;
    }
    difference == 0
}

fn calculate_tag(bytes: &[u8], key: &[u8; 32]) -> [u8; TAG_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(MAC_DOMAIN);
    hasher.update(&bytes[..80]);
    hasher.update(&bytes[HEADER_BYTES..]);
    let digest = hasher.finalize();
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

fn to_u32(value: usize) -> Result<u32, ColumnError> {
    u32::try_from(value).map_err(|_| ColumnError::Bounds)
}

fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("u32 fits usize on supported targets")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x43; 32];

    fn binding() -> ColumnBinding {
        ColumnBinding::new(7, 11, 13, 17, KEY).expect("valid binding")
    }

    fn frame() -> ColumnBatchFrame {
        ColumnBatchFrame {
            flags: 0,
            session_handle: 7,
            capability_handle: 11,
            schema_handle: 13,
            generation: 17,
            nonce: 19,
            deadline_unix_us: u64::MAX,
            result_budget: 1_024,
            plan_handle: 23,
            result_shape: 29,
            transaction_group: 0,
            operation_flags: OPERATION_READ | OPERATION_IDEMPOTENT,
            rows: 2,
            columns: 1,
            row_bytes: 8,
            parameters: [31i64.to_le_bytes(), 37i64.to_le_bytes()].concat(),
        }
    }

    #[test]
    fn column_batch_round_trips_as_borrowed_rows() {
        let bytes = frame().encode(&binding()).expect("encode column batch");
        let view = ColumnVerifier::new(binding())
            .verify(&bytes)
            .expect("verify column batch");
        assert_eq!(view.rows(), 2);
        assert_eq!(view.columns(), 1);
        assert_eq!(view.row_bytes(), 8);
        assert_eq!(view.row(0).expect("first row"), 31i64.to_le_bytes());
        assert_eq!(view.row(1).expect("second row"), 37i64.to_le_bytes());
    }

    #[test]
    fn every_authenticated_byte_is_bound() {
        let bytes = frame().encode(&binding()).expect("encode column batch");
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(
                ColumnVerifier::new(binding()).verify(&changed).is_err(),
                "accepted byte {index}"
            );
        }
    }

    #[test]
    fn replay_and_expiry_fail_without_advancing_invalid_state() {
        let mut expected = frame();
        expected.deadline_unix_us = 20;
        let expired = expected.encode(&binding()).expect("encode expired frame");
        expected.deadline_unix_us = 40;
        let current = expected.encode(&binding()).expect("encode current frame");
        let mut verifier = ColumnVerifier::new(binding());
        assert_eq!(verifier.verify_at(&expired, 30), Err(ColumnError::Expired));
        assert!(verifier.verify_at(&current, 30).is_ok());
        assert_eq!(verifier.verify_at(&current, 30), Err(ColumnError::Replay));
    }

    #[test]
    fn transaction_groups_require_atomic_execution() {
        let mut expected = frame();
        expected.transaction_group = 1;
        assert_eq!(
            expected.encode(&binding()),
            Err(ColumnError::InvalidTransactionGroup)
        );
        expected.flags = FRAME_ATOMIC;
        assert!(expected.encode(&binding()).is_ok());
    }
}
