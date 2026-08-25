use serde::{Deserialize, Serialize};

pub const EXPECTED_PRINCIPAL: u32 = 0x0102_0304;
pub const EXPECTED_PURPOSE: u16 = 0x0021;
pub const EXPECTED_TENANT: u32 = 2;
pub const REFERENCE_NOW: u64 = 1_900_000_000;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Envelope {
    pub principal: u32,
    pub purpose: u16,
    pub tenant: u32,
    pub snapshot: u64,
    pub max_items: u16,
    pub deadline: u64,
    pub nonce: u64,
}

impl Envelope {
    pub fn valid(max_items: u16) -> Self {
        Self {
            principal: EXPECTED_PRINCIPAL,
            purpose: EXPECTED_PURPOSE,
            tenant: EXPECTED_TENANT,
            snapshot: 0x1122_3344_5566_7788,
            max_items,
            deadline: REFERENCE_NOW + 3_600,
            nonce: 0x8899_aabb_ccdd_eeff,
        }
    }
}

pub fn validate_envelope(envelope: Envelope, requested_items: usize) -> Result<(), String> {
    if envelope.principal != EXPECTED_PRINCIPAL {
        return Err("principal is not authorised".to_string());
    }
    if envelope.purpose != EXPECTED_PURPOSE {
        return Err("purpose is not authorised".to_string());
    }
    if envelope.tenant != EXPECTED_TENANT {
        return Err("tenant is not authorised".to_string());
    }
    if envelope.deadline < REFERENCE_NOW {
        return Err("deadline has expired".to_string());
    }
    if requested_items > usize::from(envelope.max_items) {
        return Err("requested items exceed the trusted budget".to_string());
    }
    Ok(())
}

pub fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub fn push_envelope(bytes: &mut Vec<u8>, envelope: Envelope) {
    push_u32(bytes, envelope.principal);
    push_u16(bytes, envelope.purpose);
    push_u32(bytes, envelope.tenant);
    push_u64(bytes, envelope.snapshot);
    push_u16(bytes, envelope.max_items);
    push_u64(bytes, envelope.deadline);
    push_u64(bytes, envelope.nonce);
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| "frame length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("frame is truncated".to_string());
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    pub fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, String> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| "u16 is truncated".to_string())?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub fn u32(&mut self) -> Result<u32, String> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| "u32 is truncated".to_string())?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn u64(&mut self) -> Result<u64, String> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| "u64 is truncated".to_string())?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn envelope(&mut self) -> Result<Envelope, String> {
        Ok(Envelope {
            principal: self.u32()?,
            purpose: self.u16()?,
            tenant: self.u32()?,
            snapshot: self.u64()?,
            max_items: self.u16()?,
            deadline: self.u64()?,
            nonce: self.u64()?,
        })
    }
}

pub fn append_crc32(bytes: &mut Vec<u8>) {
    let checksum = crc32(bytes);
    push_u32(bytes, checksum);
}

pub fn verify_crc32(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.len() < 4 {
        return Err("frame has no checksum".to_string());
    }
    let body_end = bytes.len() - 4;
    let expected = u32::from_le_bytes(
        bytes[body_end..]
            .try_into()
            .map_err(|_| "checksum is truncated".to_string())?,
    );
    let body = &bytes[..body_end];
    if crc32(body) != expected {
        return Err("frame checksum does not match".to_string());
    }
    Ok(body)
}

pub fn crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

pub struct Digest64 {
    value: u64,
}

impl Default for Digest64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Digest64 {
    pub fn new() -> Self {
        Self {
            value: 0xcbf2_9ce4_8422_2325,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.value ^= u64::from(*byte);
            self.value = self.value.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    pub fn update_u16(&mut self, value: u16) {
        self.update(&value.to_le_bytes());
    }

    pub fn update_u32(&mut self, value: u32) {
        self.update(&value.to_le_bytes());
    }

    pub fn update_u64(&mut self, value: u64) {
        self.update(&value.to_le_bytes());
    }

    pub fn finish(self) -> u64 {
        self.value
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_detects_mutation() {
        let mut bytes = b"ndabi".to_vec();
        append_crc32(&mut bytes);
        assert_eq!(verify_crc32(&bytes).expect("valid checksum"), b"ndabi");
        bytes[0] ^= 1;
        assert_eq!(
            verify_crc32(&bytes).expect_err("mutation must fail"),
            "frame checksum does not match"
        );
    }
}
