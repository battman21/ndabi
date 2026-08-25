use std::io::Write as _;

use crc32fast::Hasher as Crc32;
use serde::{Deserialize, Serialize};

use super::model::{
    PreparedCapability, PreparedCommand, Query, QueryReceipt, ResultBuffer, TrustedEnvelope,
    Workload,
};

const REQUEST_MAGIC: &[u8; 4] = b"N10Q";
const RESPONSE_MAGIC: &[u8; 4] = b"N10R";
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arm {
    StatelessJson,
    PreparedJson,
    CanonicalCbor,
    ProtectedCbor,
    Ndabi,
    FusedView,
    Direct,
}

impl Arm {
    pub const ALL: [Self; 7] = [
        Self::StatelessJson,
        Self::PreparedJson,
        Self::CanonicalCbor,
        Self::ProtectedCbor,
        Self::Ndabi,
        Self::FusedView,
        Self::Direct,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::StatelessJson => "stateless-json",
            Self::PreparedJson => "prepared-json",
            Self::CanonicalCbor => "canonical-cbor",
            Self::ProtectedCbor => "protected-cbor",
            Self::Ndabi => "ndabi",
            Self::FusedView => "fused-view",
            Self::Direct => "direct",
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::StatelessJson => 0,
            Self::PreparedJson => 1,
            Self::CanonicalCbor => 2,
            Self::ProtectedCbor => 3,
            Self::Ndabi => 4,
            Self::FusedView => 5,
            Self::Direct => 6,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DecodedRequest {
    pub command: PreparedCommand,
    pub capability: Option<PreparedCapability>,
    pub envelope: Option<TrustedEnvelope>,
}

#[derive(Serialize)]
struct ReadableRequest<'a> {
    protocol_version: u8,
    operation: &'a str,
    capability: PreparedCapability,
    authority: TrustedEnvelope,
    query: Query,
}

#[derive(Deserialize)]
struct ReadableRequestOwned {
    protocol_version: u8,
    operation: String,
    capability: PreparedCapability,
    authority: TrustedEnvelope,
    query: Query,
}

#[derive(Deserialize, Serialize)]
struct CompactRequest {
    v: u8,
    h: u64,
    g: u32,
    o: u8,
    b: u32,
    a: [u64; 5],
}

#[derive(Deserialize)]
struct ReadableResponse<'a> {
    matched_records: u64,
    aggregate: u64,
    result_digest: &'a str,
    payload_hex: &'a str,
    snapshot: u64,
    nonce: u64,
    capability_handle: u64,
}

#[derive(Deserialize)]
struct CompactResponse<'a> {
    m: u64,
    a: u64,
    d: &'a str,
    p: &'a str,
    s: u64,
    n: u64,
    h: u64,
}

pub fn encode_request(
    arm: Arm,
    output: &mut Vec<u8>,
    capability: PreparedCapability,
    envelope: TrustedEnvelope,
    command: PreparedCommand,
) -> Result<(), String> {
    output.clear();
    match arm {
        Arm::StatelessJson => serde_json::to_writer(
            output,
            &ReadableRequest {
                protocol_version: VERSION,
                operation: command.query.workload.name(),
                capability,
                authority: envelope,
                query: command.query,
            },
        )
        .map_err(|error| error.to_string()),
        Arm::PreparedJson => serde_json::to_writer(
            output,
            &CompactRequest {
                v: VERSION,
                h: command.capability_handle,
                g: command.capability_generation,
                o: command.query.workload.opcode(),
                b: command.query.result_budget,
                a: command.query.arguments,
            },
        )
        .map_err(|error| error.to_string()),
        Arm::CanonicalCbor | Arm::ProtectedCbor => {
            output.push(0x8a);
            cbor_uint(output, u64::from(VERSION));
            cbor_uint(output, command.capability_handle);
            cbor_uint(output, u64::from(command.capability_generation));
            cbor_uint(output, u64::from(command.query.workload.opcode()));
            cbor_uint(output, u64::from(command.query.result_budget));
            for argument in command.query.arguments {
                cbor_uint(output, argument);
            }
            if arm == Arm::ProtectedCbor {
                append_crc32(output);
            }
            Ok(())
        }
        Arm::Ndabi => {
            output.extend_from_slice(REQUEST_MAGIC);
            output.push(VERSION);
            output.push(command.query.workload.opcode());
            output.extend_from_slice(&command.capability_handle.to_le_bytes());
            output.extend_from_slice(&command.capability_generation.to_le_bytes());
            output.extend_from_slice(&command.query.result_budget.to_le_bytes());
            for argument in command.query.arguments {
                output.extend_from_slice(&argument.to_le_bytes());
            }
            append_crc32(output);
            Ok(())
        }
        Arm::FusedView | Arm::Direct => Ok(()),
    }
}

pub fn decode_request(arm: Arm, bytes: &[u8]) -> Result<DecodedRequest, String> {
    match arm {
        Arm::StatelessJson => {
            let request: ReadableRequestOwned =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            if request.protocol_version != VERSION
                || request.operation != request.query.workload.name()
            {
                return Err("the readable request header does not match".to_string());
            }
            Ok(DecodedRequest {
                command: PreparedCommand {
                    capability_handle: request.capability.handle,
                    capability_generation: request.capability.generation,
                    query: request.query,
                },
                capability: Some(request.capability),
                envelope: Some(request.authority),
            })
        }
        Arm::PreparedJson => {
            let request: CompactRequest =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            compact_request(request)
        }
        Arm::CanonicalCbor | Arm::ProtectedCbor => {
            let body = if arm == Arm::ProtectedCbor {
                verify_crc32(bytes)?
            } else {
                bytes
            };
            let mut reader = CborReader::new(body);
            reader.array(10)?;
            let version = reader.uint()?;
            let handle = reader.uint()?;
            let generation = checked_u32(reader.uint()?, "generation")?;
            let operation = checked_u8(reader.uint()?, "operation")?;
            let result_budget = checked_u32(reader.uint()?, "result budget")?;
            let mut arguments = [0u64; 5];
            for argument in &mut arguments {
                *argument = reader.uint()?;
            }
            reader.finish()?;
            if version != u64::from(VERSION) {
                return Err("the CBOR request version does not match".to_string());
            }
            prepared_request(handle, generation, operation, result_budget, arguments)
        }
        Arm::Ndabi => {
            let body = verify_crc32(bytes)?;
            let mut reader = ByteReader::new(body);
            if reader.take(4)? != REQUEST_MAGIC || reader.u8()? != VERSION {
                return Err("the NDABI request header does not match".to_string());
            }
            let operation = reader.u8()?;
            let handle = reader.u64()?;
            let generation = reader.u32()?;
            let result_budget = reader.u32()?;
            let mut arguments = [0u64; 5];
            for argument in &mut arguments {
                *argument = reader.u64()?;
            }
            reader.finish()?;
            prepared_request(handle, generation, operation, result_budget, arguments)
        }
        Arm::FusedView | Arm::Direct => Err("the arm uses no general request frame".to_string()),
    }
}

pub fn encode_response(
    arm: Arm,
    output: &mut Vec<u8>,
    result: &ResultBuffer,
    receipt: QueryReceipt,
) -> Result<(), String> {
    output.clear();
    match arm {
        Arm::StatelessJson => {
            write!(
                output,
                "{{\"matched_records\":{},\"aggregate\":{},\"result_digest\":\"",
                result.semantic.matched_records, result.semantic.aggregate
            )
            .map_err(|error| error.to_string())?;
            hex_into(output, &result.semantic.result_digest);
            output.extend_from_slice(b"\",\"payload_hex\":\"");
            hex_into(output, &result.payload);
            write!(
                output,
                "\",\"snapshot\":{},\"nonce\":{},\"capability_handle\":{}}}",
                receipt.snapshot, receipt.nonce, receipt.capability_handle
            )
            .map_err(|error| error.to_string())
        }
        Arm::PreparedJson => {
            write!(
                output,
                "{{\"m\":{},\"a\":{},\"d\":\"",
                result.semantic.matched_records, result.semantic.aggregate
            )
            .map_err(|error| error.to_string())?;
            hex_into(output, &result.semantic.result_digest);
            output.extend_from_slice(b"\",\"p\":\"");
            hex_into(output, &result.payload);
            write!(
                output,
                "\",\"s\":{},\"n\":{},\"h\":{}}}",
                receipt.snapshot, receipt.nonce, receipt.capability_handle
            )
            .map_err(|error| error.to_string())
        }
        Arm::CanonicalCbor | Arm::ProtectedCbor => {
            output.push(0x88);
            cbor_uint(output, result.semantic.matched_records);
            cbor_uint(output, result.semantic.aggregate);
            cbor_bytes(output, &result.semantic.result_digest)?;
            cbor_bytes(output, &result.payload)?;
            cbor_uint(output, receipt.snapshot);
            cbor_uint(output, receipt.nonce);
            cbor_uint(output, receipt.capability_handle);
            cbor_uint(output, u64::from(VERSION));
            if arm == Arm::ProtectedCbor {
                append_crc32(output);
            }
            Ok(())
        }
        Arm::Ndabi => {
            output.extend_from_slice(RESPONSE_MAGIC);
            output.push(VERSION);
            output.extend_from_slice(&result.semantic.matched_records.to_le_bytes());
            output.extend_from_slice(&result.semantic.aggregate.to_le_bytes());
            output.extend_from_slice(&result.semantic.result_digest);
            output.extend_from_slice(&result.semantic.payload_bytes.to_le_bytes());
            output.extend_from_slice(&result.payload);
            output.extend_from_slice(&receipt.snapshot.to_le_bytes());
            output.extend_from_slice(&receipt.nonce.to_le_bytes());
            output.extend_from_slice(&receipt.capability_handle.to_le_bytes());
            append_crc32(output);
            Ok(())
        }
        Arm::FusedView | Arm::Direct => Ok(()),
    }
}

pub fn verify_response(
    arm: Arm,
    bytes: &[u8],
    expected: &ResultBuffer,
    receipt: QueryReceipt,
) -> Result<(), String> {
    match arm {
        Arm::StatelessJson => {
            let response: ReadableResponse<'_> =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            verify_text_response(
                response.matched_records,
                response.aggregate,
                response.result_digest,
                response.payload_hex,
                response.snapshot,
                response.nonce,
                response.capability_handle,
                expected,
                receipt,
            )
        }
        Arm::PreparedJson => {
            let response: CompactResponse<'_> =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            verify_text_response(
                response.m, response.a, response.d, response.p, response.s, response.n, response.h,
                expected, receipt,
            )
        }
        Arm::CanonicalCbor | Arm::ProtectedCbor => {
            let body = if arm == Arm::ProtectedCbor {
                verify_crc32(bytes)?
            } else {
                bytes
            };
            let mut reader = CborReader::new(body);
            reader.array(8)?;
            let matched = reader.uint()?;
            let aggregate = reader.uint()?;
            let digest = reader.bytes()?;
            let payload = reader.bytes()?;
            let snapshot = reader.uint()?;
            let nonce = reader.uint()?;
            let handle = reader.uint()?;
            let version = reader.uint()?;
            reader.finish()?;
            if version != u64::from(VERSION) {
                return Err("the CBOR response version does not match".to_string());
            }
            verify_binary_response(
                matched, aggregate, digest, payload, snapshot, nonce, handle, expected, receipt,
            )
        }
        Arm::Ndabi => {
            let body = verify_crc32(bytes)?;
            let mut reader = ByteReader::new(body);
            if reader.take(4)? != RESPONSE_MAGIC || reader.u8()? != VERSION {
                return Err("the NDABI response header does not match".to_string());
            }
            let matched = reader.u64()?;
            let aggregate = reader.u64()?;
            let digest = reader.take(32)?;
            let payload_length = usize::try_from(reader.u32()?)
                .map_err(|_| "the response payload length overflowed".to_string())?;
            let payload = reader.take(payload_length)?;
            let snapshot = reader.u64()?;
            let nonce = reader.u64()?;
            let handle = reader.u64()?;
            reader.finish()?;
            verify_binary_response(
                matched, aggregate, digest, payload, snapshot, nonce, handle, expected, receipt,
            )
        }
        Arm::FusedView | Arm::Direct => Ok(()),
    }
}

fn compact_request(request: CompactRequest) -> Result<DecodedRequest, String> {
    if request.v != VERSION {
        return Err("the compact JSON request version does not match".to_string());
    }
    prepared_request(request.h, request.g, request.o, request.b, request.a)
}

fn prepared_request(
    handle: u64,
    generation: u32,
    operation: u8,
    result_budget: u32,
    arguments: [u64; 5],
) -> Result<DecodedRequest, String> {
    Ok(DecodedRequest {
        command: PreparedCommand {
            capability_handle: handle,
            capability_generation: generation,
            query: Query {
                workload: Workload::from_opcode(operation)?,
                result_budget,
                arguments,
            },
        },
        capability: None,
        envelope: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_text_response(
    matched: u64,
    aggregate: u64,
    digest: &str,
    payload: &str,
    snapshot: u64,
    nonce: u64,
    handle: u64,
    expected: &ResultBuffer,
    receipt: QueryReceipt,
) -> Result<(), String> {
    if matched != expected.semantic.matched_records
        || aggregate != expected.semantic.aggregate
        || !hex_matches(digest.as_bytes(), &expected.semantic.result_digest)
        || !hex_matches(payload.as_bytes(), &expected.payload)
        || snapshot != receipt.snapshot
        || nonce != receipt.nonce
        || handle != receipt.capability_handle
    {
        return Err("the JSON response does not match the canonical result".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_binary_response(
    matched: u64,
    aggregate: u64,
    digest: &[u8],
    payload: &[u8],
    snapshot: u64,
    nonce: u64,
    handle: u64,
    expected: &ResultBuffer,
    receipt: QueryReceipt,
) -> Result<(), String> {
    if matched != expected.semantic.matched_records
        || aggregate != expected.semantic.aggregate
        || digest != expected.semantic.result_digest
        || payload != expected.payload
        || snapshot != receipt.snapshot
        || nonce != receipt.nonce
        || handle != receipt.capability_handle
    {
        return Err("the binary response does not match the canonical result".to_string());
    }
    Ok(())
}

fn hex_into(output: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)]);
        output.push(HEX[usize::from(byte & 0x0f)]);
    }
}

fn hex_matches(encoded: &[u8], expected: &[u8]) -> bool {
    if encoded.len() != expected.len() * 2 {
        return false;
    }
    expected.iter().enumerate().all(|(index, byte)| {
        decode_nibble(encoded[index * 2])
            .zip(decode_nibble(encoded[index * 2 + 1]))
            .map(|(high, low)| high << 4 | low)
            == Some(*byte)
    })
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn append_crc32(output: &mut Vec<u8>) {
    let mut hasher = Crc32::new();
    hasher.update(output);
    output.extend_from_slice(&hasher.finalize().to_le_bytes());
}

fn verify_crc32(bytes: &[u8]) -> Result<&[u8], String> {
    let body_length = bytes
        .len()
        .checked_sub(4)
        .ok_or_else(|| "the protected frame is shorter than its checksum".to_string())?;
    let (body, checksum) = bytes.split_at(body_length);
    let expected = u32::from_le_bytes(
        checksum
            .try_into()
            .map_err(|_| "the protected frame checksum length does not match".to_string())?,
    );
    let mut hasher = Crc32::new();
    hasher.update(body);
    if hasher.finalize() != expected {
        return Err("the protected frame checksum does not match".to_string());
    }
    Ok(body)
}

fn cbor_uint(output: &mut Vec<u8>, value: u64) {
    if value < 24 {
        output.push(value as u8);
    } else if value <= u64::from(u8::MAX) {
        output.extend_from_slice(&[24, value as u8]);
    } else if value <= u64::from(u16::MAX) {
        output.push(25);
        output.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        output.push(26);
        output.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        output.push(27);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn cbor_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| "the CBOR byte string length overflowed".to_string())?;
    if length < 24 {
        output.push(0x40 | length as u8);
    } else if length <= u64::from(u8::MAX) {
        output.extend_from_slice(&[0x58, length as u8]);
    } else if length <= u64::from(u16::MAX) {
        output.push(0x59);
        output.extend_from_slice(&(length as u16).to_be_bytes());
    } else if length <= u64::from(u32::MAX) {
        output.push(0x5a);
        output.extend_from_slice(&(length as u32).to_be_bytes());
    } else {
        output.push(0x5b);
        output.extend_from_slice(&length.to_be_bytes());
    }
    output.extend_from_slice(bytes);
    Ok(())
}

struct CborReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> CborReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn array(&mut self, length: u8) -> Result<(), String> {
        if length >= 24 || self.byte()? != 0x80 | length {
            return Err("the canonical CBOR array header does not match".to_string());
        }
        Ok(())
    }

    fn uint(&mut self) -> Result<u64, String> {
        let head = self.byte()?;
        if head >> 5 != 0 {
            return Err("the canonical CBOR value is not unsigned".to_string());
        }
        let additional = head & 0x1f;
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => {
                let value = u64::from(self.byte()?);
                if value < 24 {
                    return Err("the CBOR integer is not minimally encoded".to_string());
                }
                Ok(value)
            }
            25 => {
                let value =
                    u64::from(u16::from_be_bytes(self.take(2)?.try_into().map_err(
                        |_| "the CBOR integer length does not match".to_string(),
                    )?));
                if value <= u64::from(u8::MAX) {
                    return Err("the CBOR integer is not minimally encoded".to_string());
                }
                Ok(value)
            }
            26 => {
                let value =
                    u64::from(u32::from_be_bytes(self.take(4)?.try_into().map_err(
                        |_| "the CBOR integer length does not match".to_string(),
                    )?));
                if value <= u64::from(u16::MAX) {
                    return Err("the CBOR integer is not minimally encoded".to_string());
                }
                Ok(value)
            }
            27 => {
                let value = u64::from_be_bytes(
                    self.take(8)?
                        .try_into()
                        .map_err(|_| "the CBOR integer length does not match".to_string())?,
                );
                if value <= u64::from(u32::MAX) {
                    return Err("the CBOR integer is not minimally encoded".to_string());
                }
                Ok(value)
            }
            _ => Err("the canonical CBOR integer form is unsupported".to_string()),
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let head = self.byte()?;
        if head >> 5 != 2 {
            return Err("the canonical CBOR value is not a byte string".to_string());
        }
        let length = match head & 0x1f {
            value @ 0..=23 => usize::from(value),
            24 => {
                let value = usize::from(self.byte()?);
                if value < 24 {
                    return Err("the CBOR length is not minimally encoded".to_string());
                }
                value
            }
            25 => {
                let value = usize::from(u16::from_be_bytes(
                    self.take(2)?
                        .try_into()
                        .map_err(|_| "the CBOR length does not match".to_string())?,
                ));
                if value <= usize::from(u8::MAX) {
                    return Err("the CBOR length is not minimally encoded".to_string());
                }
                value
            }
            26 => usize::try_from(u32::from_be_bytes(
                self.take(4)?
                    .try_into()
                    .map_err(|_| "the CBOR length does not match".to_string())?,
            ))
            .map_err(|_| "the CBOR length overflowed".to_string())?,
            _ => return Err("the canonical CBOR byte-string length is unsupported".to_string()),
        };
        self.take(length)
    }

    fn byte(&mut self) -> Result<u8, String> {
        let value = *self
            .bytes
            .get(self.cursor)
            .ok_or_else(|| "the CBOR frame ended early".to_string())?;
        self.cursor += 1;
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or_else(|| "the CBOR cursor overflowed".to_string())?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| "the CBOR frame ended early".to_string())?;
        self.cursor = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), String> {
        if self.cursor != self.bytes.len() {
            return Err("the CBOR frame has trailing bytes".to_string());
        }
        Ok(())
    }
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or_else(|| "the NDABI cursor overflowed".to_string())?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| "the NDABI frame ended early".to_string())?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(
            |_| "the NDABI u32 length does not match".to_string(),
        )?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(
            |_| "the NDABI u64 length does not match".to_string(),
        )?))
    }

    fn finish(self) -> Result<(), String> {
        if self.cursor != self.bytes.len() {
            return Err("the NDABI frame has trailing bytes".to_string());
        }
        Ok(())
    }
}

fn checked_u8(value: u64, field: &str) -> Result<u8, String> {
    u8::try_from(value).map_err(|_| format!("the CBOR {field} overflowed"))
}

fn checked_u32(value: u64, field: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("the CBOR {field} overflowed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v18::model::{Dataset, PreparedCapability, Query, SemanticResult};

    fn fixture() -> (PreparedCapability, TrustedEnvelope, PreparedCommand) {
        let dataset = Dataset::fixture(512).expect("dataset");
        let query = Query::fixture(Workload::Filter, 512, 4_096).expect("query");
        let capability = PreparedCapability::fixture(dataset.snapshot, query.result_budget);
        let command = PreparedCommand {
            capability_handle: capability.handle,
            capability_generation: capability.generation,
            query,
        };
        (capability, capability.envelope(1), command)
    }

    #[test]
    fn every_request_codec_round_trips() {
        let (capability, envelope, command) = fixture();
        for arm in Arm::ALL
            .into_iter()
            .filter(|arm| !matches!(arm, Arm::FusedView | Arm::Direct))
        {
            let mut bytes = Vec::new();
            encode_request(arm, &mut bytes, capability, envelope, command).expect("encode");
            let decoded = decode_request(arm, &bytes).expect("decode");
            assert_eq!(decoded.command, command);
            if arm == Arm::StatelessJson {
                assert_eq!(decoded.capability, Some(capability));
                assert_eq!(decoded.envelope, Some(envelope));
            }
        }
    }

    #[test]
    fn every_ndabi_request_bit_change_refuses() {
        let (capability, envelope, command) = fixture();
        let mut bytes = Vec::new();
        encode_request(Arm::Ndabi, &mut bytes, capability, envelope, command).expect("encode");
        for index in 0..bytes.len() {
            for bit in 0..8 {
                let mut changed = bytes.clone();
                changed[index] ^= 1 << bit;
                assert!(decode_request(Arm::Ndabi, &changed).is_err());
            }
        }
    }

    #[test]
    fn every_protected_cbor_request_bit_change_refuses() {
        let (capability, envelope, command) = fixture();
        let mut bytes = Vec::new();
        encode_request(
            Arm::ProtectedCbor,
            &mut bytes,
            capability,
            envelope,
            command,
        )
        .expect("encode");
        for index in 0..bytes.len() {
            for bit in 0..8 {
                let mut changed = bytes.clone();
                changed[index] ^= 1 << bit;
                assert!(decode_request(Arm::ProtectedCbor, &changed).is_err());
            }
        }
    }

    #[test]
    fn noncanonical_cbor_integer_refuses() {
        let mut bytes = vec![0x8a, 0x18, VERSION];
        bytes.extend_from_slice(&[0; 9]);
        assert!(decode_request(Arm::CanonicalCbor, &bytes).is_err());
    }

    #[test]
    fn every_response_codec_verifies_exact_bytes() {
        let (capability, _, _) = fixture();
        let mut result = ResultBuffer::with_capacity(64);
        result.payload.extend_from_slice(b"exact-result");
        result.semantic = SemanticResult {
            matched_records: 1,
            aggregate: 9,
            result_digest: *blake3::hash(&result.payload).as_bytes(),
            payload_bytes: result.payload.len() as u32,
        };
        let receipt = QueryReceipt {
            snapshot: 73,
            nonce: 1,
            capability_handle: capability.handle,
            result_digest: result.semantic.result_digest,
        };
        for arm in Arm::ALL
            .into_iter()
            .filter(|arm| !matches!(arm, Arm::FusedView | Arm::Direct))
        {
            let mut bytes = Vec::new();
            encode_response(arm, &mut bytes, &result, receipt).expect("encode");
            verify_response(arm, &bytes, &result, receipt).expect("verify");
        }
    }
}
