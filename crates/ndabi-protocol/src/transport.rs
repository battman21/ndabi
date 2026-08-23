//! Define the authenticated NDABI v0.2 transport envelope.
//!
//! Key provisioning remains out of band. Negotiation selects formats and limits only.
//! The decoder authenticates the complete frame before it interprets message fields.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{
    get_u16, get_u32, get_u64, is_zero, put_u16, put_u32, put_u64, Authority, ProtocolError,
    TAG_BYTES,
};

pub const TRANSPORT_HEADER_BYTES: usize = 128;
pub const TRANSPORT_MIN_FRAME_BYTES: usize = TRANSPORT_HEADER_BYTES + TAG_BYTES;
const MAGIC: [u8; 4] = *b"NDBT";
const VERSION_MAJOR: u8 = 2;
const VERSION_MINOR: u8 = 0;
const TRANSPORT_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v2/transport-frame";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransportKind {
    Hello = 1,
    Accept = 2,
    Result = 3,
    Error = 4,
    Cancel = 5,
    StreamStart = 6,
    StreamChunk = 7,
    StreamEnd = 8,
}

impl TryFrom<u8> for TransportKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Accept),
            3 => Ok(Self::Result),
            4 => Ok(Self::Error),
            5 => Ok(Self::Cancel),
            6 => Ok(Self::StreamStart),
            7 => Ok(Self::StreamChunk),
            8 => Ok(Self::StreamEnd),
            _ => Err(ProtocolError::UnsupportedFrame),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportFields {
    pub error_code: u16,
    pub correlation_nonce: u64,
    pub sequence: u32,
    pub rows: u32,
    pub result_shape: u32,
    pub features: u32,
    pub auxiliary: u32,
    pub execution_receipt: [u8; 32],
}

impl TransportFields {
    pub const fn empty() -> Self {
        Self {
            error_code: 0,
            correlation_nonce: 0,
            sequence: 0,
            rows: 0,
            result_shape: 0,
            features: 0,
            auxiliary: 0,
            execution_receipt: [0; 32],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportFrame<'a> {
    pub kind: TransportKind,
    pub fields: TransportFields,
    pub payload: &'a [u8],
}

pub fn transport_frame_bytes(payload_bytes: usize) -> Result<usize, ProtocolError> {
    let _ = u32::try_from(payload_bytes).map_err(|_| ProtocolError::TransportPayloadTooLarge)?;
    let total = TRANSPORT_MIN_FRAME_BYTES
        .checked_add(payload_bytes)
        .ok_or(ProtocolError::TransportPayloadTooLarge)?;
    let _ = u32::try_from(total).map_err(|_| ProtocolError::TransportPayloadTooLarge)?;
    Ok(total)
}

pub fn encode_transport(
    authority: &Authority,
    kind: TransportKind,
    fields: TransportFields,
    payload: &[u8],
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    validate_semantics(kind, fields, payload)?;
    let expected_bytes = transport_frame_bytes(payload.len())?;
    if output.len() != expected_bytes {
        return Err(ProtocolError::LengthMismatch);
    }
    output.fill(0);
    output[0..4].copy_from_slice(&MAGIC);
    output[4] = VERSION_MAJOR;
    output[5] = VERSION_MINOR;
    output[6] = kind as u8;
    put_u16(output, 8, fields.error_code);
    put_u32(output, 12, expected_bytes as u32);
    put_u64(output, 16, authority.session);
    put_u64(output, 24, authority.generation);
    put_u64(output, 32, fields.correlation_nonce);
    put_u32(output, 40, fields.sequence);
    put_u32(output, 44, payload.len() as u32);
    put_u32(output, 48, fields.rows);
    put_u32(output, 52, fields.result_shape);
    put_u32(output, 56, fields.features);
    put_u32(output, 60, fields.auxiliary);
    output[64..96].copy_from_slice(&authority.context_digest);
    output[96..128].copy_from_slice(&fields.execution_receipt);
    output[128..128 + payload.len()].copy_from_slice(payload);
    let tag_offset = output.len() - TAG_BYTES;
    let tag = transport_tag(authority, &output[..tag_offset]);
    output[tag_offset..].copy_from_slice(&tag);
    Ok(())
}

pub fn decode_transport<'a>(
    authority: &Authority,
    frame: &'a [u8],
    maximum_payload_bytes: u32,
    now_unix_us: u64,
) -> Result<TransportFrame<'a>, ProtocolError> {
    let maximum_frame_bytes = transport_frame_bytes(maximum_payload_bytes as usize)?;
    if frame.len() < TRANSPORT_MIN_FRAME_BYTES || frame.len() > maximum_frame_bytes {
        return Err(ProtocolError::LengthMismatch);
    }
    let tag_offset = frame.len() - TAG_BYTES;
    let mut expected_tag = transport_tag(authority, &frame[..tag_offset]);
    let authenticated = expected_tag.ct_eq(&frame[tag_offset..]).unwrap_u8() == 1;
    expected_tag.zeroize();
    if !authenticated {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if frame[0..4] != MAGIC
        || frame[4] != VERSION_MAJOR
        || frame[5] != VERSION_MINOR
        || frame[7] != 0
    {
        return Err(ProtocolError::UnsupportedFrame);
    }
    let kind = TransportKind::try_from(frame[6])?;
    let payload_bytes = get_u32(frame, 44) as usize;
    let encoded_frame_bytes = TRANSPORT_MIN_FRAME_BYTES.checked_add(payload_bytes);
    if get_u16(frame, 10) != 0
        || get_u32(frame, 12) as usize != frame.len()
        || encoded_frame_bytes != Some(frame.len())
    {
        return Err(ProtocolError::NonCanonicalFrame);
    }
    if get_u64(frame, 16) != authority.session
        || get_u64(frame, 24) != authority.generation
        || frame[64..96] != authority.context_digest
    {
        return Err(ProtocolError::AuthorityMismatch);
    }
    if now_unix_us >= authority.expires_unix_us {
        return Err(ProtocolError::Expired);
    }
    let fields = TransportFields {
        error_code: get_u16(frame, 8),
        correlation_nonce: get_u64(frame, 32),
        sequence: get_u32(frame, 40),
        rows: get_u32(frame, 48),
        result_shape: get_u32(frame, 52),
        features: get_u32(frame, 56),
        auxiliary: get_u32(frame, 60),
        execution_receipt: frame[96..128].try_into().expect("fixed receipt field"),
    };
    let payload = &frame[TRANSPORT_HEADER_BYTES..tag_offset];
    validate_semantics(kind, fields, payload)?;
    Ok(TransportFrame {
        kind,
        fields,
        payload,
    })
}

fn transport_tag(authority: &Authority, authenticated: &[u8]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_keyed(&authority.transport_key);
    digest.update(TRANSPORT_FRAME_DOMAIN);
    digest.update(authenticated);
    let output = *digest.finalize().as_bytes();
    digest.zeroize();
    output
}

fn validate_semantics(
    kind: TransportKind,
    fields: TransportFields,
    payload: &[u8],
) -> Result<(), ProtocolError> {
    let receipt_is_zero = is_zero(&fields.execution_receipt);
    match kind {
        TransportKind::Hello => {
            if fields.error_code != 0
                || fields.correlation_nonce != 0
                || fields.sequence != 0
                || fields.rows != 0
                || fields.result_shape != 0
                || fields.features == 0
                || fields.auxiliary < TRANSPORT_MIN_FRAME_BYTES as u32
                || !receipt_is_zero
                || payload.len() != 8
            {
                return Err(ProtocolError::NonCanonicalFrame);
            }
            let minimum_major = get_u16(payload, 0);
            let maximum_major = get_u16(payload, 2);
            let maximum_chunk = get_u32(payload, 4);
            if minimum_major == 0
                || maximum_major < minimum_major
                || maximum_chunk == 0
                || maximum_chunk
                    > fields
                        .auxiliary
                        .saturating_sub(TRANSPORT_MIN_FRAME_BYTES as u32)
            {
                return Err(ProtocolError::NonCanonicalFrame);
            }
        }
        TransportKind::Accept => {
            if fields.error_code != 0
                || fields.correlation_nonce != 0
                || fields.sequence != 0
                || fields.rows != 0
                || fields.result_shape != 0
                || fields.features == 0
                || fields.auxiliary < TRANSPORT_MIN_FRAME_BYTES as u32
                || !receipt_is_zero
                || payload.len() != 8
                || get_u16(payload, 0) != VERSION_MAJOR as u16
                || get_u16(payload, 2) != VERSION_MINOR as u16
                || get_u32(payload, 4) == 0
                || get_u32(payload, 4)
                    > fields
                        .auxiliary
                        .saturating_sub(TRANSPORT_MIN_FRAME_BYTES as u32)
            {
                return Err(ProtocolError::NonCanonicalFrame);
            }
        }
        TransportKind::Result => {
            if fields.error_code != 0
                || fields.correlation_nonce == 0
                || fields.sequence != 0
                || fields.result_shape == 0
                || fields.features != 0
                || fields.auxiliary != 0
                || receipt_is_zero
            {
                return Err(ProtocolError::NonCanonicalFrame);
            }
        }
        TransportKind::Error => {
            if fields.error_code == 0
                || fields.sequence != 0
                || fields.rows != 0
                || fields.result_shape != 0
                || fields.features != 0
                || fields.auxiliary != 0
                || !receipt_is_zero
                || !payload.is_empty()
            {
                return Err(ProtocolError::NonCanonicalFrame);
            }
        }
        TransportKind::Cancel => {
            if fields.error_code != 0
                || fields.correlation_nonce == 0
                || fields.sequence != 0
                || fields.rows != 0
                || fields.result_shape != 0
                || fields.features != 0
                || fields.auxiliary != 0
                || !receipt_is_zero
                || !payload.is_empty()
            {
                return Err(ProtocolError::NonCanonicalFrame);
            }
        }
        TransportKind::StreamStart => {
            if fields.error_code != 0
                || fields.correlation_nonce == 0
                || fields.sequence != 0
                || fields.result_shape == 0
                || fields.features != 0
                || fields.auxiliary != 0
                || !receipt_is_zero
                || !payload.is_empty()
            {
                return Err(ProtocolError::NonCanonicalFrame);
            }
        }
        TransportKind::StreamChunk => {
            if fields.error_code != 0
                || fields.correlation_nonce == 0
                || fields.sequence == 0
                || fields.rows != 0
                || fields.result_shape != 0
                || fields.features != 0
                || fields.auxiliary != 0
                || !receipt_is_zero
                || payload.is_empty()
            {
                return Err(ProtocolError::NonCanonicalFrame);
            }
        }
        TransportKind::StreamEnd => {
            if fields.error_code != 0
                || fields.correlation_nonce == 0
                || fields.sequence == 0
                || fields.result_shape == 0
                || fields.features != 0
                || fields.auxiliary != 0
                || receipt_is_zero
                || !payload.is_empty()
            {
                return Err(ProtocolError::NonCanonicalFrame);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{digest_label, AuthorityContext, BackendIdentity};

    const NOW: u64 = 1_000_000;

    fn authority() -> Authority {
        let backend = BackendIdentity::new(
            1,
            2,
            digest_label(b"schema", b"transport"),
            digest_label(b"policy", b"transport"),
            digest_label(b"plan", b"transport"),
        )
        .expect("backend");
        let context = AuthorityContext::new(
            [1; 16],
            [2; 16],
            3,
            digest_label(b"capability", b"transport"),
            backend,
        )
        .expect("context");
        Authority::new_read([7; 32], 8, 9, 2_000_000, context).expect("authority")
    }

    fn cases() -> Vec<(TransportKind, TransportFields, Vec<u8>)> {
        let receipt = [9; 32];
        vec![
            (
                TransportKind::Hello,
                TransportFields {
                    features: 1,
                    auxiliary: 4096,
                    ..TransportFields::empty()
                },
                negotiation_payload(1, 2, 1024),
            ),
            (
                TransportKind::Accept,
                TransportFields {
                    features: 1,
                    auxiliary: 4096,
                    ..TransportFields::empty()
                },
                negotiation_payload(2, 0, 1024),
            ),
            (
                TransportKind::Result,
                TransportFields {
                    correlation_nonce: 1,
                    rows: 2,
                    result_shape: 3,
                    execution_receipt: receipt,
                    ..TransportFields::empty()
                },
                vec![1, 2, 3],
            ),
            (
                TransportKind::Error,
                TransportFields {
                    error_code: 1,
                    correlation_nonce: 1,
                    ..TransportFields::empty()
                },
                vec![],
            ),
            (
                TransportKind::Cancel,
                TransportFields {
                    correlation_nonce: 1,
                    ..TransportFields::empty()
                },
                vec![],
            ),
            (
                TransportKind::StreamStart,
                TransportFields {
                    correlation_nonce: 1,
                    rows: u32::MAX,
                    result_shape: 3,
                    ..TransportFields::empty()
                },
                vec![],
            ),
            (
                TransportKind::StreamChunk,
                TransportFields {
                    correlation_nonce: 1,
                    sequence: 1,
                    ..TransportFields::empty()
                },
                vec![4, 5, 6],
            ),
            (
                TransportKind::StreamEnd,
                TransportFields {
                    correlation_nonce: 1,
                    sequence: 2,
                    rows: 2,
                    result_shape: 3,
                    execution_receipt: receipt,
                    ..TransportFields::empty()
                },
                vec![],
            ),
        ]
    }

    fn negotiation_payload(first: u16, second: u16, maximum_chunk: u32) -> Vec<u8> {
        let mut output = Vec::with_capacity(8);
        output.extend_from_slice(&first.to_le_bytes());
        output.extend_from_slice(&second.to_le_bytes());
        output.extend_from_slice(&maximum_chunk.to_le_bytes());
        output
    }

    #[test]
    fn every_transport_kind_round_trips() {
        let authority = authority();
        for (kind, fields, payload) in cases() {
            let mut frame = vec![0; transport_frame_bytes(payload.len()).expect("length")];
            encode_transport(&authority, kind, fields, &payload, &mut frame).expect("encode");
            let decoded = decode_transport(&authority, &frame, 4096, NOW).expect("decode");
            assert_eq!(decoded.kind, kind);
            assert_eq!(decoded.fields, fields);
            assert_eq!(decoded.payload, payload);
        }
    }

    #[test]
    fn every_transport_frame_bit_is_authenticated() {
        let authority = authority();
        for (kind, fields, payload) in cases() {
            let mut frame = vec![0; transport_frame_bytes(payload.len()).expect("length")];
            encode_transport(&authority, kind, fields, &payload, &mut frame).expect("encode");
            for byte_index in 0..frame.len() {
                for bit in 0..8 {
                    let mut changed = frame.clone();
                    changed[byte_index] ^= 1 << bit;
                    assert!(decode_transport(&authority, &changed, 4096, NOW).is_err());
                }
            }
        }
    }

    #[test]
    fn transport_semantics_and_limits_refuse() {
        let authority = authority();
        let fields = TransportFields {
            correlation_nonce: 1,
            ..TransportFields::empty()
        };
        assert_eq!(
            encode_transport(
                &authority,
                TransportKind::Result,
                fields,
                b"result",
                &mut [0; 166]
            ),
            Err(ProtocolError::NonCanonicalFrame)
        );

        let (kind, fields, payload) = cases()[2].clone();
        let mut frame = vec![0; transport_frame_bytes(payload.len()).expect("length")];
        encode_transport(&authority, kind, fields, &payload, &mut frame).expect("encode");
        assert_eq!(
            decode_transport(&authority, &frame, 2, NOW),
            Err(ProtocolError::LengthMismatch)
        );
        assert_eq!(
            decode_transport(&authority, &frame, 4096, 2_000_000),
            Err(ProtocolError::Expired)
        );
        assert_eq!(
            transport_frame_bytes(u32::MAX as usize),
            Err(ProtocolError::TransportPayloadTooLarge)
        );

        let impossible_hello = TransportFields {
            features: 1,
            auxiliary: 1024,
            ..TransportFields::empty()
        };
        assert_eq!(
            encode_transport(
                &authority,
                TransportKind::Hello,
                impossible_hello,
                &negotiation_payload(1, 2, 1024),
                &mut [0; 168],
            ),
            Err(ProtocolError::NonCanonicalFrame)
        );
    }
}
