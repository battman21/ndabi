//! Generate deterministic NDABI v0.2 transport conformance vectors.
//!
//! Every key and identity in this executable is public test material.

use ndabi_protocol::{
    decode_transport, encode_bundle_accepted_payload, encode_bundle_removed_payload,
    encode_transport, transport_frame_bytes, Authority, AuthorityContext, BackendIdentity,
    BundleAccepted, BundleRemoved, ProtocolError, TransportDirection, TransportFields,
    TransportKind,
};
use serde_json::{json, Value};
use zeroize::Zeroize;

const NOW: u64 = 1_000_000;
const EXPIRY: u64 = 4_102_444_800_000_000;
const GENERATION: u64 = 0x0102_0304_0506_0708;
const SESSION: u64 = 0x1112_1314_1516_1718;
const ROOT_KEY: [u8; 32] = sequence::<32>(0x00);
const TENANT: [u8; 16] = sequence::<16>(0x10);
const PRINCIPAL: [u8; 16] = sequence::<16>(0x20);
const CAPABILITY: [u8; 32] = sequence::<32>(0x40);
const SCHEMA: [u8; 32] = sequence::<32>(0x60);
const POLICY: [u8; 32] = sequence::<32>(0x80);
const PLAN: [u8; 32] = sequence::<32>(0xa0);
const PURPOSE: u32 = 0x0102_0304;
const ENGINE: u32 = 0x1122_3344;
const PROFILE: u32 = 0x5566_7788;
const TRANSPORT_KEY_DOMAIN: &[u8] = b"ndabi/wire/v2/transport-key";
const TRANSPORT_FRAME_DOMAIN: &[u8] = b"ndabi/wire/v2/transport-frame";

const fn sequence<const N: usize>(start: u8) -> [u8; N] {
    let mut output = [0_u8; N];
    let mut index = 0;
    while index < N {
        output[index] = start.wrapping_add(index as u8);
        index += 1;
    }
    output
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let identity = BackendIdentity::new(ENGINE, PROFILE, SCHEMA, POLICY, PLAN)
        .map_err(|error| error.to_string())?;
    let context = AuthorityContext::new(TENANT, PRINCIPAL, PURPOSE, CAPABILITY, identity)
        .map_err(|error| error.to_string())?;
    let context_digest = context.digest();
    let authority = Authority::new_read(ROOT_KEY, GENERATION, SESSION, EXPIRY, context)
        .map_err(|error| error.to_string())?;
    let receipt = sequence::<32>(0xc0);
    let cases = vec![
        case(
            TransportKind::Hello,
            TransportFields {
                features: 0x0000_0003,
                auxiliary: 65_536,
                ..TransportFields::empty()
            },
            negotiation_payload(1, 2, 16_384),
        ),
        case(
            TransportKind::Accept,
            TransportFields {
                features: 0x0000_0001,
                auxiliary: 65_536,
                ..TransportFields::empty()
            },
            negotiation_payload(2, 0, 16_384),
        ),
        case(
            TransportKind::Result,
            TransportFields {
                correlation_nonce: 1,
                rows: 2,
                result_shape: 0x1718_191a,
                execution_receipt: receipt,
                ..TransportFields::empty()
            },
            vec![0xde, 0xad, 0xbe, 0xef],
        ),
        case(
            TransportKind::Error,
            TransportFields {
                error_code: 7,
                correlation_nonce: 1,
                ..TransportFields::empty()
            },
            vec![],
        ),
        case(
            TransportKind::Cancel,
            TransportFields {
                correlation_nonce: 1,
                ..TransportFields::empty()
            },
            vec![],
        ),
        case(
            TransportKind::StreamStart,
            TransportFields {
                correlation_nonce: 1,
                rows: u32::MAX,
                result_shape: 0x1718_191a,
                ..TransportFields::empty()
            },
            vec![],
        ),
        case(
            TransportKind::StreamChunk,
            TransportFields {
                correlation_nonce: 1,
                sequence: 1,
                ..TransportFields::empty()
            },
            vec![0xba, 0xdc, 0x0f, 0xfe],
        ),
        case(
            TransportKind::StreamEnd,
            TransportFields {
                correlation_nonce: 1,
                sequence: 2,
                rows: 2,
                result_shape: 0x1718_191a,
                execution_receipt: receipt,
                ..TransportFields::empty()
            },
            vec![],
        ),
        case(
            TransportKind::BundleAccepted,
            TransportFields {
                correlation_nonce: 2,
                result_shape: 0x1718_191a,
                ..TransportFields::empty()
            },
            encode_bundle_accepted_payload(BundleAccepted {
                bundle_handle: 0x2122_2324,
                graph_handle: 0x2526_2728,
                expiry_unix_us: 3_000_000,
                bundle_digest: sequence::<32>(0xe0),
            })
            .to_vec(),
        ),
        case(
            TransportKind::BundleRemoved,
            TransportFields {
                correlation_nonce: 3,
                result_shape: 0x1718_191a,
                ..TransportFields::empty()
            },
            encode_bundle_removed_payload(BundleRemoved {
                bundle_handle: 0x2122_2324,
                graph_handle: 0x2526_2728,
            })
            .to_vec(),
        ),
    ];

    let mut valid = Vec::with_capacity(cases.len());
    let mut frames = Vec::with_capacity(cases.len());
    for (direction, kind, fields, payload) in &cases {
        let mut frame = vec![0; transport_frame_bytes(payload.len()).map_err(display)?];
        encode_transport(&authority, *direction, *kind, *fields, payload, &mut frame)
            .map_err(display)?;
        let decoded =
            decode_transport(&authority, *direction, &frame, 65_536, NOW).map_err(display)?;
        if decoded.kind != *kind || decoded.fields != *fields || decoded.payload != payload {
            return Err("a valid transport vector changed during decoding".to_string());
        }
        valid.push(json!({
            "id": kind_name(*kind),
            "direction": direction_name(*direction),
            "kind": *kind as u8,
            "frame_hex": hex(&frame),
            "decoded": fields_json(*fields),
            "payload_hex": hex(payload),
        }));
        frames.push(frame);
    }

    let mut changed_tag = frames[2].clone();
    let last = changed_tag.len() - 1;
    changed_tag[last] ^= 1;
    let mut reserved = frames[2].clone();
    reserved[10] = 1;
    retag(
        &mut reserved,
        &context_digest,
        TransportDirection::ServerToClient,
    )?;
    let mut zero_receipt = frames[2].clone();
    zero_receipt[96..128].fill(0);
    retag(
        &mut zero_receipt,
        &context_digest,
        TransportDirection::ServerToClient,
    )?;
    let mut unknown_kind = frames[2].clone();
    unknown_kind[6] = 0xff;
    retag(
        &mut unknown_kind,
        &context_digest,
        TransportDirection::ServerToClient,
    )?;
    let mut unregistered_error = frames[3].clone();
    unregistered_error[8..10].copy_from_slice(&11_u16.to_le_bytes());
    retag(
        &mut unregistered_error,
        &context_digest,
        TransportDirection::ServerToClient,
    )?;
    let mut wrong_context = frames[2].clone();
    wrong_context[64] ^= 1;
    retag(
        &mut wrong_context,
        &context_digest,
        TransportDirection::ServerToClient,
    )?;
    let invalid = [
        (
            "result-tag-changed",
            TransportDirection::ServerToClient,
            changed_tag,
            ProtocolError::AuthenticationFailed,
        ),
        (
            "result-reserved-set",
            TransportDirection::ServerToClient,
            reserved,
            ProtocolError::NonCanonicalFrame,
        ),
        (
            "result-zero-receipt",
            TransportDirection::ServerToClient,
            zero_receipt,
            ProtocolError::NonCanonicalFrame,
        ),
        (
            "unknown-kind",
            TransportDirection::ServerToClient,
            unknown_kind,
            ProtocolError::UnsupportedFrame,
        ),
        (
            "unregistered-error-code",
            TransportDirection::ServerToClient,
            unregistered_error,
            ProtocolError::NonCanonicalFrame,
        ),
        (
            "transport-context-mismatch",
            TransportDirection::ServerToClient,
            wrong_context,
            ProtocolError::AuthorityMismatch,
        ),
        (
            "result-reflected-direction",
            TransportDirection::ClientToServer,
            frames[2].clone(),
            ProtocolError::AuthenticationFailed,
        ),
    ];
    for (_, direction, frame, expected) in &invalid {
        let actual = decode_transport(&authority, *direction, frame, 65_536, NOW)
            .expect_err("an invalid transport vector must refuse");
        if actual != *expected {
            return Err(format!("an invalid transport vector returned {actual}"));
        }
    }

    let manifest = json!({
        "schema": "ndabi-transport-conformance-v0.2",
        "integer_encoding": "decimal-string-for-64-bit",
        "status": "implemented transport candidate vectors",
        "warning": "All keys and identities are public test material.",
        "clock_unix_us": NOW.to_string(),
        "maximum_payload_bytes": 65_536,
        "authority": {
            "root_key_hex": hex(&ROOT_KEY),
            "generation": GENERATION.to_string(),
            "session": SESSION.to_string(),
            "expires_unix_us": EXPIRY.to_string(),
            "context_digest_hex": hex(&context_digest),
        },
        "valid": valid,
        "invalid": invalid.iter().map(|(id, direction, frame, expected)| json!({
            "id": id,
            "direction": direction_name(*direction),
            "frame_hex": hex(frame),
            "expected_error": expected.to_string(),
        })).collect::<Vec<Value>>(),
        "state_sequences": [
            {"id": "single-result", "messages": ["result"]},
            {"id": "stream-result", "messages": ["stream-start", "stream-chunk", "stream-end"]},
            {"id": "cancel-request", "messages": ["cancel", "error"]},
            {"id": "bundle-lifecycle", "messages": ["bundle-accepted", "bundle-removed"]},
        ],
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&manifest).map_err(display)?
    );
    Ok(())
}

fn case(
    kind: TransportKind,
    fields: TransportFields,
    payload: Vec<u8>,
) -> (TransportDirection, TransportKind, TransportFields, Vec<u8>) {
    let direction = match kind {
        TransportKind::Hello | TransportKind::Cancel => TransportDirection::ClientToServer,
        _ => TransportDirection::ServerToClient,
    };
    (direction, kind, fields, payload)
}

fn negotiation_payload(first: u16, second: u16, maximum_chunk: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(8);
    output.extend_from_slice(&first.to_le_bytes());
    output.extend_from_slice(&second.to_le_bytes());
    output.extend_from_slice(&maximum_chunk.to_le_bytes());
    output
}

fn fields_json(fields: TransportFields) -> Value {
    json!({
        "error_code": fields.error_code,
        "correlation_nonce": fields.correlation_nonce.to_string(),
        "sequence": fields.sequence,
        "rows": fields.rows,
        "result_shape": fields.result_shape,
        "features": fields.features,
        "auxiliary": fields.auxiliary,
        "execution_receipt_hex": hex(&fields.execution_receipt),
    })
}

fn kind_name(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Hello => "hello",
        TransportKind::Accept => "accept",
        TransportKind::Result => "result",
        TransportKind::Error => "error",
        TransportKind::Cancel => "cancel",
        TransportKind::StreamStart => "stream-start",
        TransportKind::StreamChunk => "stream-chunk",
        TransportKind::StreamEnd => "stream-end",
        TransportKind::BundleAccepted => "bundle-accepted",
        TransportKind::BundleRemoved => "bundle-removed",
    }
}

fn direction_name(direction: TransportDirection) -> &'static str {
    match direction {
        TransportDirection::ClientToServer => "client-to-server",
        TransportDirection::ServerToClient => "server-to-client",
    }
}

fn retag(
    frame: &mut [u8],
    context_digest: &[u8; 32],
    direction: TransportDirection,
) -> Result<(), String> {
    let mut key_hasher = blake3::Hasher::new_keyed(&ROOT_KEY);
    key_hasher.update(TRANSPORT_KEY_DOMAIN);
    key_hasher.update(&GENERATION.to_le_bytes());
    key_hasher.update(&SESSION.to_le_bytes());
    key_hasher.update(&EXPIRY.to_le_bytes());
    key_hasher.update(context_digest);
    let mut transport_key = *key_hasher.finalize().as_bytes();
    key_hasher.zeroize();
    let tag_offset = frame
        .len()
        .checked_sub(32)
        .ok_or_else(|| "the transport frame is too short".to_string())?;
    let mut tag_hasher = blake3::Hasher::new_keyed(&transport_key);
    tag_hasher.update(TRANSPORT_FRAME_DOMAIN);
    tag_hasher.update(&[direction as u8]);
    tag_hasher.update(&frame[..tag_offset]);
    let mut tag = *tag_hasher.finalize().as_bytes();
    tag_hasher.zeroize();
    frame[tag_offset..].copy_from_slice(&tag);
    transport_key.zeroize();
    tag.zeroize();
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("string writes cannot fail");
    }
    output
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
