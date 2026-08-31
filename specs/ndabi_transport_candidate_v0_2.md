# NDABI transport candidate v0.2

**Status:** Implemented transport candidate. This document is not a public RFC or a production standard.

**Scope:** Authenticated negotiation, results, errors, cancellation, bounded streaming, and operand bundle acknowledgements after authority provisioning.

## 1. Purpose

The v0.1 request frame admits registered read operations.
This transport envelope returns exact results and coordinates the connection without textual wrappers.
It does not perform key exchange, identity proofing, or transport encryption.

## 2. Authority and cryptography

Provision the v0.1 authority before transport negotiation.
Derive `transport_key` with keyed BLAKE3 under `root_key` over this exact concatenation:

```text
"ndabi/wire/v2/transport-key"
|| LE64(generation) || LE64(session) || LE64(expiry) || context_digest
```

Authenticate every transport frame with keyed BLAKE3 under `transport_key`:

```text
"ndabi/wire/v2/transport-frame" || direction || frame[0..tag_offset]
```

Use direction `1` for client-to-server frames.
Use direction `2` for server-to-client frames.
The decoder MUST bind the expected direction into authentication.
This binding prevents a valid frame from reflecting into the opposite direction.

The decoder MUST determine the tag position from the received length.
The decoder MUST authenticate the complete frame before semantic interpretation.
The decoder MUST compare tags in constant time.

## 3. Common frame

The frame contains `160 + payload_bytes` bytes.
All multibyte integers use little-endian encoding.

| Offset | Width | Type | Field | Required value |
|---:|---:|---|---|---|
| 0 | 4 | bytes | magic | `NDBT` |
| 4 | 1 | `u8` | major | `2` |
| 5 | 1 | `u8` | minor | `0` |
| 6 | 1 | `u8` | kind | registered message kind |
| 7 | 1 | `u8` | flags | `0` |
| 8 | 2 | `u16` | error code | zero outside `ERROR` |
| 10 | 2 | bytes | reserved | all zero |
| 12 | 4 | `u32` | frame bytes | actual frame length |
| 16 | 8 | `u64` | session | configured session |
| 24 | 8 | `u64` | generation | configured generation |
| 32 | 8 | `u64` | correlation nonce | admitted request nonce |
| 40 | 4 | `u32` | sequence | stream sequence number |
| 44 | 4 | `u32` | payload bytes | actual payload length |
| 48 | 4 | `u32` | rows | returned or expected rows |
| 52 | 4 | `u32` | result shape | registered result shape |
| 56 | 4 | `u32` | features | negotiation feature bits |
| 60 | 4 | `u32` | auxiliary | negotiated maximum frame bytes |
| 64 | 32 | bytes | context digest | configured authority context |
| 96 | 32 | bytes | execution receipt | terminal result receipt |
| 128 | variable | bytes | payload | kind-specific exact bytes |
| final 32 | 32 | bytes | tag | transport authentication tag |

The receiver MUST enforce its configured maximum payload before allocation.
The receiver MUST refuse expired authority before returning decoded work.

## 4. Message kinds

| Value | Kind | Direction | Meaning |
|---:|---|---|---|
| 1 | `HELLO` | client to server | propose versions, features, and limits |
| 2 | `ACCEPT` | server to client | select one version and feature subset |
| 3 | `RESULT` | server to client | return one complete exact result |
| 4 | `ERROR` | server to client | return one numeric refusal class |
| 5 | `CANCEL` | client to server | request cancellation for one admitted nonce |
| 6 | `STREAM_START` | server to client | start one ordered result stream |
| 7 | `STREAM_CHUNK` | server to client | return one non-empty result fragment |
| 8 | `STREAM_END` | server to client | finish one stream with rows and receipt |
| 9 | `BUNDLE_ACCEPTED` | server to client | acknowledge one registered operand bundle |
| 10 | `BUNDLE_REMOVED` | server to client | acknowledge one removed operand bundle |

Unknown authenticated kinds MUST return `UnsupportedFrame`.

## 5. Negotiation

`HELLO` and `ACCEPT` use correlation nonce zero.
Their payload contains exactly eight bytes:

| Offset | Width | HELLO | ACCEPT |
|---:|---:|---|---|
| 0 | 2 | minimum major | selected major, `2` |
| 2 | 2 | maximum major | selected minor, `0` |
| 4 | 4 | maximum chunk bytes | maximum chunk bytes |

Set `features` to the offered or selected feature bitmap.
Zero selects the base complete-result transport without optional features.
Set `auxiliary` to a maximum frame size of at least 168 bytes.
The maximum chunk MUST not exceed `auxiliary - 160`.
`ACCEPT` MUST select only features offered by `HELLO`.
The selected chunk and frame limits MUST not exceed either peer limit.

| Bit | Feature |
|---:|---|
| `0x00000001` | ordered result streaming |
| `0x00000002` | cancellation requests |
| `0x00000004` | registered operand bundle controls |

Negotiation occurs after authority provisioning and secure transport establishment.
It does not negotiate cryptographic algorithms or weaken authority checks.

## 6. Complete result

`RESULT` uses a non-zero correlation nonce and registered result shape.
Set sequence, features, auxiliary, and error code to zero.
Place the exact canonical result bytes in the payload.
Place the v0.2 execution receipt in the receipt field.
The receiver MUST verify the receipt against the request and exact result bytes.

Compute `request_digest` as unkeyed BLAKE3 over the complete v0.1 request frame.
Compute `result_digest` as unkeyed BLAKE3 over the complete canonical result bytes.
Compute the receipt with keyed BLAKE3 under the v0.1 `receipt_key`:

```text
"ndabi/wire/v2/execution-receipt"
|| context_digest || request_digest || LE64(nonce) || LE32(rows) || result_digest
```

The result digest permits incremental verification without retaining the complete streamed result.

## 7. Errors

`ERROR` uses a non-zero numeric error code.
Set sequence, rows, result shape, features, auxiliary, receipt, and payload to zero.
Correlation nonce zero identifies negotiation failure.
A non-zero correlation nonce identifies request failure.

| Code | Meaning |
|---:|---|
| 1 | unsupported version, kind, feature, engine, profile, or handle |
| 2 | non-canonical authenticated frame |
| 3 | authority mismatch |
| 4 | expired authority or deadline |
| 5 | result, row, payload, or resource budget exceeded |
| 6 | replay or sequence violation |
| 7 | cancellation accepted before commitment |
| 8 | backend refusal |
| 9 | output shape mismatch |
| 10 | internal failure without sensitive detail |

All other error codes are unregistered.
The receiver MUST refuse an authenticated frame that contains an unregistered error code.

Do not return human-readable diagnostics in the binary hot path.
A diagnostic surface MAY map the numeric code to local text outside NDABI.

## 8. Cancellation

`CANCEL` identifies one non-zero admitted request nonce.
All other semantic fields and payload MUST be zero.
Cancellation is a request, not proof of rollback.
The server MUST return code 7 only when no result commitment occurred.
The server MUST return the existing terminal result after commitment.

## 9. Streaming

`STREAM_START` uses sequence zero and a registered result shape.
Rows MAY contain the exact expected count or `u32::MAX` when unknown.
The start frame has no payload or receipt.

Each `STREAM_CHUNK` uses the same correlation nonce.
Sequence starts at one and increases by one without gaps.
Every chunk contains a non-empty payload.
The chunk has no rows, result shape, or receipt.

`STREAM_END` uses the next sequence number.
It contains final rows, result shape, and the execution receipt.
It has no payload.
The receipt covers the complete canonical result digest, not individual chunk boundaries.

The receiver MUST refuse duplicate, missing, reordered, or cross-request chunks.
The receiver MUST enforce cumulative row and byte budgets.
The receiver MUST discard an incomplete stream after failure.

## 10. Operand bundle acknowledgements

Use the `REGISTER_BUNDLE` and `REMOVE_BUNDLE` frames from the operand bundle candidate.
The client and server MUST authenticate the corresponding control before acknowledgement.
The connection MUST negotiate feature `0x00000004` before it registers a bundle control.

`BUNDLE_ACCEPTED` uses the registration nonce and registered result shape.
Its payload contains exactly 48 bytes.
The payload contains `LE32(bundle_handle)`, `LE32(graph_handle)`, `LE64(expiry)`, then the 32-byte bundle digest.
Every payload field MUST be non-zero.

`BUNDLE_REMOVED` uses the removal nonce and registered result shape.
Its payload contains exactly eight bytes.
The payload contains `LE32(bundle_handle)` followed by `LE32(graph_handle)`.
Both handles MUST be non-zero.

The receiver MUST match the acknowledgement to the authenticated control nonce, kind, graph, handle, expiry, and result shape.
The registration caller MUST supply the expected digest from the authenticated control and reviewed operand layout.
The receiver MUST match `BUNDLE_ACCEPTED` to that expected digest.
An `ERROR` can terminate either control, except code 7.

## 11. State machine

The connection starts in `PROVISIONED` state.
Only `HELLO` is valid before negotiation.
`ACCEPT` moves both peers to `READY` state.

One admitted request can end through exactly one terminal path:

```text
RESULT
ERROR
STREAM_START -> STREAM_CHUNK+ -> STREAM_END
CANCEL -> ERROR(7) or an already committed terminal result
REGISTER_BUNDLE -> BUNDLE_ACCEPTED or ERROR
REMOVE_BUNDLE -> BUNDLE_REMOVED or ERROR
```

The transport codec validates individual frames.
The connection implementation enforces this state machine and correlation ownership.
It bounds in-flight requests and requires increasing registered nonces.
It derives nonce, result shape, and budgets from the authenticated v0.1 request.
It removes terminal requests and refuses later frames for their correlations.

## 12. Conformance

A conforming codec MUST pass `ndabi-transport-conformance-v0.2`.
It MUST reproduce all ten valid message kinds exactly.
It MUST reproduce all seven invalid direction, authentication, authority, and canonicality cases.
It MUST return each registered invalid class exactly.
It MUST reject every single-bit mutation of every valid frame.
It MUST enforce maximum payload and authority expiry before returning decoded data.

The Rust, Go, and TypeScript codecs implement frame-level conformance.
The Rust connection enforces direction, negotiation, authenticated request registration, correlation, cancellation, sequencing, budgets, and receipts.
The independent Go sequence enforces negotiation, correlation, cancellation, streaming, budgets, receipts, and bundle acknowledgements.
Its request registration accepts only authenticated `Pending` values from the Go verifier.
The independent TypeScript sequence enforces the same paths and accepts only verifier-issued pending requests.
Both independent bundle-control decoders authenticate registration and removal through shared v0.1 vectors.
Their state machines bind decoder-issued metadata to the same authority session and context.
Both independent state machines pass the shared v0.2 negotiation and state-refusal vectors.
The v6.4 local Docker campaign connected complete results to the canonical PostgreSQL adapter.
The v8.4 candidate connected separate client and server processes through TLS 1.3 mutual authentication.
Its exact results, receipts, trust refusals, and same-CA certificate rotation passed in one diagnostic run.
The host-qualified performance result failed and retained no source or binary digest.
Treat every v8.4 transport measurement as unattributed diagnostics.
The portable codec and state conformance gate is implemented.

## 13. Security boundaries

Use TLS or an equivalent protected transport for remote connections.
NDABI tags authenticate frames but do not hide their contents.
TLS certificate validation and same-CA leaf rotation passed the v8.4 candidate.
NDABI authority exchange, revocation delivery, and production custody remain outside this candidate.
Database authority and row policies remain mandatory.
The server MUST avoid detailed internal errors on the binary surface.
