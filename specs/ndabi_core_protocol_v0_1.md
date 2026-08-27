# NDABI core protocol v0.1

**Status:** IMPLEMENTED RESEARCH SLICE. **Date:** 2026-08-22.

This document defines the first bounded NDABI binary execution contract.
It does not define a public RFC or a production security protocol.

## 1. Purpose

NDABI carries complete typed execution units between an agent compiler and an engine adapter.
The format removes readable query syntax, repeated schemas, and repeated policy envelopes from the hot path.

The research parser validates `EXECUTE_ONE`, `EXECUTE_BATCH`, and `EXECUTE_GRAPH` frames.
It selects graph execution only when an adapter declares native graph support.
This slice does not contain an engine graph executor.
It does not support streaming, cancellation, result encoding, or network negotiation.

## 2. Required behaviour

An adapter must authenticate the complete frame before it allocates operation parameters.
It must bind the frame to one session, capability, schema, and generation.
It must refuse unknown versions, kinds, flags, reserved bytes, and non-canonical layouts.
It must refuse a frame at or after its declared deadline.

An adapter must accept each nonce once within one session generation.
It must not execute a partial authenticated frame.
It must not replace an unsupported batch or graph with hidden sequential operations.
It must restore the last accepted nonce when it restores a session generation.
It must bind the frame deadline and result budget to server-held limits.
It must authenticate a complete bounded frame before it returns semantic errors.

## 3. Integer and size rules

All integers use unsigned little-endian encoding.
The frame limit is 16 MiB.
The operation limit is 4,096.
The dependency limit is 16,384.
Each parameter block has a 1 MiB limit.

## 4. Frame header

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | Magic `NDBI` |
| 4 | 1 | Major version `1` |
| 5 | 1 | Minor version `0` |
| 6 | 1 | Frame kind |
| 7 | 1 | Frame flags |
| 8 | 4 | Complete frame bytes |
| 12 | 4 | Session handle |
| 16 | 4 | Capability handle |
| 20 | 4 | Schema handle |
| 24 | 2 | Operation count |
| 26 | 2 | Dependency count |
| 28 | 8 | Session generation |
| 36 | 8 | Monotonic nonce |
| 44 | 8 | Deadline as Unix microseconds |
| 52 | 4 | Maximum result bytes |
| 56 | 4 | Payload bytes |
| 60 | 4 | Reserved zero bytes |
| 64 | 16 | Truncated keyed BLAKE3 tag |

The tag covers the domain, header bytes 0 through 63, and the complete payload.
The domain is `ndabi-core-v1-frame`.

`FRAME_ATOMIC` is bit zero.
`FRAME_ALLOW_PARTIAL` is bit one.
The two flags cannot appear together.

## 5. Operation record

Each operation record uses 32 bytes.
Records appear first, dependencies appear second, and parameter blocks appear last.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | Operation identifier |
| 4 | 4 | Prepared plan handle |
| 8 | 4 | Transaction group |
| 12 | 4 | Result-shape handle |
| 16 | 4 | Parameter offset from payload start |
| 20 | 4 | Parameter bytes |
| 24 | 2 | First dependency index |
| 26 | 2 | Dependency count |
| 28 | 2 | Operation flags |
| 30 | 2 | Reserved zero bytes |

Every handle and operation identifier must be non-zero.
Every operation must declare exactly one of `READ` or `WRITE`.
The optional `IDEMPOTENT` flag does not change access authority.
The current read profile refuses `WRITE`.
A later admission protocol must define write authority and commitment.

## 6. Canonical execution forms

`EXECUTE_ONE` contains exactly one operation without dependencies.
`EXECUTE_BATCH` contains at least two independent operations.
`EXECUTE_GRAPH` contains at least two operations and one dependency.

Graph operations use topological order.
Each dependency references an earlier operation index.
Duplicate dependencies are invalid.

Parameter blocks and dependency ranges must form one contiguous canonical layout.
Equivalent frames cannot use padding, alternate offsets, or alternate record orders.

## 7. Planning rules

A single operation selects one direct prepared execution.
A homogeneous batch selects one set query when the profile supports set queries.
A heterogeneous batch selects one prepared pipeline when the profile supports pipelines.
A graph selects one server graph when the profile supports graph execution.

The planner must refuse an unavailable strategy.
It must not hide sequential database round trips behind one NDABI frame.

## 8. Lossless and security gates

The conformance suite must compare complete decoded structures.
It must change every authenticated byte and observe a refusal.
It must test replay, binding changes, generation changes, invalid dependencies, and transaction conflicts.

The implementation uses a 128-bit truncated keyed BLAKE3 tag for this research slice.
A public RFC requires independent cryptographic and protocol review.

The reference implementation compares tags with `subtle::ConstantTimeEq`.
It redacts and zeroises stored frame keys.
These controls do not prove deployed side-channel resistance.

The reference implementation provides an owned diagnostic decoder and a borrowed hot-path decoder.
The borrowed decoder authenticates and validates operation views without copying parameter blocks.

## 9. Unproved boundaries

This slice proves deterministic encoding, authenticated decoding, replay refusal, and execution-strategy selection.
It does not prove key custody, nonce persistence, transport security, interoperability, or production safety.
