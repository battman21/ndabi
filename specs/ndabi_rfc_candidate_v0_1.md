# NDABI RFC candidate v0.1

**Status:** Implemented candidate subset. This document is not a public RFC or a production standard.

**Name:** Neural Data Access Binary Interface.

**Scope:** Authenticated, read-only execution of registered plans through one fixed frame or one homogeneous batch frame.

## 1. Purpose

NDABI removes repeated textual query syntax, field names, object wrappers, and plan construction from the hot path.
An adapter maps a semantic agent request to a registered plan handle before it creates a frame.
The database engine still controls planning, indexing, transactions, isolation, and storage.
NDABI does not replace a database engine or permit arbitrary machine instructions.

The binary format provides compact transport and constant-layout decoding.
Registered plans and fused execution provide most measured speed gains.
Binary encoding alone does not bypass database execution time or network latency.

## 2. Normative language

The terms **MUST**, **MUST NOT**, **REQUIRED**, and **MAY** define conformance requirements.
All multibyte integers use little-endian encoding.
All offsets use zero-based byte positions.
All digests and tags contain 32 bytes.

## 3. Roles

The compiler maps an agent request to a finite operation, authority, budgets, and deadline.
The encoder creates the authenticated frame.
The decoder authenticates and admits the complete frame before backend execution.
The backend binds a plan handle to one fixed query or governed engine operation.
The replay store records successful nonce transitions.

An agent MAY emit NDABI through a constrained tool interface.
A model does not need to emit hexadecimal text.
The host SHOULD pass raw bytes or structured integer fields to the encoder.

## 4. Authority context

Provision the following values outside the frame:

| Field | Width | Meaning |
|---|---:|---|
| root key | 32 bytes | shared frame and receipt authority |
| generation | `u64` | authority generation |
| session | `u64` | session identity |
| expiry | `u64` | authority expiry in Unix microseconds |
| tenant | 16 bytes | tenant identity |
| principal | 16 bytes | principal identity |
| purpose | `u32` | authorised purpose |
| capability digest | 32 bytes | admitted capability set |
| engine and profile | two `u32` values | backend and finite operation profile |
| schema, policy, and plan digests | three 32-byte values | pinned execution context |

Compute `context_digest` as unkeyed BLAKE3 over this exact concatenation:

```text
"ndabi/wire/v1/context"
|| tenant || principal || LE32(purpose) || capability_digest
|| LE32(engine) || LE32(profile)
|| schema_digest || policy_digest || plan_digest
```

Derive `frame_key` with keyed BLAKE3 under `root_key` over this exact concatenation:

```text
"ndabi/wire/v1/session-key"
|| LE64(generation) || LE64(session) || LE64(expiry) || context_digest
```

Derive `receipt_key` identically, using `"ndabi/wire/v1/receipt-key"` as the domain.
Implementations MUST protect the root and derived keys.
The public conformance keys are test material only.
The root key, identities, and authority digests MUST be non-zero.

## 5. Single execute-handle frame

The single frame contains exactly 160 bytes.
Authenticate bytes `0..127` under `frame_key` with this keyed BLAKE3 input:

```text
"ndabi/wire/v1/frame" || frame[0..128]
```

Store the resulting tag in bytes `128..159`.

| Offset | Width | Type | Field | Required value |
|---:|---:|---|---|---|
| 0 | 4 | bytes | magic | `NDBI` |
| 4 | 1 | `u8` | major | `1` |
| 5 | 1 | `u8` | minor | `0` |
| 6 | 1 | `u8` | kind | `1` |
| 7 | 1 | `u8` | access | `1`, read |
| 8 | 2 | `u16` | flags | `0` |
| 10 | 2 | `u16` | opcode | non-zero registered opcode |
| 12 | 4 | `u32` | frame bytes | `160` |
| 16 | 8 | `u64` | session | configured session |
| 24 | 8 | `u64` | generation | configured generation |
| 32 | 8 | `u64` | nonce | next session nonce |
| 40 | 8 | `u64` | deadline | Unix microseconds |
| 48 | 4 | `u32` | result budget | maximum result bytes |
| 52 | 4 | `u32` | row budget | maximum rows |
| 56 | 4 | `u32` | plan handle | non-zero registered handle |
| 60 | 4 | `u32` | result shape | non-zero registered shape |
| 64 | 8 | `i64` | first operand | profile-defined |
| 72 | 8 | `i64` | second operand | profile-defined |
| 80 | 4 | `u32` | third operand | profile-defined |
| 84 | 12 | bytes | reserved | all zero |
| 96 | 32 | bytes | context digest | configured context |
| 128 | 32 | bytes | tag | authenticated tag |

## 6. Homogeneous batch frame

The batch frame contains `160 + 20N` bytes for `2 <= N <= 4096`.
Authenticate every byte before the final tag with this keyed BLAKE3 input:

```text
"ndabi/wire/v1/batch-frame" || frame[0..tag_offset]
```

The common fields at offsets `0..63` match the single frame.
Set kind to `2` and set frame bytes to the actual length.

| Offset | Width | Type | Field | Required value |
|---:|---:|---|---|---|
| 64 | 4 | `u32` | operation count | `N` |
| 68 | 4 | `u32` | operand stride | `20` |
| 72 | 4 | `u32` | payload bytes | `20N` |
| 76 | 20 | bytes | reserved | all zero |
| 96 | 32 | bytes | context digest | configured context |
| 128 | `20N` | repeated tuple | operands | `i64`, `i64`, `u32` |
| `128 + 20N` | 32 | bytes | tag | authenticated tag |

The backend MUST execute the complete batch as one fused engine operation.
The backend MUST refuse an adapter that loops over independent database calls.

## 7. Admission and execution

The decoder MUST apply this order:

1. Select the candidate frame domain from the received length.
2. Derive authority keys from configured values.
3. Verify the complete tag with constant-time comparison.
4. Verify magic, version, kind, and read access.
5. Verify fixed lengths, strides, and zero reserved bytes.
6. Verify session, generation, and context digest.
7. Verify batch counts, payload length, and operation limit.
8. Verify the deadline against admission time and authority expiry.
9. Verify the result and row budgets against server limits.
10. Verify that the nonce equals the last accepted nonce plus one.
11. Verify all required operation identifiers are non-zero.

The server MUST validate configured authority fields before frame admission.
The decoder MUST NOT interpret unauthenticated operation fields.
The server MUST verify the registered backend identity before execution.
The decoder MUST keep admitted operation fields immutable until execution completes.
The backend MUST enforce the admitted row, byte, and deadline limits.
The server MUST check the deadline again after execution.
The replay store MUST commit only after successful bounded execution.

## 8. Replay identity

Key replay state by `context_digest`, session, and generation.
Start each new replay identity at nonce zero.
Accept nonce one as its first frame.
Refuse gaps, duplicates, rollback, and nonce exhaustion.
Commit each nonce transition with an atomic compare-and-set operation.
Bind commitment to the decoder-issued admission capability.
Do not derive commitment from caller-mutable decoded fields.
Use transaction-coupled storage when backend effects can change persistent state.

## 9. Execution receipt

Compute `frame_digest` as unkeyed BLAKE3 over the complete authenticated frame.
Compute the receipt with keyed BLAKE3 under `receipt_key` over this exact concatenation:

```text
"ndabi/wire/v1/receipt"
|| context_digest || frame_digest
|| LE64(nonce) || LE32(rows) || exact_result_bytes
```

This receipt proves shared-key possession only.
It does not provide public verification or non-repudiation.

## 10. Error classes

A conforming decoder MUST distinguish these admission classes:

| Class | Meaning |
|---|---|
| `LengthMismatch` | the received length cannot identify a candidate frame domain |
| `AuthenticationFailed` | the complete frame tag differs |
| `UnsupportedFrame` | the authenticated header requests an unsupported frame |
| `NonCanonicalFrame` | authenticated fixed fields violate canonical encoding |
| `AuthorityMismatch` | authenticated authority fields differ from configured authority |
| `Expired` | the deadline passed or exceeds authority expiry |
| `BudgetExceeded` | an authenticated budget exceeds server limits |
| `Replay` | the nonce is not the next accepted nonce |
| `ReplayConflict` | another execution changed replay state before commit |
| `ReplayStoreUnavailable` | required replay state is unavailable |
| `ZeroKey` | the configured root key is zero |
| `ZeroIdentity` | a required configured identity is zero |
| `ZeroDigest` | a required configured authority digest is zero |
| `ZeroOperationField` | a required registered operation identifier is zero |
| `BatchTooSmall` | the batch contains fewer than two operations |
| `BatchLimitExceeded` | the batch exceeds 4,096 operations |

The v0.2 transport candidate maps these classes to numeric response codes.
Version 0.1 does not define its own response envelope.

## 11. Backend registry

| Surface | Engine | Profile | Candidate binding |
|---|---:|---:|---|
| PostgreSQL | `0x50470001` | `0x50471001` | registered range and point-read plans |
| MongoDB | `0x4d470001` | `0x4d471001` | finite identifier-window reads |
| White Tree | `0x57540001` | `0x57541001` | governed context reads |
| Supabase direct | PostgreSQL | PostgreSQL profile | trusted service connection |
| Supabase PostgREST | none | none | user-JWT reference control surface |

Supabase is not a separate database engine.
Use PostgreSQL NDABI for trusted direct or session connections.
Use the PostgREST binding when user JWT row-level security is the authority boundary.
Transaction-mode poolers MUST NOT assume durable prepared statements across transactions.

## 12. Negotiation and compatibility

Version and profile negotiation occur outside the v0.1 request frame.
The authenticated v0.2 transport candidate defines post-provisioning negotiation.
The connection setup MUST pin the supported major version, backend identity, and plan registry.
A decoder MUST refuse unknown authenticated versions, kinds, access modes, engines, profiles, or handles.
Future incompatible layouts require a new major version.
Future compatible profiles require separate registered profile identifiers and vectors.

## 13. Conformance

A conforming implementation MUST pass the committed `ndabi-conformance-v0.1` vectors.
The JSON manifest encodes every 64-bit integer as a base-ten string.
Implementations MUST parse these strings without floating-point conversion.
It MUST reproduce both valid decodes and both execution receipts exactly.
It MUST return the specified class for each invalid vector.
It MUST reject every single-bit mutation of each valid frame.
It MUST accept verification before execution without changing replay state.
It MUST refuse the same frame after the successful nonce commit.

The Rust generator defines the implemented reference bytes.
The Go and TypeScript decoders are independent cross-language implementations.
Agreement between three implementations reduces shared-code false confidence.

## 14. Security boundaries

Use a protected transport for remote connections.
NDABI authentication does not hide frame contents.
Do not log root keys, derived keys, frames containing sensitive operands, or raw results.
Apply database permissions and row policies independently of NDABI.
Bind each plan handle to a fixed parameter schema and maximum output shape.
Refuse arbitrary SQL, collection names, operators, projections, and sort specifications in this version.

Key provisioning, rotation, revocation, custody, transport security, and denial-of-service policy remain deployment responsibilities.
The Go implementation cannot guarantee compiler-resistant key zeroisation.
The candidate does not establish production key custody.

## 15. Explicit exclusions

Version 0.1 does not define writes, arbitrary SQL, graph instructions, streaming, cancellation, or public-key receipts.
It does not define model token encoding, tool-call transport, TLS, WAN routing, or hosted Supabase behaviour.
It does not prove token savings, energy savings, or general database speed.
Existing benchmark results apply only to their registered profiles and recorded environments.
