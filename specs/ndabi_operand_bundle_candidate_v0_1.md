# NDABI prepared operand and bundle candidate v0.1

**Status:** Implemented research candidate.

The protocol crate implements layouts, three request frames, a session store, bundled receipts, and transport acknowledgements.
Independent Go and TypeScript decoders authenticate registration and removal through shared vectors.
PostgreSQL and Supabase implement one review-batch bundle profile with focused Docker proof.
MongoDB and White Tree adapters and comparative performance evidence do not exist.

**Parents:** `ndabi_registered_graph_candidate_v0_1.md` and `ndabi_transport_candidate_v0_2.md`.

## 1. Purpose

This extension removes repeated operand construction from registered graph execution.
It keeps query text, graph topology, schemas, and policy descriptions outside the hot path.

The extension has two independent parts:

| Part | Location | Removed work |
|---|---|---|
| prepared operand template | client process | allocation, header construction, and unchanged operand copying |
| session operand bundle | trusted adapter | repeated agent-to-adapter operand transport and decoding |

Neither part removes database planning, execution, permissions, row policies, or result verification.
An adapter-side bundle does not prove reduced database-wire traffic.

## 2. Required boundary

A bundle is immutable after registration.
A bundle belongs to one authority session, generation, context digest, registry digest, and graph handle.
A bundle never crosses tenants, principals, purposes, sessions, or registry generations.

The trusted registry defines every operand slot before execution.
An untrusted model can select handles and provide registered slot values only.
It cannot define offsets, types, collection names, SQL, operators, policies, or executable code.

The first candidate supports read graphs only.
It does not define writes, transactions, durable cross-session caches, or shared public caches.

## 3. Canonical operand layout

A bundle-capable graph binds one ordered operand layout through its existing parameter-schema digest.
Sort all layout records by increasing slot identifier before digest calculation.

Each layout record contains these fields:

| Field | Type | Rule |
|---|---|---|
| slot identifier | `u16` | Non-zero and unique. |
| storage class | `u8` | `1` for bundle or `2` for each execution. |
| value type | `u8` | One registered portable type. |
| flags | `u16` | Only the nullable bit can be set. |
| maximum value bytes | `u32` | Exact width for fixed values; upper bound for variable values. |

Encode each layout record with this exact 10-byte concatenation:

```text
LE16(slot_id) || U8(storage_class) || U8(value_type)
|| LE16(flags) || LE32(maximum_value_bytes)
```

The portable value types use these codes and non-null widths:

| Code | Type | Value bytes |
|---:|---|---:|
| 1 | `BOOL` | 1 |
| 2 | `I64` | 8 |
| 3 | `U64` | 8 |
| 4 | `I128` | 16 |
| 5 | `F64` | 8 |
| 6 | `TIMESTAMP_US` | 8 |
| 7 | `UUID` | 16 |
| 8 | `BYTES` | zero to the registered maximum |
| 9 | `UTF8` | zero to the registered maximum |

`BOOL` uses one byte containing zero or one.
Integers use little-endian two's-complement encoding.
`F64` accepts finite IEEE 754 binary64 values only.
`TIMESTAMP_US` uses a signed 64-bit Unix microsecond value.
`UUID` uses 16 network-order bytes.
`UTF8` must contain valid UTF-8 without normalisation.

Profiles can define more types through a new parameter-schema digest and profile identifier.
The base protocol must refuse an unknown type.
An existing graph cannot gain bundle semantics without a new schema digest and profile identifier.

Compute the parameter-schema digest over this exact concatenation:

```text
BLAKE3(
  "ndabi/wire/v1/operand-layout"
  || LE32(layout_record_count)
  || sorted_layout_records
)
```

The layout must contain at least one slot and no more than 4,096 slots.
The total declared value limit must not exceed one MiB.

## 4. Canonical value records

Encode each value record as this concatenation:

```text
LE16(slot_id) || U8(value_type) || U8(value_flags)
|| LE32(value_bytes) || value
```

Set value flag bit zero only for `NULL`.
A null value must declare zero value bytes.
The layout must permit null before a record can contain it.

Sort value records by slot identifier.
Reject duplicates, missing required slots, type drift, unknown flags, padding, and trailing bytes.
Bundle registration must contain every bundle-class slot exactly once.
Bundle execution must contain every execution-class slot exactly once.

This split gives one logical operand set one canonical composition.
Changing a bundle-class value requires a new bundle registration.

## 5. Client prepared template

The prepared template is a local API object, not a wire object.
It retains the canonical header, layout, bundle values, and fixed-width execution slots.

Each execution updates only these fields:

1. Execution-class slot values.
2. The request nonce.
3. The deadline.
4. The authentication tag.

The first candidate must refuse variable-width slot updates that require buffer growth.
A later implementation can add bounded reusable capacity without changing the wire format.

The template must keep its byte buffer private.
It must bind the authority context before each signing operation.
It must not consume a nonce after any validation failure.
It must zero retained operand bytes on drop.

## 6. Bundle registration frame

Transport feature bit `0x00000004` means operand-bundle support.
Both peers must negotiate this feature before they use bundle frames or acknowledgements.

The registration frame contains `160 + B` bytes.
`B` contains the canonical bundle-class value records.

Authenticate the complete frame under the existing frame key:

```text
"ndabi/wire/v1/register-operand-bundle" || frame[0..tag_offset]
```

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | `NDBI` |
| 4 | 1 | major | `1` |
| 5 | 1 | minor | `0` |
| 6 | 1 | frame kind | `5` |
| 7 | 1 | access class | `1`, read |
| 8 | 2 | flags | zero |
| 10 | 2 | opcode | registered graph opcode |
| 12 | 4 | complete frame bytes | exact length |
| 16 | 8 | session | authority session |
| 24 | 8 | generation | authority generation |
| 32 | 8 | nonce | next session nonce |
| 40 | 8 | bundle expiry | not after authority expiry |
| 48 | 4 | value bytes | exact `B` |
| 52 | 4 | bundle slot count | exact registered count |
| 56 | 4 | graph handle | registered handle |
| 60 | 4 | result shape | registered shape |
| 64 | 4 | bundle handle | non-zero session-local handle |
| 68 | 28 | reserved | zero |
| 96 | 32 | authority context digest | exact binding |
| 128 | `B` | bundle values | canonical records |
| `128 + B` | 32 | authentication tag | complete keyed tag |

The client selects a bundle handle that is unused in the session generation.
The server must refuse handle reuse, including identical content.

## 7. Bundle execution frame

The execution frame contains `160 + D` bytes.
`D` contains the canonical execution-class value records.

Authenticate the complete frame under the existing frame key:

```text
"ndabi/wire/v1/execute-bundled-graph" || frame[0..tag_offset]
```

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | `NDBI` |
| 4 | 1 | major | `1` |
| 5 | 1 | minor | `0` |
| 6 | 1 | frame kind | `6` |
| 7 | 1 | access class | `1`, read |
| 8 | 2 | flags | zero |
| 10 | 2 | opcode | registered graph opcode |
| 12 | 4 | complete frame bytes | exact length |
| 16 | 8 | session | authority session |
| 24 | 8 | generation | authority generation |
| 32 | 8 | nonce | next session nonce |
| 40 | 8 | deadline | Unix microseconds |
| 48 | 4 | result-byte budget | non-zero |
| 52 | 4 | result-row budget | non-zero |
| 56 | 4 | graph handle | registered handle |
| 60 | 4 | result shape | registered shape |
| 64 | 4 | bundle handle | registered session handle |
| 68 | 4 | value bytes | exact `D` |
| 72 | 4 | execution slot count | exact registered count |
| 76 | 20 | reserved | zero |
| 96 | 32 | authority context digest | exact binding |
| 128 | `D` | execution values | canonical records |
| `128 + D` | 32 | authentication tag | complete keyed tag |

An all-bundle layout uses zero execution slots and zero value bytes.
The fixed authenticated frame then contains 160 bytes.

## 8. Bundle removal frame

The removal frame contains exactly 160 bytes.

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | `NDBI` |
| 4 | 1 | major | `1` |
| 5 | 1 | minor | `0` |
| 6 | 1 | frame kind | `7` |
| 7 | 1 | access class | `1`, read |
| 8 | 2 | flags | zero |
| 10 | 2 | opcode | registered graph opcode |
| 12 | 4 | complete frame bytes | `160` |
| 16 | 8 | session | authority session |
| 24 | 8 | generation | authority generation |
| 32 | 8 | nonce | next session nonce |
| 40 | 8 | deadline | Unix microseconds |
| 48 | 8 | reserved | zero |
| 56 | 4 | graph handle | registered handle |
| 60 | 4 | result shape | registered shape |
| 64 | 4 | bundle handle | registered session handle |
| 68 | 28 | reserved | zero |
| 96 | 32 | authority context digest | exact binding |
| 128 | 32 | authentication tag | complete keyed tag |

Authenticate it with domain `ndabi/wire/v1/drop-operand-bundle`.
The server must tombstone the handle before it acknowledges removal.
It must not reuse a removed handle within the session generation.

## 9. Digests and receipts

Compute the immutable bundle digest as follows:

```text
BLAKE3(
  "ndabi/wire/v1/operand-bundle"
  || context_digest
  || LE32(graph_handle)
  || parameter_schema_digest
  || LE32(bundle_handle)
  || LE64(bundle_expiry)
  || canonical_bundle_value_records
)
```

Compute the execution-value digest over the canonical execution records:

```text
BLAKE3(
  "ndabi/wire/v1/execution-operands"
  || parameter_schema_digest
  || canonical_execution_value_records
)
```

Compute the effective operand digest as follows:

```text
BLAKE3(
  "ndabi/wire/v1/effective-operands"
  || bundle_digest
  || execution_value_digest
)
```

The terminal receipt must bind the effective operand digest.
It must also bind the complete request digest, nonce, rows, and exact result digest.

```text
"ndabi/wire/v3/bundled-execution-receipt"
|| context_digest || request_digest || effective_operand_digest
|| LE64(nonce) || LE32(rows) || result_digest
```

The client must know the accepted bundle digest before execution.

Extend the v0.2 transport with these server-to-client message kinds:

| Value | Kind | Correlation | Payload |
|---:|---|---|---|
| 9 | `BUNDLE_ACCEPTED` | registration nonce | 48-byte accepted-bundle record |
| 10 | `BUNDLE_REMOVED` | removal nonce | 8-byte removed-bundle record |

The accepted-bundle record contains the bundle handle, graph handle, expiry, and 32-byte bundle digest.
The removed-bundle record contains the bundle handle and graph handle.
Use little-endian integers and no padding.

Set sequence, rows, features, auxiliary, and execution receipt to zero.
Set the transport result shape to the registered graph result shape.
The existing transport tag authenticates the complete acknowledgement.

An uncertain acknowledgement invalidates the client session.
The client must not guess whether registration succeeded.

Map an unavailable bundle to transport error code `11`.
Map a collision, schema failure, or cache-limit refusal to transport error code `12`.
Neither error can contain human-readable details on the binary surface.

## 10. Admission order

Bundle registration must use this order:

1. Check the bounded frame length.
2. Authenticate the complete frame.
3. Check canonical header fields and reserved bytes.
4. Check authority, expiry, and the next nonce.
5. Resolve the registered graph and operand layout.
6. Validate every bundle value without allocation.
7. Check per-session count and byte budgets.
8. Allocate and copy the accepted immutable values once.
9. Commit the bundle and replay state atomically.
10. Return the authenticated bundle acknowledgement.

Registration must not perform a database query or governed data read.

Bundle execution must use this order:

1. Authenticate and validate the complete execution frame.
2. Check authority, deadline, budgets, and the next nonce.
3. Resolve the graph and immutable bundle.
4. Reject expired, missing, removed, or identity-mismatched bundles.
5. Validate every execution value without allocation.
6. Dispatch one native backend operation.
7. Check the deadline again.
8. Commit replay state.
9. Return the exact result and bundled execution receipt.

No failure may trigger readable-query construction or sequential fallback.

## 11. Cache lifecycle

The server must configure all these limits:

| Limit | Required bound |
|---|---|
| bundles per session | finite and non-zero |
| bytes per bundle | no more than one MiB |
| total bundle bytes per session | finite and non-zero |
| bundle expiry | not after authority expiry |
| concurrent readers per bundle | finite and non-zero |

The server can evict a bundle before expiry for resource control.
An eviction must make later execution fail with `OperandBundleNotFound`.
The server must not rebuild, re-register, or execute a fallback automatically.

A new authority generation invalidates every earlier bundle.
A registry activation or revocation invalidates every bundle bound to the earlier registry digest.
Authority expiry invalidates every bundle in that authority session.

Concurrent executions can borrow one immutable bundle.
Removal blocks new borrowers and waits for existing borrowers before zeroing memory.
The server must zero bundle bytes before releasing their storage.
It must not log raw bundle values or execution values.

## 12. Backend contract

The backend receives the immutable bundle values and execution values as separate borrowed views.
It must bind values in registered slot order.
It must not concatenate a complete parameter block on the qualified zero-copy path.

The PostgreSQL profile binds both views directly to one prepared statement or set query.
PostgreSQL still receives required parameter bytes through its native protocol.

The Supabase profile uses one admitted user identity and forced row-level security.
It must compare the authority tenant and principal with the admitted JWT identity before bundle lookup.
Bundle expiry must not exceed the admitted JWT expiry.
Bundle caching must not depend on a durable pooled database session.

Every adapter must reapply its database authority and policy checks during each execution.
Registration alone never authorises later data access.

The MongoDB profile maps registered slots to fixed BSON fields and operators.
It must not accept agent-authored field names, collections, or operators.

The White Tree profile can consume both borrowed views inside the embedded engine boundary.
It must preserve governance, clock, evidence, and receipt checks.

## 13. Security and lossless gates

Conformance must prove these behaviours:

- Every changed authenticated bit fails before bundle lookup or backend work.
- Missing, duplicate, reordered, mistyped, and excessive slots fail before allocation.
- Context, session, generation, registry, graph, and result-shape drift fail before dispatch.
- Expired, evicted, removed, and reused bundle handles fail closed.
- A failed registration or execution does not consume a nonce.
- Bundle removal never changes an in-flight execution.
- Exact effective operands produce exact cross-arm results.
- Every changed request, operand digest, result, row count, or receipt fails verification.
- PostgreSQL and MongoDB read-only identities still refuse writes.
- Supabase forced row-level security still filters exact results.
- White Tree governance still reports withheld and unknown states correctly.

Each adapter must provide this minimum proof:

| Adapter | Required successful path | Required refusal |
|---|---|---|
| PostgreSQL | one prepared set query with borrowed registered values | write attempt and role drift |
| Supabase | one admitted forced-RLS user execution | tenant, principal, JWT-expiry, and policy drift |
| MongoDB | one registered BSON filter with fixed operators | collection, field, operator, and write drift |
| White Tree | one governed result with exact receipt | clock, profile, evidence, and governance drift |

Production custody, remote administration, public signatures, and denial-of-service policy remain unproved.

## 14. Performance campaign

Measure prepared templates and server bundles separately.
Compare them with the existing graph frame, concise JSON, and expert fused-native execution.

Use static operand sizes of 64 bytes, one KiB, 64 KiB, and one MiB.
Use zero, one, eight, and 256 execution-class slots.
Use concurrency one, eight, and 32.
Use local embedded, local Docker, controlled 2 ms, and controlled 40 ms paths.

Apply these candidate gates:

| Boundary | Gate |
|---|---|
| prepared-template encoding CPU | at least 70% below fresh graph encoding |
| prepared-template hot allocations | zero after construction |
| bundled execute request bytes | match the frozen byte model and reduce this profile by at least 70% at 1,024 items |
| adapter operand-decoding CPU | at least 70% below the current graph decoder for one KiB or larger static operands |
| protocol-dominant complete-stack CPU | at least 25% below the current graph path |
| protocol-dominant p95 | at least 25% below the current graph path |
| database-dominant fused-native mean | no more than 3% overhead |
| database-dominant fused-native p95 | no more than 5% overhead |
| complete result and receipt equality | exact in every sample |

Compute the request-byte gate from the complete authenticated frames.
The PostgreSQL profile keeps three quarters of operand bytes static and one quarter dynamic.
Its theoretical large-batch reduction therefore approaches 75%, not 90%.
Apply a 90% gate only when the frozen workload keeps at least 90% of operand bytes static.

Do not apply the complete-stack reduction gates to database-dominant cells.
Report those cells against the fused-native floor instead.

Bundle registration cost must remain outside execution latency reports.
Report amortisation after one, eight, 256, and 4,096 executions.
Reject any result that hides registration, eviction, or database-wire costs.

## 15. Model and token boundary

Binary bundle frames can reduce agent-host and adapter transport bytes.
They do not prove model-token savings.

A provider call still tokenises visible tool names, argument names, system instructions, and human text.
Measure tokens only through a provider-reported token counter.
Compare an equivalent textual tool contract with a compact handle contract.

## 16. Promotion boundary

This document includes an implemented core slice.
Promote the complete extension after transport acknowledgement and adapter conformance passes.
Promote performance claims only after the frozen comparative campaign passes every gate.
