# NDABI column-batch profile v0.1

**Status:** IMPLEMENTED RESEARCH SLICE. **Date:** 2026-08-22.

This profile defines one homogeneous prepared-plan batch for NDABI core version 1.2.
It removes one repeated operation record for every parameter row.

## 1. Execution meaning

One frame selects one prepared plan, result shape, transaction group, and operation policy.
The parameter payload contains fixed-width typed rows defined by the schema and plan handles.

The adapter must execute the complete column as one set operation.
It must not replace the column with sequential database round trips.

## 2. Header

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | Magic `NDBI` |
| 4 | 1 | Major version `1` |
| 5 | 1 | Minor version `2` |
| 6 | 1 | Column-batch kind `4` |
| 7 | 1 | Frame flags |
| 8 | 4 | Complete frame bytes |
| 12 | 4 | Session handle |
| 16 | 4 | Capability handle |
| 20 | 4 | Schema handle |
| 24 | 2 | Row count |
| 26 | 2 | Column count |
| 28 | 8 | Session generation |
| 36 | 8 | Monotonic nonce |
| 44 | 8 | Deadline as Unix microseconds |
| 52 | 4 | Maximum result bytes |
| 56 | 4 | Prepared plan handle |
| 60 | 4 | Result-shape handle |
| 64 | 4 | Transaction group |
| 68 | 2 | Operation flags |
| 70 | 2 | Bytes per row |
| 72 | 4 | Parameter bytes |
| 76 | 4 | Reserved zero bytes |
| 80 | 16 | Truncated keyed BLAKE3 tag |

The parameter column starts at byte 96.
Its length must equal row count multiplied by bytes per row.

## 3. Bounds and refusals

The row count must remain between 2 and 4,096.
The row width must remain between 1 and 4,096 bytes.
The complete frame must not exceed 16 MiB.

The verifier must refuse replay, expiry, changed bindings, invalid flags, invalid lengths, and changed authenticated bytes.
It must expose borrowed row views without allocating parameter objects.
It must restore the last nonce when it restores the same generation.
It must refuse budgets or deadlines above server-held binding limits.
The adapter must refuse a result which exceeds the authenticated result budget.
The current profile refuses write operations.

## 4. Boundary

This profile supports homogeneous fixed-width parameters.
Variable-width columns, null maps, heterogeneous batches, graphs, results, and negotiation remain outside this slice.

