# NDABI PostgreSQL column-batch campaign v3.2

**Status:** FROZEN before the first v3.2 result. **Date:** 2026-08-22.

This campaign replaces repeated homogeneous operation records with one column-batch descriptor.
The v3.1 failed evidence remains unchanged.

Use binary SHA-256 `8a37036e62e2e2435c33ea8c5a81aa816bad64dc92047d1d568657a2e5e64a88`.

## 1. Fixed protocol change

Use NDABI column-batch wire version 1.2.
Encode one prepared plan, result shape, policy, and fixed-width parameter column.
Use one implicit operation position for each parameter row.

Retain the complete authenticated frame, replay, deadline, binding, budget, and type-shape checks.
Retain the v3.1 prepared-dataset environment and all four fair arms.

Require frame sizes of 352 bytes for 32 rows and 1,120 bytes for 128 rows.
The prior record format used 1,360 bytes and 5,200 bytes respectively.

## 2. Hard gates

- All five processes must return complete results.
- Every process must report zero borrowed-decode allocations and bytes.
- Every process must return exact payload and receipt equality.
- Every process must return the registered column-frame size.
- Every batch size must return one result and receipt identity across all processes.
- Batch sizes 32 and 128 must reach four times sequential p95 speed.
- Batch sizes 32 and 128 must remain within 10% of native-set p95.
- Both speed-ratio coefficients of variation must remain below 20%.

Batch size 8 remains diagnostic.

## 3. Boundary

This campaign tests one fixed-width homogeneous parameter profile.
It does not prove variable-width columns, graphs, native Linux, TLS, WAN delay, concurrency, energy, or another engine.
