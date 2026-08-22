# NDABI PostgreSQL dense-operation campaign v3.1

**Status:** FROZEN before the first v3.1 result. **Date:** 2026-08-22.

This campaign replaces quadratic duplicate-identifier validation with canonical dense identifiers.
The v3.0 failed evidence remains unchanged.

Use binary SHA-256 `152a2b98c2e408d7014fc95df76a963e5022471a154645d629c917b308e26d8f`.

## 1. Fixed protocol change

Use NDABI core wire version 1.1.
Require each operation identifier to equal its one-based record position.
Validate identifiers in one linear pass without allocation.

Retain the complete authenticated frame, replay, deadline, binding, layout, and dependency checks.
Retain the v3.0 prepared-dataset environment and all four fair arms.

## 2. Hard gates

- All five processes must return complete results.
- Every process must report zero borrowed-decode allocations and bytes.
- Every process must return exact payload and receipt equality.
- Every batch size must return one result and receipt identity across all processes.
- Batch sizes 32 and 128 must reach four times sequential p95 speed.
- Batch sizes 32 and 128 must remain within 10% of native-set p95.
- Both speed-ratio coefficients of variation must remain below 20%.

Batch size 8 remains diagnostic.

## 3. Boundary

This campaign tests linear decoder validation in one Docker Desktop environment.
It does not prove native Linux, TLS, controlled WAN delay, concurrency, energy, or another engine.
