# NDABI PostgreSQL borrowed batch campaign v2.8

**Status:** FROZEN before the first v2.8 result. **Date:** 2026-08-22.

This campaign changes only the NDABI decode ownership and one v2.7 gate mismatch.
The v2.7 failed evidence remains unchanged.

## 1. Fixed changes

Verify the authenticated frame through borrowed operation and parameter views.
Reuse one identifier buffer for the PostgreSQL array.
Do not allocate one owned operation or parameter buffer per decoded operation.

Apply the native-distance speed gate only to batch sizes 32 and 128.
The v2.7 contract made batch size 8 diagnostic, but its implementation applied a speed gate.

## 2. Retained environment and arms

Retain the v2.7 PostgreSQL image, rows, queries, arms, batch sizes, samples, and rotation.
Retain complete result and receipt equality across every arm.
Retain the four-times sequential speed gate at batch sizes 32 and 128.
Retain the maximum 1.10 native-set distance at batch sizes 32 and 128.

## 3. New hard gate

Decode and inspect one authenticated 128-operation frame before database work.
Require zero measured Rust allocations and zero allocated bytes for that borrowed decode.

## 4. Boundary

This campaign tests one local Docker process.
It does not prove repeatability, native Linux, TLS, WAN delay, concurrency, energy, or another engine.
