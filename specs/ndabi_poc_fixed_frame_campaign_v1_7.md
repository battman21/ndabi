# NDABI POC fixed-frame campaign v1.7

**Status:** FROZEN before the first v1.7 result. **Date:** 2026-08-22.

This campaign changes one v1.6 component.
It replaces dynamic fused-frame construction with a prepared fixed-size frame.

## 1. Cause and change

The v1.6 fused view passed its two registered speed targets.
It remained 12.97% slower than direct execution for the point case.

The v1.6 path cleared and extended a dynamic vector for every 21-byte request.
The v1.7 path prepares the invariant header and execution handle once.

Each hot execution writes only the nonce.
The resolver validates the fixed prefix and reads the nonce.

## 2. Frozen campaign

Use the same three cases, three Linux ARM64 replicas, result bytes, and operation counts as v1.6.
Use 63 measured batches and five warm-up batches.

Retain all v1.6 correctness, refusal, allocation, calibration, custody, and speed gates.
Require the fused path within 10% of direct execution for every case.

## 3. Boundary

This campaign measures a trusted local binding over a fixture engine.
It does not prove a socket, PostgreSQL, White Tree, remote model, or production result.
