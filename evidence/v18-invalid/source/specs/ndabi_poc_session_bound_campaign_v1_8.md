# NDABI POC session-bound campaign v1.8

**Status:** FROZEN before the first v1.8 result. **Date:** 2026-08-22.

This campaign changes one v1.7 component.
It binds the prepared execution handle to the trusted session before measurement.

## 1. Cause and change

The v1.7 fused path remained 11.23% slower than direct execution for the point case.
It repeated an invariant handle and validated its prefix for every operation.

The v1.8 prepare phase resolves the capability, command, and execution handle once.
The hot execute frame contains only an eight-byte nonce.

The kernel still checks authority, expiry, snapshot, budget, and replay for every operation.
The result remains a read-only borrowed view with an exact receipt.

## 2. Frozen campaign

Use the same three cases, three Linux ARM64 replicas, result bytes, and operation counts as v1.7.
Use 63 measured batches and five warm-up batches.

Retain all v1.7 correctness, refusal, allocation, calibration, custody, and speed gates.
Require the session-bound path within 10% of direct execution for every case.

## 3. Boundary

This campaign measures a trusted local session over a fixture engine.
It excludes handle preparation from the hot operation by design.

It does not prove a socket, PostgreSQL, White Tree, remote model, or production result.
