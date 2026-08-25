# NDABI PostgreSQL real-engine campaign v2.5

**Status:** FROZEN before the first v2.5 result. **Date:** 2026-08-22.

This campaign tests NDABI against PostgreSQL 16 through the native PostgreSQL protocol.

## 1. Fixed environment

Use local image `postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20`.
Create one ephemeral container and remove it after the campaign.
Use one persistent host connection over loopback TCP.

Create 100,000 indexed rows inside PostgreSQL.
Select row 99,999 by its primary key.
Return one integer identifier, one integer bucket, and one 64-byte payload.

## 2. Arms

| Arm | PostgreSQL path | Client request |
|---|---|---|
| Simple SQL | Simple query protocol and text result | A complete SQL string |
| Native prepared | Named prepared statement and binary result | A typed integer parameter |
| Full NDABI | The same prepared statement and binary result | An authenticated 72-byte frame |
| Session NDABI | The same prepared statement and binary result | A 24-byte bound frame |
| Direct repeat | The same prepared statement and binary result | A typed integer parameter |

Every arm must calculate the same adapter policy and result receipt.
Every arm must return one byte-identical canonical payload.

Run 63 measured samples after five warm-up samples.
Run eight operations in each sample and rotate the arm order.

## 3. Hard gates

- Every arm must return one byte-identical canonical payload and receipt core.
- A modified full frame, wrong handle, wrong generation, and replayed nonce must fail closed.
- Native prepared and direct-repeat p95 must remain within 10%.
- Session NDABI p95 must be no more than 10% slower than native prepared.
- Full NDABI p95 must be no more than 50% slower than session NDABI.
- Simple SQL must be at least 1.10 times slower than session NDABI.

## 4. Evidence and boundary

Record p50, p95, p99, throughput, Rust allocations, allocated bytes, request bytes, and response bytes.
Record the PostgreSQL version, image digest, binary digest, complete samples, and gate result.

Request bytes are application payload sizes, not captured network bytes.
The allocation counter excludes PostgreSQL server allocations.
This campaign excludes TLS, pipelines, concurrency, server CPU, and physical network measurements.
