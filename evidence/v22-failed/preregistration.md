# NDABI White Tree real-engine campaign v2.2

**Status:** FROZEN before the first v2.2 result. **Date:** 2026-08-22.

This campaign tests a signed White Tree `Database` through its public governed read surfaces.
It does not use the bare fixture `ChunkStore` benchmark path.

## 1. Question

Measure the cost removed when NDABI selects a typed governed kernel instead of governed SQL.
Measure full and session-bound NDABI overhead against the same direct typed kernel.

## 2. Fixed workload

Create 10,000 software-operation trajectories in 100 signed partitions.
Open the database with its verification key.
Authenticate one capability for the exact profile, label, tenant, principal, and purpose.
Pin one governed snapshot before measurement.

Select one trajectory near the end of the dataset.
Return the same six scalar columns and four logical rows from every arm.

Run 63 measured samples after five warm-up samples.
Run one operation per sample because the database operation dominates the timer.
Rotate the five arm orders between samples.

## 3. Arms

| Arm | Request path | Required work |
|---|---|---|
| Governed SQL | Preformatted SQL text | Parse, validate, plan, execute, hash, and receipt |
| Full NDABI | Authenticated 72-byte frame | Verify and decode, then call governed Arrow |
| Session NDABI | 24-byte bound frame | Check handle, generation, and nonce, then call governed Arrow |
| Native typed | Rust typed request | Call governed Arrow without NDABI framing |
| Direct repeat | The same Rust typed request | Detect order or measurement bias |

The SQL arm uses a preformatted string.
It does not include JSON, network, capability minting, database opening, or snapshot creation.

## 4. Hard gates

- Every arm must return byte-identical canonical row payloads.
- Every governed receipt must verify.
- Every receipt must bind the same database, tenant, generation, data root, principal, purpose, and policy.
- A modified full frame must fail authentication.
- A wrong handle, wrong generation, and replayed nonce must fail closed.
- The two direct arms must remain within 10% at p95.
- Session NDABI must remain within 10% of the native typed p95.
- Governed SQL must be at least 2.5 times slower than session NDABI at p95.

## 5. Evidence

Record p50, p95, p99, operations per second, allocations, allocated bytes, and peak live bytes.
Record request bytes and canonical response bytes.
Record the source fingerprint, release binary digest, database root, and complete raw samples.

## 6. Boundary

This campaign can prove White Tree stack compression for one point-query shape.
It cannot prove PostgreSQL, MongoDB, Supabase, transport, concurrency, energy, or model-token behaviour.

The SQL comparison proves removal of SQL-layer work.
The native typed arm prevents attribution of that gain to binary syntax alone.
