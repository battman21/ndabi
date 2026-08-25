# NDABI PostgreSQL batch campaign v2.7

**Status:** FROZEN before the first v2.7 result. **Date:** 2026-08-22.

This campaign tests whether one NDABI batch removes repeated PostgreSQL round trips.
The v2.5 and v2.6 failed results remain unchanged.

## 1. Fixed environment

Use local image `postgres@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20`.
Create one ephemeral container and remove it after the campaign.
Use one host client over loopback TCP without TLS.

Create 100,000 indexed rows.
Run batch sizes 8, 32, and 128.
Each operation returns one identifier, one bucket, and one 64-byte payload.

## 2. Fair arms

| Arm | Database work | Request processing |
|---|---|---|
| Sequential prepared | One prepared query and round trip per operation | Typed identifiers |
| Native set | One prepared `UNNEST` query per batch | Typed identifier array |
| Native pipeline | Prepared point queries without intermediate waits | Typed identifiers |
| NDABI set | The same native set query | One authenticated `EXECUTE_BATCH` frame |

Every arm must use the same connection, indexes, result bytes, receipt function, and transaction semantics.
The native set and pipeline arms receive every optimisation available to NDABI.

Run 63 measured samples after five warm-up samples.
Rotate the arm order inside each batch-size case.

## 3. Hard gates

- Every arm must return one byte-identical canonical payload and receipt.
- Every NDABI frame must pass complete decoding and replay checks.
- Every modified frame byte, wrong binding, wrong generation, and replay must fail closed.
- NDABI set p95 must be no more than 10% slower than native set p95.
- NDABI set throughput must reach four times sequential throughput at batch size 32.
- NDABI set throughput must reach four times sequential throughput at batch size 128.
- Native pipeline and native set results must remain byte-identical.

The batch-size 8 case is diagnostic.
It has no speed gate.

## 4. Required evidence

Record complete p50, p95, p99, throughput, allocation, and allocated-byte samples.
Record the PostgreSQL version, image digest, source digest, binary digest, and complete gate result.

Record batch latency and derived operation latency separately.
Do not calculate a wire-byte claim without packet capture.
Do not calculate a server-compute claim without server counters.

## 5. Boundary

This local Docker campaign tests relative stack behaviour.
It does not prove native Linux latency, TLS, controlled WAN performance, concurrency, energy, or other database profiles.

The sequential speed-up measures round-trip removal.
The native-set distance measures NDABI overhead against the fair PostgreSQL ceiling.
