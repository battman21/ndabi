# NDABI PostgreSQL replay campaign v3.4

**Status:** FROZEN, NOT RUN. **Frozen:** 2026-08-22.

## 1. Question

Can restart-safe NDABI admission remain close to an equally secure native PostgreSQL control?

This campaign separates restart-scoped sessions from resumable sessions.
It does not compare durable NDABI against an unsafe volatile control.

## 2. Security profiles

The ephemeral profile rotates the authority generation and root key after every server restart.
All frames from an earlier process must fail authentication after the restart.
The profile performs no durable write per request.

The resumable profile stages frame verification without advancing volatile replay state.
PostgreSQL advances the nonce and executes the query inside one transaction.
The verifier advances volatile state only after PostgreSQL commits.

## 3. Frozen environment

Use the pinned Rust 1.92 Bookworm builder and Debian Bookworm runtime.
Use the pinned PostgreSQL 16 image from campaign v3.3.
Connect through one Docker bridge without TLS.

Prepare one 100,000-row table and one replay-state table.
Use batches of 32 and 128 fixed-width point reads.
Use five warm-up cycles and 63 measured cycles for latency.

Run concurrency levels 1, 8, 32, and 128 with batch 32.
Each worker uses one independent database connection and replay identity.
Each worker completes three warm-up requests and 31 measured requests.

## 4. Frozen arms

| Arm | Frame | Replay state | Database work |
|---|---|---|---|
| native ephemeral | typed values | volatile nonce | prepared set query |
| NDABI ephemeral | authenticated column frame | volatile nonce | prepared set query |
| native resumable | typed values | PostgreSQL transaction | prepared set query in that transaction |
| NDABI resumable | authenticated pending frame | PostgreSQL transaction | prepared set query in that transaction |

The native and NDABI arms must use the same result encoding and receipt function.
The resumable arms must use the same nonce statement and transaction boundary.

## 5. Correctness gates

1. Return byte-identical results and receipts from all four arms.
2. Refuse every pre-restart ephemeral frame after authority rotation.
3. Refuse an equal or lower resumable nonce after commit.
4. Leave no nonce after PostgreSQL terminates an uncommitted transaction.
5. Leave the volatile nonce unchanged after an abandoned pending frame.
6. Allocate no Rust heap memory during borrowed frame decoding.

Any failed correctness gate rejects the campaign.

## 6. Performance gates

| Gate | Target |
|---|---|
| Ephemeral latency distance | NDABI p95 no more than 1.05 times native p95 |
| Resumable latency distance | NDABI p95 no more than 1.10 times native p95 |
| Concurrent ephemeral throughput | NDABI at least 90% of native throughput |
| Concurrent resumable throughput | NDABI at least 90% of native throughput |
| Concurrent p95 distance | NDABI no more than 1.15 times the matching native p95 |
| Completion | Every worker completes every registered request |

Apply the latency gates to batches 32 and 128.
Apply the concurrency gates to levels 1, 8, 32, and 128.
Any failed registered gate rejects the campaign.

## 7. Evidence gates

Run five fresh Linux ARM64 client containers from one immutable image.
Require five complete reports and five zero exit codes.
Retain the source, lockfile, image identifier, binary digest, raw reports, and aggregate summary.

## 8. Boundaries

Docker Desktop does not prove physical Linux behaviour.
The campaign excludes TLS, WAN delay, multi-node replay coordination, and malicious disk rollback.
The campaign measures one PostgreSQL read profile only.
