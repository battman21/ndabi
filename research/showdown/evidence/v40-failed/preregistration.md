# NDABI PostgreSQL gateway campaign v4.0

**Status:** FROZEN, NOT RUN. **Frozen:** 2026-08-22.

## 1. Question

Can a persistent NDABI gateway compress a complete agent-to-PostgreSQL operation?
Can it beat human-facing and repeated-query surfaces without materially regressing native set execution?

This campaign tests stack compression, not binary syntax alone.
It runs only through local Docker Desktop.
Physical Linux remains a future release gate.

## 2. Frozen environment

Use Linux ARM64 containers on the current Docker Desktop host.
Use the pinned Rust 1.92 Bookworm builder and Debian Bookworm runtime.
Use PostgreSQL 16 at digest `sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20`.
Use PostgREST 14.16 at digest `sha256:bea1c76a856fa39d1e542d25911cf95d02fe2bf971992d033044ff209f1504b8`.

Prepare 100,000 rows with an eight-byte identifier, four-byte bucket, and 64-byte payload.
Use batches of 32 and 128 ordered point reads.
Run five complete client processes from one immutable image.

## 3. Frozen surfaces

| Surface | Persistent state | Database work | Result form |
|---|---|---|---|
| PostgREST JSON | HTTP connection and server pool | one REST-filtered query | JSON with hexadecimal `bytea` |
| simple SQL sequential | database connection | one unnamed query per identifier | PostgreSQL rows |
| prepared SQL sequential | connection and prepared statement | one prepared query per identifier | PostgreSQL rows |
| native prepared set | connection and prepared set statement | one array-set query | PostgreSQL rows |
| NDABI gateway | connection, authority, verifier, plan, and database statement | one authenticated batch query | canonical binary result and receipt |

Every surface must return the same ordered canonical rows and receipt.
The native set surface is the execution ceiling.
The repeated and REST surfaces represent stack-compression opportunities.

## 4. Latency method

Use five warm-up cycles and 63 measured cycles.
Execute every surface once per cycle.
Rotate the first surface in every cycle.
Retain every raw wall-time and client thread-CPU sample.

Measure batches 32 and 128.
Measure application request and response bytes for PostgREST and NDABI.
Do not estimate PostgreSQL protocol bytes.

## 5. Concurrency method

Use concurrency levels 1, 8, 32, and 128 with batch 32.
Each worker keeps independent persistent connections and authority state.
Use three warm-up cycles and seven measured blocks.
Execute three requests per surface and worker in each block.
Rotate the first surface in every block.

Retain every request latency and each critical worker duration.
Complete every registered request.

## 6. Hard gates

1. Return byte-identical canonical results and receipts from all surfaces.
2. Refuse a changed NDABI frame.
3. Refuse an NDABI replay on the same connection.
4. Refuse an NDABI frame on a different session.
5. Preserve the read-only PostgREST role.
6. Return five complete process reports and five zero exit codes.
7. Keep NDABI p95 within 1.15 times native set execution.
8. Make NDABI at least two times faster than prepared sequential execution at batch 32.
9. Make NDABI at least four times faster than prepared sequential execution at batch 128.
10. Make NDABI at least two times faster than PostgREST p95 for both batches.
11. Keep concurrent NDABI throughput at least 85% of native set throughput.
12. Keep concurrent NDABI p95 within 1.20 times native set p95.
13. Make NDABI concurrent throughput at least two times PostgREST throughput.
14. Use at least 40% fewer application request bytes than PostgREST.

Any failed hard gate rejects the campaign.
Do not alter or rerun the campaign after its first complete result.

## 7. Diagnostics

Record client thread CPU for every surface.
Record gateway thread CPU and Rust allocations returned with each successful response.
Record client maximum RSS and each service container memory peak.

These diagnostics have no promotion threshold in v4.0.
They identify the next causal optimisation boundary.

## 8. Evidence

Retain the preregistration, source, lockfile, runner, Dockerfile, client binary, raw reports, and summary.
Bind every retained file with SHA-256.
Validate raw sample counts, percentiles, ratios, identities, image identifiers, and exit codes.

## 9. Boundaries

This campaign does not prove physical Linux, TLS, WAN, MongoDB, production Supabase, or provider-token savings.
PostgREST represents the Supabase REST shape, not the complete hosted Supabase platform.
The research gateway uses fixed test authority material, not production key custody.
