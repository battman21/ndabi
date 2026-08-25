# NDABI PostgreSQL embedded campaign v4.1

**Status:** FROZEN, NOT RUN. **Frozen:** 2026-08-22.

## 1. Question

Can an embedded NDABI adapter preserve the compact protocol without the standalone gateway penalty?
Can it approach native prepared-set execution while retaining exact results and authenticated admission?

## 2. Frozen environment

Use local Docker Desktop with Linux ARM64 containers.
Use the same pinned PostgreSQL, PostgREST, Rust, Debian, dataset, and query shapes as v4.0.
Prepare 100,000 rows.
Run five complete client processes from one immutable image.

Physical Linux remains deferred.

## 3. Frozen surfaces

Measure PostgREST JSON, simple SQL, sequential prepared SQL, native prepared-set, embedded NDABI, and gateway NDABI.
The embedded adapter shares the client process and the native PostgreSQL connection.
It authenticates the 56-byte execute frame before it interprets arguments.
It commits replay state only after successful database execution.

The gateway remains a diagnostic control.
It does not participate in the embedded promotion gate.

## 4. Frozen method

Measure batches 32 and 128.
Use five warm-up cycles and 63 rotated latency cycles.
Measure concurrency 1, 8, 32, and 128 with batch 32.
Use three warm-up cycles and seven rotated blocks of three requests.

Retain wall time, client thread CPU, request bytes, exact payload identity, exact receipt identity, and process maximum RSS.
Record embedded allocations and allocated bytes.
Global allocation diagnostics remain causal observations under concurrency.

## 5. Hard gates

1. Return byte-identical canonical results and receipts from all six surfaces.
2. Refuse changed, replayed, cross-session, and expired embedded frames.
3. Preserve all four v4.0 gateway security checks.
4. Return five complete process reports and five zero exit codes.
5. Keep embedded p95 within 1.10 times native prepared-set p95 for both batches.
6. Keep embedded concurrent throughput at least 95% of native throughput at every level.
7. Keep embedded concurrent p95 within 1.15 times native p95 at every level.
8. Make embedded p95 at least two times faster than PostgREST for both batches.
9. Make embedded p95 at least two times faster than sequential prepared SQL at batch 32.
10. Make embedded p95 at least four times faster than sequential prepared SQL at batch 128.
11. Use at least 80% fewer application request bytes than PostgREST.
12. Complete every registered concurrent request.

Any failed hard gate rejects the campaign.
Do not alter or rerun the campaign after its first complete result.

## 6. Boundaries

This campaign tests one read-only ordered range profile.
It does not prove arbitrary SQL, writes, TLS, WAN, physical Linux, MongoDB, hosted Supabase, production custody, energy, or provider tokens.
The fixed research key does not represent a production capability resolver.
