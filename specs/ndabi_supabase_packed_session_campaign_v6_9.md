# NDABI Supabase packed-session campaign v6.9

Status: frozen before the first formal campaign.

## 1. Repair

Retain the v6.8 dedicated admitted PostgreSQL session and scalar range predicate.
Make PostgreSQL return one packed binary result per operation.
Use PostgreSQL network byte order for every numeric result field.
Include the opcode and row count in the packed database result.
Remove per-row PostgreSQL client materialisation and decoding.

## 2. Equal authority and work

Retain every v6.8 JWT, RLS, least-privilege, refusal, exactness, and query-count gate.
Retain one million rows and the one-row, 32-row, and 128-row cases.
Retain 7 warm-ups, 63 rotated samples, and five fresh processes.
Use the same scalar range predicate for both database arms.
Require complete canonical result equality after every operation.
Require one PostgreSQL result row per measured NDABI operation.

## 3. Measurements

Record wall p50, p95, and p99.
Record the client-thread CPU and Rust allocations as diagnostics.
Do not compare the client-thread CPU as complete-stack CPU.
PostgREST server work runs outside the measured client thread.

## 4. Hard gates

Require every v6.8 security, exactness, query-count, byte, and evidence gate.
Require NDABI median wall time at most 0.40 times PostgREST for 32 and 128 rows.
Require each median wall ratio coefficient of variation below 10% across five processes.
Require at most 50 mean NDABI allocations for each 128-row process.
Require at most 60,000 mean allocated NDABI bytes for each 128-row process.
Treat the one-row ratio and every tail ratio as diagnostics.
Use identical floor-index percentile calculation in the producer and validator.

## 5. Boundaries

This campaign measures one finite PostgreSQL result shape against local PostgREST.
The packed query remains a prepared, profile-bound operation.
It applies to direct PostgreSQL and Supavisor session mode.
It does not apply to Supavisor transaction mode.
The fixed database timeout caps each query at five seconds.
The protocol can refuse a result after a shorter operation deadline.
This campaign does not prove database cancellation at each shorter operation deadline.
It does not prove complete-stack CPU, hosted Supabase, TLS, WAN, tokens, energy, revocation latency, or production key custody.
