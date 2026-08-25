# NDABI Supabase range-session campaign v6.8

Status: frozen before the first formal campaign.

## 1. Repair

Retain the v6.7 dedicated admitted PostgreSQL session.
Replace the identifier-array query with two scalar range bounds.
Borrow each PostgreSQL binary payload during canonical encoding.
Reserve the exact bounded output size before row encoding.
Keep one prepared data query per measured operation.

## 2. Equal authority and work

Retain every v6.7 JWT, RLS, least-privilege, refusal, exactness, and query-count gate.
Retain one million rows and the one-row, 32-row, and 128-row cases.
Retain 7 warm-ups, 63 rotated samples, and five fresh processes.
Use the same scalar range predicate for both database arms.
Require complete canonical result equality after every operation.

## 3. Measurements

Record wall p50, p95, and p99.
Record the client-thread CPU and Rust allocations as diagnostics.
Do not compare the client-thread CPU as complete-stack CPU.
PostgREST server work runs outside the measured client thread.

## 4. Hard gates

Require every v6.7 security, exactness, query-count, byte, and evidence gate.
Require NDABI median wall time at most 0.45 times PostgREST for 32 and 128 rows.
Require each median wall ratio coefficient of variation below 10% across five processes.
Require at most 170 mean NDABI allocations for each 128-row process.
Require at most 100,000 mean allocated NDABI bytes for each 128-row process.
Treat the one-row ratio and every tail ratio as diagnostics.
Use identical floor-index percentile calculation in the producer and validator.

## 5. Boundaries

This campaign measures direct PostgreSQL session binding against local PostgREST.
It applies to direct PostgreSQL and Supavisor session mode.
It does not apply to Supavisor transaction mode.
The fixed database timeout caps each query at five seconds.
The protocol can refuse a result after a shorter operation deadline.
This campaign does not prove database cancellation at each shorter operation deadline.
It does not prove complete-stack CPU, hosted Supabase, TLS, WAN, tokens, energy, revocation latency, or production key custody.
