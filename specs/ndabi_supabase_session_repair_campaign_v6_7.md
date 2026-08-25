# NDABI Supabase session repair campaign v6.7

Status: frozen before the first formal campaign.

## 1. Repair

Replace per-operation transaction controls with one dedicated admitted PostgreSQL user session.
Apply the authenticated role, exact claims, read-only state, and maximum statement timeout during admission.
Keep these controls outside steady-session timing.
Use one prepared data query per measured NDABI operation.

## 2. Equal authority

Retain the v6.6 ES256, issuer, audience, subject, role, expiry, forced RLS, and least-privilege gates.
Retain every v6.6 JWT, frame, replay, receipt, cross-subject, and write refusal.
Bind each PostgreSQL connection to one admitted user until the connection closes.
Never return this connection to a generic pool.

## 3. Equal work

Retain the v6.6 one-row, 32-row, and 128-row cases against one million rows.
Retain 7 warm-ups, 63 rotated samples, and five fresh processes.
Require one data query per operation for both arms.
Require complete canonical result equality after every operation.

## 4. Measurements

Record wall p50, p95, and p99.
Record client-thread CPU and Rust allocations as diagnostics.
Do not compare client-thread CPU as complete-stack CPU.
PostgREST server work runs outside the measured client thread.

## 5. Hard gates

Require every v6.6 security, exactness, query-count, byte, and evidence gate.
Require NDABI median wall time below 0.50 times PostgREST for 32 and 128 rows.
Require each median wall ratio coefficient of variation below 10% across five processes.
Treat the one-row ratio and every tail ratio as diagnostics.

Use identical floor-index percentile calculation in the producer and validator.

## 6. Boundaries

This campaign measures direct PostgreSQL session binding against local PostgREST.
It applies to direct PostgreSQL and Supavisor session mode.
It does not apply to Supavisor transaction mode because that mode can change underlying connections.
The fixed database timeout caps each query at five seconds.
The protocol can refuse a result after a shorter operation deadline.
This campaign does not prove database cancellation at each shorter operation deadline.
It does not prove complete-stack CPU, hosted Supabase, TLS, WAN, tokens, energy, revocation latency, or production key custody.
