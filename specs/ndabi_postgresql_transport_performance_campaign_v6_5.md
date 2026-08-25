# NDABI PostgreSQL transport performance campaign v6.5

Status: frozen before the first formal campaign.

## 1. Question

Measure the steady-session cost of the authenticated v0.2 result transport.
Compare equal PostgreSQL work against native prepared execution and the canonical v0.1 path.

## 2. Surfaces

Use one registered ordered-range profile against PostgreSQL 16.
Measure native prepared execution, canonical v0.1 execution, and canonical v0.2 result transport.
Keep transport negotiation outside measured samples.
Include request creation, admission, database execution, result authentication, and client verification.

## 3. Cases

Use one, 32, 128, and 1,024 returned rows.
Use seven warm-up cycles and 63 rotated measured cycles per case.
Run five fresh client processes against one fresh one-million-row Docker database.

## 4. Measurements

Record wall p50, p95, and p99.
Record median client-thread CPU, allocations, allocated bytes, and peak additional live bytes.
Record exact request, result, and transport-frame sizes.
Preserve every raw wall and CPU sample.

## 5. Hard gates

Require five complete zero-exit process reports.
Require exact complete result bytes for every arm and sample.
Require one data query per execution for every arm.
Require v0.1 median wall time within 1.25 times native execution for every process.
Require v0.2 median wall time within 1.35 times native execution for every process.
Require v0.2 median wall time within 1.25 times v0.1 execution for every process.
Require v0.2 median CPU within 1.50 times v0.1 execution for every process.
Require each case ratio coefficient of variation below 10% across five processes.

Require request mutation, replay, invalid result receipt, and reflected result refusal.
Require each refusal to preserve the pending or database state that it protects.

Treat p95 and p99 distances as diagnostics.
Do not use them as hard gates on this sub-millisecond local path.

## 6. Evidence closure

Bind the complete source set, release binary, and PostgreSQL image by SHA-256.
Persist every process report before aggregate validation.
Remove only the uniquely named campaign container.

## 7. Boundaries

This campaign measures the trusted direct PostgreSQL surface used by persistent Supabase backends.
It does not measure PostgREST, user JWTs, Supavisor, TLS, WAN, hosted Supabase, tokens, or energy.
The next campaign must compare the user-scoped path under equal JWT and RLS authority.
