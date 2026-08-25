# NDABI Supabase user-session campaign v6.6

Status: frozen after static request calculation and before the first formal campaign.

## 1. Question

Measure whether one admitted NDABI user session compresses the local Supabase data path.
Compare it with persistent PostgREST requests under equal user identity and PostgreSQL row-level security.

## 2. Authority

Use an ephemeral ES256 signing key and a public JWKS document.
Require the expected key identifier, algorithm, issuer, audience, subject, role, and expiry.
Accept only the `authenticated` PostgreSQL role.
Validate the JWT once before creating the NDABI session.
Bound the NDABI session expiry to the JWT expiry.
Bind the issuer, audience, subject, role, schema, and policy to the NDABI authority context.

PostgREST must validate the same token and JWKS.
Both arms must use the same forced row-level security policy.
Neither arm can use service-role or table-owner authority.

## 3. Equal work

Use one, 32, and 128 ordered rows from one million PostgreSQL rows.
Use one database data query per measured operation.
Return the same five columns and the same complete rows.
Convert each PostgREST result into the canonical binary result inside the timed request.
Compare complete canonical result bytes after every operation.

## 4. Measured paths

Use one persistent PostgREST HTTP connection.
Include HTTP creation, JWT verification, RLS execution, JSON receipt, JSON decoding, and canonical conversion.

Use one persistent NDABI session and one persistent PostgreSQL connection.
Include frame creation, admission, RLS execution, result framing, receipt creation, and client verification.
Keep JWT admission and transport negotiation outside steady-session samples.
Measure their separate first-session costs.

## 5. Samples

Use seven warm-up cycles and 63 rotated measured cycles per case.
Run five fresh client processes against one fresh Docker data plane.
Record wall p50, p95, and p99 for both arms.
Record client-thread CPU, allocations, allocated bytes, and peak additional live bytes.
Preserve every raw wall and CPU sample.

## 6. Hard gates

Require five complete zero-exit process reports.
Require exact complete result equality for every operation.
Require every row to belong to the admitted subject.
Require one data query per execution for each arm.
Require NDABI median wall time below 0.50 times PostgREST for 32 and 128 rows.
Require NDABI median CPU below 0.60 times PostgREST for 32 and 128 rows.
Require NDABI request bytes at least 69% below a conservative PostgREST request lower bound.
Require every registered ratio coefficient of variation below 10% across five processes.

Treat the one-row performance ratio as a diagnostic.
Treat p95 and p99 distances as diagnostics on Docker Desktop.

## 7. Refusals

Refuse a changed signature, unknown key, wrong issuer, wrong audience, expired token, unsigned subject mutation, and elevated role.
Refuse an NDABI replay before database execution.
Refuse a changed NDABI frame before database execution.
Refuse an invalid result receipt before client acceptance.
Refuse cross-subject rows and every user write.

## 8. Evidence

Bind the complete source set, release binary, PostgreSQL image, and PostgREST image by SHA-256.
Persist every process report before aggregate validation.
Remove only the uniquely named campaign containers and network.

## 9. Boundaries

This campaign measures an embedded NDABI adapter against local PostgREST.
It does not measure hosted Supabase, GoTrue, Supavisor, TLS, WAN, key custody, revocation latency, tokens, or energy.
Supavisor session and transaction modes require a separate campaign.
