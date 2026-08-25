# NDABI Supavisor session campaign v7.2

Status: frozen before the first formal campaign.

## 1. Purpose

Test the accepted v7.1 indexed-batch profile through Supavisor session mode.
Compare the pooler path with direct PostgreSQL and the PostgREST user-JWT control path.
Attribute pooler overhead separately from NDABI stack compression.

## 2. Environment

Use one local Docker network.
Use the pinned PostgreSQL, PostgREST, and Supavisor images.
Use Supavisor session port `5432` and an explicit session-mode tenant.
Use one million indexed rows and the v7.1 ES256 identity boundary.
Do not use Supavisor transaction mode.

## 3. Equal work

Retain batches of 2, 8, and 16 logical operations.
Retain eight rows per operation, 7 warm-ups, and 63 measured samples.
Run direct and pooled NDABI through the same release binary.
Run each NDABI arm against its own repeated PostgREST control measurements.
Require equal canonical result bytes and digests across both NDABI arms.
Require exactly 2,030 data queries for each arm and process.

## 4. Session proof

Connect through the published Supavisor session endpoint.
Prepare a statement in one transaction and execute it after that transaction.
Set a session value and read it after another transaction.
Require the admitted NDABI session to retain the role, claims, read-only state, and prepared query.

## 5. Security

Run all seventeen v7.1 refusal and authority checks through the pooler connection.
Require ES256 signature, key, issuer, audience, expiry, subject, and role validation.
Require RLS isolation, least privilege, read-only access, replay refusal, and receipt verification.
Fail closed when any check fails.

## 6. Hard performance gates

Require pooled NDABI p50 at most 0.20 times PostgREST for 8-operation and 16-operation batches.
Require pooled NDABI p50 at most 1.50 times direct NDABI for those batches.
Require those pooled-to-direct p50 ratio coefficients of variation below 10% across five processes.
Require those pooled-to-PostgREST p50 ratio coefficients of variation below 10% across five processes.
Retain every v7.1 request, query, allocation, and exactness gate.
Treat two-operation ratios and all tail ratios as diagnostics.

## 7. Source custody

Run the formal campaign only from committed registered source bytes.
Build the v7.1 release binary from those bytes inside the runner.
Recheck all registered source bytes before the acceptance decision.
Commit the campaign results separately from the frozen source commit.

## 8. Boundaries

This campaign tests local Supavisor session mode on macOS Docker.
It does not test a hosted Supabase project, TLS, WAN delay, concurrency, or transaction mode.
It does not prove token, energy, or comparative memory reductions.
The speed source remains one admitted session and one indexed query per NDABI batch.

## 9. External basis

Supabase documents session mode for persistent application traffic.
Supabase documents prepared-statement support for direct and session-mode connections.
The local configuration follows the official self-hosted Supavisor tenant bootstrap shape.
