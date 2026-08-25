# NDABI registered PostgreSQL and Supabase-compatible RLS campaign v0.3

**Status:** Frozen before the first formal campaign.

**Repair:** Rebind the complete source closure after registering the MongoDB campaign binary.

## 1. Purpose

Prove the sealed registry against one real PostgreSQL 16 engine in local Docker.
Prove the same registered profile through one Supabase-compatible user RLS path.
Do not compare performance in this campaign.

## 2. Environment

Use the pinned PostgreSQL image digest from the validator.
Create one private Docker network and one ephemeral database container.
Publish PostgreSQL on an automatically selected loopback port.
Remove the container and network after every outcome.

## 3. Database authority

Create one login service role with default read-only transactions.
Create one login authenticator role without inherited privileges.
Create one non-login authenticated role.
Grant the authenticated role to the authenticator.
Grant only schema usage and table selection to the read roles.
Enable and force row-level security.
Restrict each authenticated user to rows matching the admitted JWT subject.

## 4. Registered execution

Use registered PostgreSQL profile `0x50471002`.
Use one sealed range plan containing no caller-supplied SQL.
Wrap each live backend with `RegisteredBackend`.
Bind every authority to the registry identity.
Return the complete typed result and receipt.

## 5. Functional cases

Run five fresh service processes for identifiers 1 and 2.
Run five fresh user-one processes for identifiers 1 and 2.
Run five fresh user-two processes for identifiers 3 and 4.
Require one database data query from each successful process.
Require exact row bytes and SHA-256 digests.
Require the same registry digest across all processes.

## 6. Refusal gates

Require every process to refuse these conditions before data dispatch:

- A changed registry.
- A legacy backend identity.
- An unknown plan handle.
- A changed result shape.
- Limits above the registered plan.
- An authenticated-frame mutation.
- A replayed request.

Require user one to refuse user-two rows.
Require user two to refuse user-one rows.
Require changed, expired, and incorrectly scoped JWTs to fail admission.
Require service and user writes to fail.

## 7. Acceptance

Accept only when all five process groups pass every functional and refusal gate.
Record source, binary, image, registry, result, and campaign digests.
Bind the complete local validator dependency closure into the source digest.
Treat any missing field or producer-validator disagreement as failure.

## 8. Boundaries

This campaign proves one fixed read profile against local PostgreSQL and Supabase-compatible RLS.
It does not prove hosted Supabase, PostgREST, Supavisor, TLS, WAN, arbitrary SQL, writes, or production custody.
It does not prove latency, CPU, memory, allocation, token, energy, or scaling improvements.
