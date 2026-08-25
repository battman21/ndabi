# NDABI canonical Supabase binding campaign v5.8

Status: frozen before the first formal campaign.

## 1. Purpose

Test the canonical NDABI frame against a local Supabase-compatible data plane.
Test a least-privilege PostgreSQL service binding and a PostgREST user-JWT binding.

## 2. Canonical protocol gates

Use the `NDBI` version 1.0 fixed execute-handle frame.
Bind the frame to the tenant, principal, purpose, capability, engine, profile, schema, policy, and prepared plan.
Use a complete 256-bit keyed BLAKE3 frame tag and a separately keyed result receipt.
Require complete canonical result comparison.
Require a non-zero keyed receipt.

## 3. Trusted service gates

Use a dedicated login role without superuser, role creation, database creation, or write authority.
Set the role to read-only by default.
Require the canonical PostgreSQL adapter to return two exact rows.
Require the direct service role to refuse an insert.

## 4. User-JWT gates

Enable and force row-level security on the test table.
Require each valid user token to return only its owner rows.
Require an absent token, changed signature, expired token, and unsigned token to refuse.
Require a user write request to refuse.

## 5. Campaign rules

Use digest-pinned PostgreSQL 16 and PostgREST 14.16 images.
Run five complete client processes against one fresh ephemeral Docker data plane.
Record the source digest, binary digest, image identifiers, and each process result.
Remove every campaign container and network after the run.

## 6. Boundaries

This campaign tests the Supabase PostgreSQL and PostgREST data surfaces.
It does not test hosted Supabase, GoTrue, Supavisor, Realtime, Storage, Edge Functions, or production credentials.
It does not make a new latency, token, memory, energy, or WAN claim.
