# NDABI PostgreSQL transport and Supabase binding campaign v6.4

Status: frozen before the first formal campaign.

## 1. Purpose

Prove the authenticated v0.2 result transport against the canonical PostgreSQL adapter.
Retest both Supabase-compatible data surfaces in local Docker.

## 2. NDABI gates

Use the fixed 160-byte v0.1 execute-handle request.
Negotiate the base v0.2 transport without optional features.
Derive correlation, shape, and budgets from the authenticated request.
Return the complete canonical result in one direction-bound transport frame.
Verify the v0.2 receipt before the client accepts the result.

## 3. PostgreSQL gates

Use one prepared range profile through the canonical PostgreSQL adapter.
Use a dedicated read-only login role without administration or write authority.
Require two exact canonical rows from each client process.
Require a direct insert to fail.

## 4. Supabase-compatible gates

Enable and force row-level security on the test table.
Require each valid user JWT to return only its owner rows through PostgREST.
Refuse absent, changed, expired, and unsigned tokens.
Refuse a user write request.

## 5. Campaign rules

Use digest-pinned PostgreSQL 16 and PostgREST 14.16 images.
Run five complete client processes against one fresh Docker data plane.
Record source, binary, and image digests.
Remove only the uniquely named campaign containers and network.

## 6. Boundaries

This campaign proves a local PostgreSQL service binding and a PostgREST user-JWT control surface.
It does not test hosted Supabase, Supavisor, GoTrue, TLS, LAN, WAN, or production key custody.
It adds no speed, token, memory, or energy claim.
