# NDABI Supabase binding campaign v5.0

Status: frozen before the first formal campaign.

## 1. Purpose

Prove both Supabase access modes without treating Supabase as a separate database engine.
Use PostgreSQL for trusted services and PostgREST with user JWT claims for user-scoped requests.

## 2. Trusted service binding

Run the shared NDABI PostgreSQL adapter against a digest-pinned PostgreSQL 16 container.
Use a read-only prepared range profile and the authenticated NDABI session.
Require exact canonical rows and a non-zero session receipt.

## 3. User JWT binding

Run digest-pinned PostgREST 14.16 against the same PostgreSQL database.
Create an `authenticated` role and row-level policy based on the JWT `sub` claim.
Require a valid user token to return only that user's rows.
Require an absent token, a changed signature, and a write request to refuse.

## 4. Gates and boundaries

Run five complete fresh binding processes.
Require all trusted-service and user-JWT checks in every process.
Record exact container image identifiers and the executable hash.

This campaign proves local Supabase-compatible bindings, not the hosted Supabase control plane.
It does not prove Supavisor modes, hosted identity, realtime, storage, edge functions, WAN, or production credentials.
It adds no new performance claim beyond the accepted PostgreSQL and PostgREST campaigns.
