# NDABI dynamic Supabase-compatible RLS campaign v0.1

Status: implemented candidate with one passing non-formal Docker smoke.

## Purpose

Prove one cached dynamic NDABI program through an admitted user and forced PostgreSQL row-level security.
Prove that two user identities receive different exact results from the same numeric program.
Reject any result that lacks exact receipt and refusal proof.

## Environment

Use the pinned PostgreSQL and Toxiproxy image digests.
Create one private Docker network and one ephemeral PostgreSQL container.
Connect only through a non-superuser authenticator role.
Grant that role permission to assume only the non-login authenticated role.
Remove the exact containers, network, and campaign binary after every outcome.

## Dynamic operation

Use one verified numeric schema and one trusted PostgreSQL catalogue.
Scan `public.supabase_items`.
Project the numeric `id` and `owner_sub` fields.
Sort by the numeric `id` field and apply a typed limit operand.
Register the verified program once and execute one compact handle request.

## Identity and database authority

Admit one ES256 JWT for `user-a` and one for `user-b`.
Bind the NDABI authority to the admitted tenant and principal.
Set the authenticated database role and canonical claims before preparing the program.
Require read-only transactions, active row security, no superuser privilege, and no RLS bypass.
Force the database policy to compare each row owner with the JWT subject.

## Acceptance gates

Run one pair during a smoke and five pairs during a formal campaign.

| Gate | Requirement |
|---|---|
| User A result | Exactly identifiers 2, 4, 6, and 8 |
| User B result | Exactly identifiers 1, 3, 5, and 7 |
| Isolation | No result digest or row set is shared across users |
| Receipt | Verify the exact request, row count, and result bytes |
| Replay | Refuse the repeated compact frame |
| Mutation | Refuse an authenticated-frame mutation |
| Principal | Refuse a changed authority principal |
| JWT | Refuse a changed signature, expired token, wrong audience, and wrong role |
| Write | Refuse a database write through the authenticator |
| Preparation | Prepare exactly one verified dynamic program per process |
| Compression | Reduce the compact request by at least 70 percent |

## Evidence custody

Require a clean checkout for a formal run.
Record the commit source closure, binary digest, image identities, exact results, and cleanup result.
Record every failed run and its cleanup result before returning the failure.
Treat a smoke as diagnostic evidence only.

## Boundaries

This campaign proves a Supabase-compatible JWT and PostgreSQL RLS boundary in local Docker.
It does not prove hosted Supabase, Supabase Auth transport, PostgREST, Supavisor, TLS, WAN, or production key custody.
It does not measure latency, CPU, memory, allocation, token, energy, or scaling improvements.
