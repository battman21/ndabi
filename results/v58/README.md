# NDABI canonical Supabase v5.8 result

The frozen campaign passed every process gate on 2026-08-23.
Five client processes used one fresh ephemeral Docker data plane.
The data plane used digest-pinned PostgreSQL 16 and PostgREST 14.16 images.

The canonical NDABI path used a 160-byte authenticated execute-handle frame.
Every process returned two complete expected rows and a non-zero keyed receipt.
Every frame bound the tenant, principal, purpose, capability, engine, profile, schema, policy, and prepared plan.

The trusted path used a dedicated login role without superuser, role creation, database creation, or write authority.
The role used read-only transactions and refused a direct insert.

PostgreSQL enabled and forced row-level security for the user table.
Two valid JWT identities returned only their own rows.
Absent, changed, expired, and unsigned tokens refused.
A user write request also refused.

The campaign removed both containers and its Docker network.
It proves the local Supabase PostgreSQL and PostgREST data surfaces.
It does not prove the hosted Supabase control plane or other Supabase services.
It makes no new performance, token, memory, energy, or WAN claim.

The aggregate file SHA-256 is `cd3de88eb210155abbda4292852b9a15afac6f02b866d9e04a7f38fd4de11cfd`.
The aggregate records the source, binary, image, and five process reports.
