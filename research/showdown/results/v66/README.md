# NDABI Supabase user-session performance v6.6 results

The first formal campaign ran at `20260823T144013Z` and failed.

The campaign uses ephemeral ES256 keys, equal user claims, and forced PostgreSQL row-level security.
It compares one admitted NDABI session with persistent local PostgREST requests.
The runner records the installed `cryptography` version and binds its pinned requirement file.

All seventeen security checks passed.
All five processes observed the exact 420 data queries.
NDABI median wall time measured 1.540 to 2.261 times PostgREST.
Client-thread CPU measured 4.690 to 8.300 times PostgREST.
The validator also found a percentile-rounding mismatch in every process.

Commit `a6dad61` preserves the exact source for source digest
`33fc1bbebdc4e789b8a50b88197c71beeaf2d5390fb89c3a8f0e915d9f43ea33`.
The result supports no accepted Supabase performance claim.
