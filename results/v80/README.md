# NDABI Supabase production campaign v8.0

No v8.0 performance campaign is accepted.

Formal campaign `20260824T160420Z` stopped during its first stack.
It produced no complete repetition.
The PostgREST RPC worker completed before the required two-second duration.
The source-bound aggregate and manifest retain that rejected campaign.

The functional-only smoke `20260824T134115Z` passed against one million local PostgreSQL rows.
It exercised native fused, NDABI, PostgREST RPC, and repeated PostgREST arms.
It exercised concurrency 1, 8, and 32 with three requests per worker.
All exact-result, query-count, resource-evidence, session, row-level security, and seventeen security checks passed.

The smoke disabled performance and repeatability gates.
Its timing values are diagnostics and support no performance claim.
Its source remained stable during execution but was not committed.

The v8.1 candidate corrects the sample duration without changing an acceptance gate.
