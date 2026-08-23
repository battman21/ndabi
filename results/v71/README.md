# Supabase indexed-batch-session v7.1 results

The formal campaign ran at `20260823T153807Z` from commit `f3d4f37`.
The aggregate source digest matches every registered source byte.
All seventeen security checks passed.
All five process reports passed exactness, query-count, allocation, and validation checks.
Every wall ratio stayed within the 10% repeatability limit.

Median NDABI wall time measured 0.33 to 0.75 milliseconds.
Median PostgREST wall time measured 1.79 to 17.40 milliseconds.
Median wall ratios measured 0.04 to 0.20.
The 8-operation and 16-operation ratios passed the 0.20 hard gate.

The campaign accepts the v7.1 candidate for its frozen profile.
It does not prove hosted Supabase, TLS, WAN, or Supavisor transaction mode.
