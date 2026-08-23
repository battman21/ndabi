# Supabase indexed-batch-session v7.1 results

The formal campaign ran at `20260823T153807Z` from commit `f3d4f37`.
The aggregate source digest matches every registered source byte.
All seventeen security checks passed.
All five process reports passed exactness, query-count, allocation, and validation checks.
Every wall ratio stayed within the 10% repeatability limit.

| Operations | NDABI median p50 | PostgREST median p50 | Median speed-up | Request reduction | Query reduction |
|---:|---:|---:|---:|---:|---:|
| 2 | 0.360 ms | 1.930 ms | 5.46 times | 81.17% | 50.00% |
| 8 | 0.581 ms | 7.770 ms | 13.60 times | 92.50% | 87.50% |
| 16 | 0.714 ms | 14.993 ms | 22.12 times | 94.39% | 93.75% |

Each process observed exactly 2,030 data queries.
The sixteen-operation case used a median 156.57 Rust allocations and 85,562 allocated bytes.

The campaign accepts the v7.1 candidate for its frozen profile.
The speed-up comes from one admitted session and one indexed query per batch.
Binary frames reduce request bytes, but binary encoding alone does not produce the speed-up.
The campaign used direct PostgreSQL and local PostgREST without TLS.
It does not prove hosted Supabase, Supavisor, WAN, tokens, energy, or production key custody.
