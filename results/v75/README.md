# NDABI Supavisor concurrency campaign v7.5

The first formal attempt `20260824T043226Z` binds source commit `3664690`.
It refused before saving a process because an unrelated Cargo and Rust build started.

The complete formal campaign `20260824T063749Z` binds source commit `72fc936`.
All five processes completed from registered source bytes.
All fifteen process-level performance cases passed.
The aggregate failed the frozen p95-ratio repeatability gate.

| Concurrency | Median speed-up | NDABI p95 | PostgREST p95 | Throughput CV | p95-ratio CV |
|---:|---:|---:|---:|---:|---:|
| 1 | 20.90× | 0.764 ms | 16.844 ms | 5.64% | 15.01% |
| 8 | 13.79× | 2.699 ms | 24.168 ms | 7.54% | 16.12% |
| 32 | 39.04× | 8.187 ms | 163.068 ms | 9.47% | 15.42% |

NDABI used one data query for each 16-operation request.
PostgREST used sixteen data queries for the same result.
This reduced requests by 94.39% and data queries by 93.75%.
All result bytes matched.
All seventeen security checks passed through Supavisor session mode.
The prepared-statement proof, forced RLS, least privilege, and source custody passed.

The throughput coefficients passed the 15% repeatability threshold.
The p95-ratio coefficients exceeded that threshold at every concurrency level.
The result is a valid failed campaign, not an accepted performance claim.
Client allocations and memory values remain diagnostics only.
Hosted Supabase, TLS, WAN, tokens, energy, and service memory remain untested.
