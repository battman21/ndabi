# NDABI Supavisor concurrency campaign v7.6

The formal campaign `20260824T075353Z` binds source commit `2e65c31`.
All five processes and all fifteen process-level cases passed.
The committed gzip files preserve each complete raw process report.

| Concurrency | Median speed-up | NDABI p95 | PostgREST p95 | Throughput CV | p95-ratio CV |
|---:|---:|---:|---:|---:|---:|
| 1 | 21.30× | 0.858 ms | 16.350 ms | 6.38% | 13.50% |
| 8 | 16.01× | 2.090 ms | 25.258 ms | 6.65% | 11.38% |
| 32 | 43.97× | 7.939 ms | 172.466 ms | 0.57% | 2.67% |

Every worker and arm ran for at least 1.556 seconds.
No compiler process entered any measured arm.
All canonical result bytes matched.
All observed data-query counts matched their exact expected values.
All seventeen security checks passed through Supavisor session mode.
The prepared-statement proof, forced RLS, least privilege, and source custody passed.

NDABI used one data query for each 16-operation request.
PostgREST used sixteen data queries for the same request.
This reduced request bytes by at least 94.39% and data queries by 93.75% per logical request.
The campaign used different sample counts to give both surfaces stable measured durations.
Do not compare the total query counts across the two benchmark arms.

This campaign accepts concurrent local Supavisor session performance on macOS Docker.
Client CPU, allocation, and memory values remain diagnostics only.
Hosted Supabase, TLS, WAN, tokens, energy, transaction mode, and service memory remain untested.
