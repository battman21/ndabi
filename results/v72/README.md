# NDABI Supavisor session campaign v7.2

The first formal campaign passed every frozen gate.
It binds source commit `9c41128` and five fresh local Docker processes.

| Operations | Pooled NDABI p50 | Direct NDABI p50 | Pooled PostgREST p50 | Pooled speed-up | Pooler overhead |
|---:|---:|---:|---:|---:|---:|
| 2 | 0.465 ms | 0.356 ms | 1.837 ms | 3.91× | 33.34% |
| 8 | 0.746 ms | 0.527 ms | 7.695 ms | 10.55× | 33.90% |
| 16 | 0.834 ms | 0.679 ms | 15.240 ms | 18.25× | 27.81% |

| Operations | Request reduction | Query reduction | Pooled allocations | Pooled allocated bytes |
|---:|---:|---:|---:|---:|
| 2 | 81.17% | 50.00% | 30.33 | 9,450 |
| 8 | 92.50% | 87.50% | 85.22 | 40,959 |
| 16 | 94.39% | 93.75% | 156.27 | 84,646 |

Each direct and pooled process issued exactly 2,030 measured data queries.
All seventeen security checks passed through the pooled path.
Prepared statements and session values survived separate transactions.
Every hard repeatability coefficient remained below 10%.

The pooler did not make an individual query faster than a direct connection.
NDABI retained its large advantage because one pooled session executed one indexed query per batch.
This result does not prove hosted Supabase, TLS, WAN, concurrency, tokens, energy, or comparative memory savings.
