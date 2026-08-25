# NDABI Supavisor concurrency campaign v7.4

The first attempt `20260824T040118Z` binds source commit `55f218a`.
It retained one complete passing process before an unrelated compiler started.
The environment gate then refused the next measured arm.

| Concurrency | NDABI throughput gain | NDABI p95 | PostgREST p95 | Query counts |
|---:|---:|---:|---:|---:|
| 1 | 23.32× | 0.771 ms | 18.133 ms | 34 / 544 |
| 8 | 15.30× | 2.415 ms | 30.166 ms | 272 / 4,352 |
| 32 | 55.85× | 7.843 ms | 539.828 ms | 1,088 / 17,408 |

The second attempt `20260824T041713Z` refused before saving a process.
Neither attempt produced a five-process aggregate or an accepted result.
Treat the retained process as a source-bound diagnostic only.
