# NDABI Supabase batch-session performance v7.0 results

The first campaign ran at `20260823T152108Z` and lacks source custody.

The source changed while the campaign ran.
The aggregate source digest does not identify the built binary source.
Treat every performance value as an unattributed diagnostic.

All seventeen security checks passed.
All five processes observed exactly 2,030 data queries.
Every request, query-reduction, allocation, and repeatability gate passed.

The database-side join plan was defective.
Median NDABI wall time measured 297, 311, and 332 milliseconds.
Median PostgREST wall time measured 2.65, 9.15, and 17.15 milliseconds.
The NDABI plan was 19 to 112 times slower.

Request bytes fell by 81% to 94%.
Database queries fell by 50% to 94%.
Median 16-operation NDABI allocations measured 16 against 1,345 for PostgREST.
These diagnostics justify a v7.1 indexed identifier-batch repair.

The second campaign ran at `20260823T152815Z` from commit `9f43510`.
Its aggregate source digest matches the registered source bytes.
All seventeen security checks passed.
All process reports passed exactness, query-count, allocation, and validation checks.
Every wall ratio stayed within the 10% repeatability limit.

The wall-time gate failed in every 8-operation and 16-operation process.
Median NDABI wall time measured 296 to 333 milliseconds across the three batch sizes.
The NDABI plan was 18 to 112 times slower than PostgREST.
The second campaign rejects the v7.0 candidate with attributable evidence.
