# NDABI Supabase batch-session performance v7.0 results

The first campaign ran at `20260823T152108Z` and is rejected.

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
