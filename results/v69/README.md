# NDABI Supabase packed-session performance v6.9 results

The first formal campaign ran at `20260823T151019Z` and failed its frozen speed gate.

All seventeen security checks passed.
All five processes observed exactly 420 data queries.
Every measured NDABI operation returned one packed PostgreSQL result row.
Every process passed the result, request-compression, allocation, and validator gates.
All three wall-ratio coefficients of variation stayed below 10%.

Median NDABI wall time measured 0.393 times PostgREST for one row.
It measured 0.463 times PostgREST for 32 rows.
It measured 0.511 times PostgREST for 128 rows.
Every 32-row and 128-row process missed the 0.400 hard gate.

Median 128-row NDABI allocations fell from 156 in v6.8 to 18.
Median 128-row allocated bytes fell from 84,716 to 40,077.
Database-side packing reduced memory without reducing the single-query wall floor.
The next campaign must measure an NDABI batch instruction against repeated PostgREST operations.

Source digest `7c28acfbec58d494edf8df4429120f3953746b11e886ad4ecb7478fad54e9695` does not match commit `6e72ef5`.
The committed source digest is `922cf9b7ebea5769f108608e71541e36c5f5b2d72fb707f3c02fd319253f7acf`.
The campaign therefore fails source custody and supports no accepted Supabase performance or allocation claim.
