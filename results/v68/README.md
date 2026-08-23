# NDABI Supabase range-session performance v6.8 results

The first formal campaign ran at `20260823T150337Z` and failed its frozen speed gate.

All seventeen security checks passed.
All five processes observed exactly 420 data queries.
Every process passed the result, request-compression, allocation, and validator gates.
All three wall-ratio coefficients of variation stayed below 10%.

Median NDABI wall time measured 0.374 times PostgREST for one row.
It measured 0.424 times PostgREST for 32 rows.
It measured 0.514 times PostgREST for 128 rows.
Two 32-row processes and four 128-row processes missed the 0.450 hard gate.

Median 128-row NDABI allocations fell from 286 in v6.7 to 156.
Median 128-row allocated bytes fell from 107,885 to 84,716.
PostgreSQL still materialised and transmitted 128 separate database rows.
The next frozen campaign must return one packed native binary result.

Source digest `69111fd4f01c7891a8ba8c4b2d50828731ae1d78fb446b7c6ea782b9e01f5576` does not match commit `8eb2f90`.
The committed source digest is `9b4728cabd87a918868e60f2b84091e93dbc7af5b846e59d78d2ed4507295401`.
The campaign therefore fails source custody and supports no accepted Supabase performance or allocation claim.
