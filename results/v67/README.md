# NDABI Supabase dedicated-session performance v6.7 results

The first formal campaign ran at `20260823T145613Z` and failed its frozen speed gate.

All seventeen security checks passed.
All five processes observed exactly 420 data queries.
Every process passed the result, request-compression, and validator gates.
All three wall-ratio coefficients of variation stayed below 10%.

Median NDABI wall time measured 0.373 times PostgREST for one row.
It measured 0.440 times PostgREST for 32 rows.
It measured 0.529 times PostgREST for 128 rows.
The 128-row case missed the 0.500 hard gate in every process.

Median NDABI allocations increased from 82 at 32 rows to 286 at 128 rows.
Median allocated bytes reached 107,885 at 128 rows.
The adapter builds an identifier array and allocates each binary payload.
The next frozen campaign must use a scalar range plan and borrowed payload bytes.

Source digest `7968cfbd87df86348006d4a1900639486db11e94726a4ee2ad87bb687e28761b` binds the campaign source.
Binary digest `ef8c3744c7843a2325fffa0e46e40ab64a1373b0556c9fa4eae0c7ef46a68351` binds the tested executable.
This result supports no accepted Supabase performance claim.
