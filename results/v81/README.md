# NDABI Supabase production campaign v8.1

No v8.1 performance campaign is accepted.

The candidate retains every v8.0 workload, correctness, security, performance, and repeatability gate.
It increases PostgREST RPC samples from 1,023 to 2,047 per worker.
It increases repeated PostgREST samples from 127 to 255 per worker.
These changes give the two control arms a margin above the required two-second duration.

Commit the candidate before the formal campaign starts.

Performance smoke `20260824T165552Z` used uncommitted but stable source.
It passed every throughput, p50, absolute p95, REST speed, correctness, query, duration, and security gate.
NDABI reached 85.88%, 94.95%, and 95.07% of native throughput at concurrency 1, 8, and 32.
Combined process CPU measured 147.17%, 132.26%, and 137.91% of native.
The CPU limit was 125% of native.
The smoke is rejected.
