# NDABI Supabase attributed CPU campaign v8.2

No v8.2 performance campaign is accepted.

The candidate separates the incremental server path, complete incremental path, and legacy receipt path.
It retains the v8.1 native, PostgREST RPC, and repeated PostgREST controls.
It adds six fresh-stack checks for the incremental receipt path.
Run the functional smoke before the performance smoke.
Run no formal campaign until every frozen performance gate passes.

Functional smoke `20260824T181147Z` passed exact results and all 23 security checks.
Performance smoke `20260824T181320Z` passed exact results, query counts, duration, latency, throughput, and security checks.
It failed every CPU comparison gate.

Incremental combined CPU measured 138.99%, 132.74%, and 133.50% of native.
Incremental server CPU measured 127.42%, 120.21%, and 117.48% of native.
The estimated client receipt cost measured 412, 532, and 754 nanoseconds per logical operation.
Incremental combined CPU measured 103.09%, 101.12%, and 105.21% of legacy NDABI.

The incremental result digest did not reduce compute for this complete-result workload.
Do not run the formal v8.2 campaign.
