# Canonical PostgreSQL batch methodology repair v6.3

The first formal v6.3 campaign passed every gate across five fresh client processes.
It used one ephemeral, digest-pinned PostgreSQL 16 container and a dedicated release build.

At 32 operations, median p95 speedup measured 25.75 times repeated canonical execution.
At 128 operations, median p95 speedup measured 73.99 times repeated canonical execution.
The minimum process speedups measured 19.07 times and 48.44 times.

Request bytes fell by 84.38% and 86.72%.
Median CPU speedups measured 21.54 times and 47.47 times.
Minimum allocation reductions measured 88.61% and 90.77%.
Minimum allocated-byte reductions measured 64.33% and 53.02%.

Median batch wall time stayed within 1.110 times native fused execution across every process.
The native p95 diagnostic remained noisy and reached 2.230 times in one process.
The native arm excludes NDABI authentication and receipts, so it remains a performance floor.

- Campaign: `20260823T044535Z`
- Aggregate SHA-256: `207ceb38beb0a52dcdbc8298a27753ef95ac8c4452bd7d2e6c6db3235a42a8e0`
- Binary SHA-256: `d404007ef3745cfb4e0eb0b36cdb27b6190165375b25eec582d26197dae544a5`
- Source SHA-256: `b1f163763eb38ff5629bfe118b28a4333566567c9beec17ce398846d34a6d8b3`

This result proves one finite local PostgreSQL read profile.
It does not prove hosted Supabase, general queries, tokens, energy, WAN, TLS, or physical Linux.
