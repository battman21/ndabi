# NDABI Supabase CPU attribution campaign v8.2

Status: candidate preregistration.
Freeze this document with the implementation before performance measurement.

## 1. Purpose

Measure the CPU saved by the incremental server receipt.
Separate the remaining client receipt cost from the server path.
Retain the v8.1 production-shaped workload and controls.

## 2. Fixed workload

Use one million PostgreSQL rows and forced row-level security.
Use sixteen indexed operations and eight rows per operation.
Return the complete canonical result bytes.
Run concurrency levels 1, 8, and 32.
Use Supavisor session mode for every PostgreSQL arm.

## 3. Arms

| Arm | Receipt work | Purpose |
|---|---|---|
| Native fused | None | Measure the engine floor |
| Incremental NDABI | Incremental server receipt and complete client verification | Measure total improved CPU |
| Incremental NDABI server | Incremental server receipt without client verification | Attribute server CPU |
| Legacy NDABI | Complete server and client result hashing | Measure the removed work |
| PostgREST RPC | One JWT HTTP request | Measure fused HTTP |
| Repeated PostgREST | Sixteen JWT HTTP requests | Measure the layered path |

## 4. Correctness and security

Require exact result bytes across every worker and arm.
Require one database data query for each non-repeated request.
Require sixteen data queries for each repeated PostgREST request.
Retain all seventeen v8.1 security checks.
Add six incremental receipt checks on every fresh stack.
Require changed frames, results, receipts, and replays to refuse.

## 5. Sampling

Use 8,191 samples for every native and NDABI worker.
Use 2,047 PostgREST RPC samples per worker.
Use 255 repeated PostgREST samples per worker.
Require each arm and worker to run for at least two seconds.
Retain three Docker stacks and five repetitions per stack.
Retain the fixed Latin-square arm order.

## 6. Performance gates

Apply every gate within every repetition and concurrency level.

| Metric | Gate |
|---|---:|
| Incremental NDABI throughput over native | At least 0.85 |
| Incremental NDABI p50 over native | At most 1.20 |
| Incremental NDABI combined CPU over native | At most 1.25 |
| Incremental server CPU over native | At most 1.10 |
| Incremental combined CPU over legacy NDABI | At most 0.95 |
| Incremental throughput over repeated PostgREST | At least 5.00 |
| Incremental absolute p95 | Below 25 milliseconds |

Retain every v8.1 repeatability gate.
Reject the campaign after one missing or invalid repetition.

## 7. Attribution limits

Calculate client receipt CPU as the incremental combined CPU minus incremental server CPU.
Describe this value as an estimate from separate workers.
Do not clamp a negative estimate.
Treat container resource snapshots as diagnostics.

## 8. Boundaries

This campaign tests local Docker and Supavisor session mode.
It does not test hosted Supabase, WAN delay, production custody, energy, or provider tokens.
It does not prove arbitrary SQL or general writes.
