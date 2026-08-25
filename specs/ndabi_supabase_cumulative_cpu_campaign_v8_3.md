# NDABI Supabase cumulative CPU campaign v8.3

Status: candidate preregistration.
Freeze this document with the implementation before performance measurement.

## 1. Purpose

Measure NDABI client and Docker-stack CPU for the measured request interval.
Test an exact fixed-buffer result encoder against the previous small-write encoder.
Retain exact canonical results, governed admission, and receipt verification.

## 2. Fixed workload

Use one million PostgreSQL rows and forced row-level security.
Use sixteen indexed operations and eight rows per operation.
Return the complete canonical result bytes.
Run concurrency levels 1, 8, and 32.
Use Supavisor session mode for every PostgreSQL arm.

## 3. Arms

| Arm | Result path | Purpose |
|---|---|---|
| Native fused | Exact fixed buffer, no NDABI receipt | Measure the engine floor |
| Fixed NDABI | Exact fixed buffer and one complete receipt | Test the candidate path |
| Legacy NDABI | Small bounded writes and one complete receipt | Measure the encoder change |
| PostgREST RPC | One JWT HTTP request | Measure fused HTTP |
| Repeated PostgREST | Sixteen JWT HTTP requests | Measure the layered path |

## 4. CPU measurement

Use the process CPU clock for every v8.3 client worker.
Read cumulative cgroup CPU immediately before worker release.
Read cumulative cgroup CPU after every worker completes.
Sum PostgreSQL, Supavisor, and PostgREST CPU deltas.
Add the worker process CPU to calculate measured stack CPU.
Reject a missing, changed, or decreasing counter.

The cgroup probe executes one `cat` process in each container.
This fixed probe cost remains in every arm and can bias very short runs.
Require each performance arm to run for at least two seconds.

## 5. Correctness and security

Require exact result bytes across every worker and arm.
Require one database query for each non-repeated request.
Require sixteen database queries for each repeated PostgREST request.
Retain all seventeen applicable v8.0 security checks.
Require a failed exact encoder to expose no partial result.
Require byte and row budgets before allocation or dispatch.

## 6. Sampling

Use 8,191 samples for every native and NDABI worker.
Use 2,047 PostgREST RPC samples per worker.
Use 255 repeated PostgREST samples per worker.
Retain three Docker stacks and five repetitions per stack.
Retain the fixed Latin-square arm order.

## 7. Performance gates

Apply every gate within every repetition and concurrency level.

| Metric | Gate |
|---|---:|
| Fixed NDABI throughput over native | At least 0.95 |
| Fixed NDABI p50 over native | At most 1.15 |
| Fixed NDABI client CPU over native | At most 1.10 |
| Fixed NDABI client CPU over legacy NDABI | At most 0.95 |
| Fixed NDABI measured stack CPU over native | At most 1.10 |
| Fixed NDABI measured stack CPU over PostgREST RPC | At most 0.60 |
| Fixed NDABI measured stack CPU over repeated PostgREST | At most 0.60 |
| Fixed NDABI absolute p95 | Below 25 milliseconds |

Retain every v8.0 repeatability gate.
Reject the campaign after one missing or invalid repetition.

## 8. Boundaries

This campaign tests local Docker and Supavisor session mode.
It measures the request interval, not process setup or container startup.
It does not test hosted Supabase, WAN delay, energy, or production custody.
It does not prove arbitrary SQL, general writes, or token savings.
