# NDABI Supabase production campaign v8.1

Status: candidate preregistration. Freeze this document with the implementation before formal measurement.

## 1. Correction

The v8.0 campaign produced no complete repetition and accepted no performance result.
Its PostgREST RPC control completed in 1.451 seconds at concurrency one.
The two-second duration gate rejected that worker before the first repetition completed.

Retain every v8.0 workload, correctness, security, performance, and repeatability gate.
Increase PostgREST RPC samples from 1,023 to 2,047 per worker.
Increase repeated PostgREST samples from 127 to 255 per worker.
Keep native and NDABI samples at 8,191 per worker.

## 2. Purpose

Measure the complete NDABI path against three controls with identical data, identity, policy, query shape, and result bytes.
Separate binary protocol overhead from operation fusion and HTTP round trips.
Test repeatability across fresh service stacks.

## 3. Fixed workload

Use one million PostgreSQL rows.
Use the existing forced row-level security policy.
Use one authenticated user with fixed signed claims.
Use sixteen indexed operations per logical request.
Return eight rows for each operation.
Return the complete canonical result without projection or omission.

Run concurrency levels 1, 8, and 32.
Give each worker a distinct indexed range.
Reject overlapping worker ranges.

## 4. Required arms

Run these four arms through Supavisor session mode.

| Arm | Transport | Database work | Purpose |
|---|---|---|---|
| Native fused | PostgreSQL extended protocol | One prepared set query | Measure the engine floor |
| NDABI | Authenticated binary frame | The same prepared set query | Measure NDABI overhead |
| PostgREST RPC | One JWT HTTP request | One security-invoker set function | Measure HTTP without repeated calls |
| Repeated PostgREST | Sixteen JWT HTTP requests | Sixteen indexed queries | Measure the existing REST path |

Use the same canonical result schema for native fused and NDABI results.
Decode PostgREST results into the same canonical bytes.
Reject an arm when any complete result differs.

## 5. Sampling and ordering

Create three independent Docker stacks.
Remove every stack and network before the next stack starts.
Run five complete repetitions within each stack.
Record the stack identifier and repetition identifier.

Use 8,191 measured requests per native worker.
Use 8,191 measured requests per NDABI worker.
Use 2,047 measured requests per PostgREST RPC worker.
Use 255 measured requests per repeated PostgREST worker.
Retain three warm-up requests per worker.
Require every measured worker and arm to run for at least two seconds.

Rotate the first arm through a fixed Latin-square order.
Record the complete arm order.
Do not select the order after measurement.

## 6. Correctness and query gates

Require one data query for each native fused request.
Require one data query for each NDABI request.
Require one top-level RPC query for each PostgREST RPC request.
Require sixteen data queries for each repeated PostgREST request.

Require exact result bytes for every worker and arm.
Require exact query counts for every arm.
Require forced row-level security and least privilege.
Run all seventeen v7.6 security checks on every fresh stack.

## 7. Performance gates

Apply every gate at every concurrency level.
Apply every gate within every repetition.

Require NDABI throughput to reach at least 0.85 times native fused throughput.
Require NDABI p50 latency to stay within 1.20 times native fused p50 latency.
Require NDABI client CPU to stay within 1.25 times native fused client CPU.
Require NDABI throughput to exceed repeated PostgREST throughput by at least five times.
Require NDABI p95 latency below 25 milliseconds.

Treat the PostgREST RPC comparison as an attribution measurement.
Do not set its result as an NDABI acceptance gate.

## 8. Repeatability gates

Require fifteen complete repetitions across three fresh stacks.
Require each throughput-ratio coefficient of variation below 15%.
Require each p95-ratio coefficient of variation below 15%.
Require each stack-median ratio coefficient of variation below 10%.
Require the campaign median NDABI p95 within 1.15 times the native fused p95.

Do not combine missing repetitions with valid repetitions.
Reject the complete campaign after one missing or invalid repetition.

## 9. Resource evidence

Record client CPU, allocation count, allocated bytes, and peak additional live bytes.
Record container CPU and memory before and after every arm.
Treat container resource values as diagnostics until a later campaign freezes resource gates.

Record available application payload bytes for every arm.
Mark a value unavailable when the client library cannot measure it exactly.
Do not call these values network-wire measurements.
Use a later TLS campaign to measure encrypted wire bytes.

## 10. Build and evidence custody

Build one dedicated release binary before service creation.
Hash the complete source set and release binary.
Require committed source and a clean tracked worktree.
Do not compile during a measured stack.

Poll for compiler processes every 250 milliseconds during measured arms.
Describe this result only as a monitor observation.
Do not claim that an unobserved short process did not run.

Write every repetition before aggregate validation.
Create a deterministic manifest with every evidence-file SHA-256 digest.
Reject missing, additional, changed, symbolic-link, or non-regular evidence files.
Do not include JWTs, private keys, connection strings, or row data in evidence metadata.

## 11. Functional smoke mode

Provide a three-request functional smoke mode.
Allow this mode during unrelated host builds.
Disable every performance and repeatability gate in this mode.
Mark every comparison as functional-only.
Never write an accepted formal result from this mode.

## 12. Production boundaries

This campaign tests local Docker and Supavisor session mode.
It does not test transaction pooling, hosted Supabase, TLS, WAN delay, key custody, or geographic distribution.
It does not prove general SQL, general writes, token savings, service-memory savings, or energy savings.

## 13. Development result

Performance smoke `20260824T165552Z` used uncommitted but stable source.
It passed every non-CPU comparison gate.
Combined process CPU exceeded native by 47.17%, 32.26%, and 37.91% at concurrency 1, 8, and 32.
Reject the smoke and do not start the formal campaign from this candidate.
