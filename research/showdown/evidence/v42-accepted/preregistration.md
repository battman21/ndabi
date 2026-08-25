# NDABI PostgreSQL scale and query-shape campaign v4.2

Status: frozen before the first formal campaign.

## 1. Purpose

Test the embedded NDABI architecture beyond one ordered range query.
Test one million PostgreSQL rows with range, predicate, aggregate, and join operations.
Measure complete operation latency, client CPU, allocations, request bytes, response bytes, and exactness.

This campaign does not change the accepted v4.1 evidence.

## 2. Reusable boundary

Use the independent `ndabi-postgres` prototype crate.
Keep authentication, replay control, typed operation decoding, result budgets, and receipts outside the benchmark binary.
Pass prepared SQL from the profile owner into the PostgreSQL backend.

The protocol accepts only registered typed operations.
It must refuse arbitrary SQL and every write operation.
Do not add unsafe write support to improve feature coverage.

## 3. Dataset

Create exactly 1,000,000 deterministic item rows and 4,096 owner rows.
Each item contains an identifier, bucket, owner, score, and 64-byte payload.
Create indexes for each measured predicate and join key.

## 4. Query shapes

| Shape | Logical operation | Result boundary |
|---|---|---|
| range-128 | Read 128 ordered identifiers | 128 item rows |
| predicate-64 | Filter one bucket and a minimum score | At most 64 item rows |
| aggregate | Count rows and sum scores by bucket | At most 1,024 groups |
| join-64 | Join items to owners for one owner | At most 64 joined rows |
| large-range-4096 | Read 4,096 ordered identifiers | 4,096 item rows |

## 5. Arms

Use one persistent PostgreSQL connection and prepared plan per arm.

| Arm | Boundary |
|---|---|
| native-prepared | Construct the typed operation directly and execute the prepared plan |
| compact-json | Encode and decode a complete JSON request before prepared execution |
| ndabi-embedded | Encode, authenticate, verify, decode, execute, budget-check, and receipt the 76-byte frame |

Randomise the arm order for each sample with one deterministic schedule.
Use seven warm-up samples and 63 recorded samples for each shape.
Run five complete client processes from one immutable Linux ARM64 image.

## 6. Correctness and security

Require identical canonical result bytes across all arms, samples, and processes.
Require one deterministic result digest for each query shape.
Require one deterministic NDABI receipt for each query shape and authority binding.

Run these refusal checks in each process:

1. Refuse every changed authenticated frame.
2. Refuse a replayed frame.
3. Refuse an expired frame.
4. Refuse a cross-session frame.
5. Refuse an unsupported opcode.
6. Refuse an excessive result budget.
7. Preserve the nonce after a backend failure.
8. Refuse arbitrary SQL and write operation requests.

## 7. Registered gates

Reject the campaign unless all five processes exit successfully.
Reject the campaign unless every correctness and security check passes.
Reject the campaign unless every shape returns one result identity.

For each query shape, require NDABI median-process p95 below 1.15 times native p95.
For each query shape, require NDABI median-process client CPU below 1.25 times native CPU.
For each query shape, require NDABI mean allocations below native allocations plus five.
Require the NDABI request to use at least 70% fewer application bytes than compact JSON.

Report all failed gates.
Do not replace a failed result with a later run under this version.

## 8. Boundaries

The Docker host runs on Apple silicon.
The client and database containers run Linux ARM64.
This does not prove physical Linux behaviour.

This campaign does not prove TLS, WAN, MongoDB, hosted Supabase, provider tokens, energy, writes, or production key custody.
Test those boundaries in separate frozen campaigns with their real dependencies.
