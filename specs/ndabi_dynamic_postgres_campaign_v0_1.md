# NDABI dynamic PostgreSQL campaign v0.1

Status: frozen candidate benchmark.

## Purpose

Measure the dynamic agent instruction path against an equal-result trusted typed control.
Separate binary request compression from database execution performance.
Reject any result that lacks exact output and receipt proof.

## Claims under test

The cached dynamic request must reduce full dynamic request bytes by at least 70 percent.
The cached dynamic path must stay within five percent of the typed control p95 latency.
The cached dynamic path must stay within three percent of the typed control mean latency.
The cached dynamic path must stay within fifteen percent of the typed control client CPU.
The cached dynamic path must not allocate more bytes than the full dynamic path.
The cached dynamic path must reach 95 percent of the typed control throughput.

These gates do not claim model-token, WAN, energy, or complete-stack savings.

## Frozen operation

Use the one-million-row `public.items` fixture.
Select `id` and `payload` where `id` is at least parameter zero.
Sort by `id` in ascending order.
Limit the result with parameter one.
Return the canonical dynamic result format.

Use 16 operand variants.
Use result counts of 1, 32, and 256 at concurrency one.
Use 32 result rows at concurrency 8 and 32.

## Arms

| Arm | Admission | Program handling | Receipt |
|---|---|---|---|
| `governed_native` | Trusted typed benchmark control | Preverified program and operands | Required |
| `dynamic_full` | Authenticated full frame | Verify the program and operands per request | Required |
| `dynamic_cached` | Authenticated cached frame | Resolve a registered program and verify compact operands | Required |

Compile the typed control only with `benchmark-governed-native`.
Do not expose this control to an untrusted caller.

## Measurement boundary

Prepare authenticated frames before the measured interval.
Include server admission, replay control, database execution, canonical result encoding, and receipt verification.
Measure wall latency, client-thread CPU, allocations, request bytes, and per-worker throughput.
Run one process and one retained PostgreSQL connection per worker.

## Correctness gates

Every arm must return one identical fingerprint over all 16 exact canonical results.
Every operation must return the expected result bytes.
Generate expected bytes from one independent prepared SQL statement and an independent canonical encoder.
Every operation must verify its receipt.
The backend must use one read-only transaction and one database deadline per operation.

## Performance gates

Apply all gates to each formal cell.

| Gate | Requirement |
|---|---|
| Cached request reduction | At least 70 percent against the full dynamic request |
| Cached p95 latency | At most 105 percent of the typed control |
| Cached mean latency | At most 103 percent of the typed control |
| Cached client CPU | At most 115 percent of the typed control |
| Cached allocation bytes | No more than the full dynamic path |
| Cached throughput | At least 95 percent of the typed control |
| Repeatability | Each arm mean and p95 coefficient of variation stays below 10 percent |

## Runs

The smoke run uses 100 operations, 10 warm-ups, 32 result rows, and concurrency one.
The formal run uses five repetitions.
Each formal arm executes 4,096 total measured operations per cell.
Divide these operations across workers at concurrency 8 and 32.
Rotate the arm order for every cell and repetition.

## Evidence custody

Require a clean checkout for a formal run.
Record the commit, source closure, compiler, binary digest, image identities, and host snapshots.
Require three quiet-host samples before a formal run.
Write the aggregate and cleanup result into `campaigns/results/dynamic-isa-v01/`.
Remove the campaign binary and exact campaign containers after every run.
