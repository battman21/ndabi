# NDABI operand-bundle comparative campaign v0.1

**Status:** Frozen and not executed.

**Protocol:** `ndabi_operand_bundle_candidate_v0_1.md`.

## 1. Question

Measure whether one registered operand bundle removes repeated client and adapter work.
Do not treat binary syntax as a database-engine speed claim.

The campaign separates three effects:

| Effect | Measurement |
|---|---|
| request compression | complete authenticated request bytes |
| semantic reuse | static operand decodes and allocations |
| complete workflow | wall time, client CPU, and database queries |

## 2. Compared arms

Use one SQL statement, one result encoding, and one PostgreSQL role in every arm.

| Arm | Request work | Database work |
|---|---|---|
| `fused_native` | pass three prepared typed arrays | one prepared query |
| `ndabi_graph` | authenticate and decode all operands | one prepared query |
| `ndabi_bundle` | authenticate dynamic thresholds and reuse two static arrays | one prepared query |

Exclude repeated PostgREST and repeated SQL from the primary speed gate.
Report them only as workflow-collapse context.

Register the bundle before measurement.
Report registration latency and bytes separately.

## 3. Frozen workload

Use the registered PostgreSQL review-batch profile.
Keep the start and count arrays immutable.
Change every score threshold before each measured execution.
Generate thresholds deterministically from the iteration number.

Use one million fixture rows.
Use an indexed `bigint` primary key and one integer score column.
Return one fixed 16-byte aggregate record per item.

Run these cells:

| Items | Executions per bundle | Concurrency |
|---:|---:|---:|
| 8 | 4,096 | 1 |
| 128 | 4,096 | 1 |
| 1,024 | 4,096 | 1 |
| 1,024 | 4,096 | 8 |
| 1,024 | 4,096 | 32 |

Run separate amortisation cells with 1, 8, 256, and 4,096 executions.
Include registration in the amortised total only.

## 4. Frozen byte model

Count the complete authenticated NDABI frame.
Do not count only the value payload.

The graph request contains 16 operand bytes per item.
The bundled execution contains four dynamic operand bytes per item.
Both requests include their fixed frame and record headers.

At 1,024 items, require at least 70% request reduction.
The theoretical large-batch limit approaches 75% for this profile.

Also report the complete registration frame.
Do not hide registration through request-byte averaging.

## 5. Measurements

Collect these values for every arm and cell:

| Metric | Unit |
|---|---|
| complete request | bytes |
| wall latency | mean, p50, p95, and p99 nanoseconds |
| throughput | complete workflows per second |
| client thread CPU | mean and p95 nanoseconds |
| process allocations | count and bytes per workflow |
| resident memory | peak and steady-state bytes |
| database queries | count per workflow |
| exact result equality | Boolean |
| receipt verification | Boolean |
| static bundle decodes | count per authority bundle |

Measure the registration latency, CPU, allocations, and bytes separately.
Record the PostgreSQL server CPU where the host supports reliable process accounting.

## 6. Acceptance gates

Apply the primary gates at 1,024 items and concurrency one.

| Gate | Required result |
|---|---|
| request bytes | at least 70% below `ndabi_graph` |
| static decode count | exactly one across 4,096 executions |
| adapter decode CPU | at least 70% below `ndabi_graph` |
| client allocated bytes | at least 50% below `ndabi_graph` |
| protocol-dominant client CPU | at least 25% below `ndabi_graph` |
| complete p95 against `fused_native` | no more than 5% slower |
| complete mean against `fused_native` | no more than 3% slower |
| results | byte-for-byte equal |
| receipts | valid for every NDABI execution |

The database-dominant cells do not require a 25% complete-stack speed gain.
They must remain within the fused-native floors.

The 10x workflow claim requires at least ten collapsed database exchanges.
Do not derive it from this single-query profile.

## 7. Run validity

Use the pinned Rust toolchain and lock file.
Build the measured binary once before qualification.
Use the same binary digest for every formal repetition.

Require three consecutive host-idle samples above 80%.
Refuse active compilers, benchmark processes, or unrelated high-CPU workloads.
Do not stop another task without explicit authorisation.

Use one temporary PostgreSQL container with a pinned digest.
Use a random loopback port and a read-only test role.
Remove the container and its temporary volume after each campaign.

Run five formal repetitions.
Require a coefficient of variation below 10% for primary mean and p95 values.
Randomise or rotate arm order inside each repetition.

## 8. Result integrity

Change dynamic thresholds each iteration.
Require exact output equality before recording a timing sample.
Verify every NDABI receipt outside the database query.

Record the source manifest, binary digest, image digest, host snapshot, and command arguments.
Store raw samples and one aggregate report.
Never overwrite an earlier result directory.

## 9. Claim boundary

Passing request compression proves wire reduction only.
Passing the static-decode gate proves adapter semantic reuse.
Passing the fused-native gates proves low overhead for this PostgreSQL profile.

This campaign does not prove WAN, TLS, energy, token, MongoDB, or White Tree performance.
It does not prove arbitrary SQL support.
