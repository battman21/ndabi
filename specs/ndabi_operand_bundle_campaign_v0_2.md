# NDABI operand-bundle comparative campaign v0.2

**Status:** Frozen and not executed.

**Protocol:** `ndabi_operand_bundle_candidate_v0_1.md`.

## 1. Correction

The v0.1 smoke measured complete client CPU and allocations.
PostgreSQL driver work dominated both values.
The v0.1 gates then required a reduction below an unchanged database-driver floor.
That target was mathematically impossible in the measured cell.

This campaign keeps complete CPU, latency, and allocation gates.
It also subtracts the fused-native floor before it measures NDABI protocol overhead.
It does not subtract the floor from reported measurements.

## 2. Compared work

Use the same SQL, PostgreSQL role, one-million-row fixture, and result encoding in every arm.

| Arm | Database exchanges | Request work |
|---|---:|---|
| `fused_native` | one | three prepared typed arrays |
| `ndabi_graph` | one | authenticate and decode all operands |
| `ndabi_bundle` | one | authenticate dynamic operands and reuse registered static operands |

## 3. Cells

Run 4,096 measured executions after 64 warm-ups.
Run five repetitions with rotated arm order.

| Items | Concurrency |
|---:|---:|
| 8 | 1 |
| 128 | 1 |
| 1,024 | 1 |
| 1,024 | 8 |
| 1,024 | 32 |

## 4. Gates

Apply byte compression only to the 1,024-item cells.

| Gate | Required result |
|---|---|
| request bytes | at least 70% below `ndabi_graph` |
| static decode count | exactly one per bundle and worker |
| complete p95 | no more than 5% above `fused_native` |
| complete mean | no more than 3% above `fused_native` |
| complete client CPU | no more than 25% above `fused_native` |
| protocol CPU excess | at least 25% below `ndabi_graph` excess |
| complete allocated bytes | no more than `ndabi_graph` |
| protocol allocation excess | at least 50% below `ndabi_graph` excess |
| results | byte-for-byte equal |
| receipts | valid for every NDABI execution |

Define protocol excess as `max(measured - fused_native, 0)`.
If the graph excess is zero, the bundle excess must also be zero.

## 5. Evidence validity

Use the pinned Rust toolchain, lock file, PostgreSQL image, and Toxiproxy image.
Build one binary before qualification.
Record the source manifest, binary digest, image identity, host state, raw reports, and cleanup result.
Require three consecutive host samples above 80% idle before a formal run.
Refuse an active compiler, campaign, or unrelated high-CPU workload.
Require five repetitions for each cell.
Require variation below 10% for every arm's mean and p95.

## 6. Claim boundary

Passing this campaign proves one PostgreSQL operand-bundle profile.
It does not prove arbitrary SQL, WAN, TLS, energy, tokens, MongoDB, Supabase, or White Tree performance.
Request compression remains a byte claim.
Floor-adjusted CPU remains a protocol-overhead claim.
