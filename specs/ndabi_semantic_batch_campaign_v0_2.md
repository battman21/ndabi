# NDABI semantic batch campaign v0.2

**Status:** Frozen next campaign. **Date:** 2026-08-27.

## 1. Purpose

Qualify semantic stack compression against repeated and expert-fused native PostgreSQL execution.
Do not use the v0.1 diagnostic as accepted performance evidence.

## 2. Workload

Use one million indexed rows in digest-pinned PostgreSQL 16.
Use batch sizes 1, 8, 32, 128, 256, and 1,024.
Use controlled round trips of 0, 2, 10, and 40 ms.
Use concurrency 1, 8, and 32.
Use equal prepared statements, operands, policies, result bytes, and connection lifetimes.

Compare repeated native, fused native, and NDABI graph arms.
Rotate arm order for every measured block.
Run five fresh processes with at least 200 measured samples per selected cell.

Use these selected cells:

| Batch size | Controlled round trip | Concurrency |
|---:|---:|---:|
| 1 | 0 ms | 1 |
| 8 | 0 ms | 1 |
| 32 | 0 ms | 1 |
| 128 | 0 ms | 1 |
| 256 | 0 ms | 1 |
| 1,024 | 0 ms | 1 |
| 256 | 2 ms | 1 |
| 256 | 10 ms | 1 |
| 256 | 40 ms | 1 |
| 256 | 2 ms | 8 |
| 256 | 2 ms | 32 |

Run each arm separately through a coordinated start barrier.
Rotate the arm order for each cell and repetition.
Use 200 repeated-native samples per worker.
Run each fused-native and NDABI arm for at least 200 samples and approximately five seconds.

## 3. Hard correctness gates

Every result byte must match across all three arms.
Every NDABI receipt must verify.
Replay, changed frames, changed receipts, expired deadlines, excessive budgets, and unknown graphs must fail before repeated work.
The PostgreSQL role must refuse writes.
Any failure rejects the complete campaign.

## 4. Performance gates

| Boundary | Gate |
|---|---|
| NDABI against fused native mean | No repetition exceeds 3% overhead |
| NDABI against fused native p95 | No repetition exceeds 5% overhead |
| NDABI against repeated native at 256 items and 2 ms | Every repetition reaches 100 times speedup |
| Complete stack CPU against repeated native | At least 50% lower |
| Client allocations against repeated native | At least 80% lower |
| Maximum RSS against fused native | No more than 5% higher |
| Compact request against concise JSON | At least 60% fewer bytes |
| Relative process coefficient of variation | Less than 10% |

Do not apply the 100 times gate to one operation or to the fused native floor.
Report work per request and logical operations per second separately.

## 5. Evidence custody

Freeze the specification before measurement.
Hash the complete Rust source closure, `Cargo.lock`, release binary, and container manifests.
Record raw samples, host activity, thermal state, container CPU, container memory, and exit status.
Reject a run that overlaps another build or performance campaign.
Require at least 80% host idle before each formal arm.
Wait no more than five minutes for the host to become quiet.

Use `campaigns/semantic_batch_v02.py` as the sole campaign runner.
Use `--smoke` for unqualified end-to-end verification.
Use `--formal` only from a clean committed checkout.

## 6. Promotion boundary

Passing this campaign qualifies one PostgreSQL read-only semantic batch profile.
It does not qualify Supabase, MongoDB, White Tree, writes, streaming, provider tokens, or production key custody.
Run an equivalent forced-RLS Supabase campaign next.
