# NDABI PostgreSQL paired replay campaign v3.5

**Status:** FAILED. **Frozen:** 2026-08-22. **Run:** 2026-08-22.

## 1. Correction

Campaign v3.4 ran each concurrency arm as one separate time block.
Equivalent arms received different database, storage, and scheduler conditions.
The resulting ratios varied from 0.62 to 3.26 times.

This campaign uses paired microblocks and aggregate performance gates.
It does not change the security profiles, controls, dataset, or target thresholds.

## 2. Frozen profiles and controls

Use the same four arms from campaign v3.4.
Keep the same PostgreSQL replay transaction and exact result contract.
Keep the same batches, concurrency levels, Docker images, and connection limits.

## 3. Paired latency method

Use five warm-up microcycles and 63 measured microcycles.
Execute all four arms once per microcycle.
Rotate the first arm in every microcycle.

Retain every process p95 and every raw sample.
Apply performance gates to aggregate medians across five complete processes.
Do not reject a correct process because of one local timing ratio.

## 4. Paired concurrency method

Use nine measured blocks with seven requests per worker and arm.
Rotate the first arm in every block.
Use three warm-up requests per worker and arm.

Start all workers through one barrier.
Keep one connection and one replay identity per worker.
Retain every request latency and the critical worker duration for each arm.

## 5. Process gates

1. Complete every registered request.
2. Return byte-identical results and receipts.
3. Pass restart invalidation, killed-transaction rollback, and committed-replay refusal.
4. Allocate no Rust heap memory during borrowed decoding.
5. Return a complete report and a zero exit code.

Only correctness and evidence failures reject an individual process.

## 6. Aggregate performance gates

| Gate | Target |
|---|---|
| Batch-32 ephemeral p95 | NDABI no more than 1.05 times native |
| Batch-128 ephemeral p95 | NDABI no more than 1.05 times native |
| Batch-32 resumable p95 | NDABI no more than 1.10 times native |
| Batch-128 resumable p95 | NDABI no more than 1.10 times native |
| Concurrent ephemeral throughput | NDABI at least 90% of native |
| Concurrent resumable throughput | NDABI at least 90% of native |
| Concurrent ephemeral p95 | NDABI no more than 1.15 times native |
| Concurrent resumable p95 | NDABI no more than 1.15 times native |
| Ratio repeatability | Process ratio coefficient below 0.20 |

Apply every concurrency gate at levels 1, 8, 32, and 128.
Any failed aggregate gate rejects the campaign.

## 7. Evidence gates

Run five fresh Linux ARM64 clients from one immutable image.
Require five complete reports and five zero exit codes.
Retain the frozen source, lockfile, image identifier, binary digest, raw reports, and aggregate summary.

## 8. Boundaries

Docker Desktop does not prove physical Linux behaviour.
The campaign excludes TLS, WAN delay, multi-node coordination, malicious rollback, energy, and PostgreSQL server memory.

## 9. Result

All five Linux ARM64 processes returned complete evidence and zero exit codes.
Every correctness, security, identity, latency, throughput, and p95 target passed.

Two registered repeatability gates failed.
Concurrency-one resumable throughput had a 0.233 coefficient of variation.
Concurrency-eight resumable p95 had a 0.312 coefficient of variation.
The registered maximum was 0.20.

The aggregate NDABI distances ranged from 0.955 to 1.056 times native at batch latency.
Concurrent throughput ranged from 0.951 to 1.111 times native.
Concurrent p95 ranged from 0.941 to 1.004 times native.

The campaign supports correctness and security observations.
It supports no accepted performance claim because repeatability failed.
Do not rerun or change the v3.5 gates.
