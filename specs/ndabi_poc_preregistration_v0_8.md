# NDABI POC preregistration v0.8

**Status:** FROZEN before the first v0.8 benchmark result. **Date:** 2026-08-21.

The frozen v0.7 campaign failed. It passed 27 of 30 process gates. Direct and prepared p95
coefficients of variation reached approximately 29%.

The test host exposes 12 performance cores and four efficiency cores. The v0.7 results formed two
clear timing groups. This experiment tests a recorded scheduler request without changing the workload.

## 1. Fixed change

Request the macOS user-interactive quality-of-service class before warm-up. Refuse the run if macOS
rejects that request. Record the requested scheduler class in every result.

Do not change the kernel, frames, workload, arm order, iteration count, warm-up count, or v0.7
performance targets. Use the same 30 independent processes.

## 2. Evidence

Bind the campaign to one source fingerprint and one release-binary SHA-256 digest. Store every raw
process result under one immutable campaign directory. Record every raw result SHA-256 digest.

Report p95, p99, p99.9, throughput, population deviation, and coefficient of variation. Preserve the
failed v0.7 campaign as the default-scheduler comparison.

## 3. Hard gates

All 30 process gates must pass. Prepared and direct p95 coefficients of variation must not exceed
10%.

The conservative same-executable p95 speedup must remain at least three times for prepared wire and
four times for the direct kernel.

Every exactness, refusal, byte-size, allocation, receipt-time, and control-memory gate remains active.

## 4. Required disclosures

The scheduler request does not pin one physical core. This experiment still requires Linux CPU
affinity and hardware counters before publication.

The result remains a local in-memory test. It does not prove production scheduling, durable custody,
shared-state concurrency, remote transport, database adapters, energy, or model tokens.
