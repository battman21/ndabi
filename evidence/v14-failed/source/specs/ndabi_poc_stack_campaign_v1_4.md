# NDABI POC stack compression campaign v1.4

**Status:** FROZEN before the first v1.4 result. **Date:** 2026-08-22.

The v1.3 campaign failed because its control performed arithmetic for every measured operation.
That control measured loop work, not only timer overhead.

This campaign copies the v1.3 execution and codec logic into the v1.4 binary.
It changes measurement calibration and registers complete-path speed targets.

## 1. Corrected calibration

Measure at least 1,000 back-to-back `Instant` calls.
Require the non-zero timer p95 below 0.1% of the fastest median batch.

Measure the arithmetic loop separately.
Report its ratio without using it as a hard gate.

Run 24 measured batches and two warm-up batches per arm.
Retain every v1.3 case and operations-per-batch value.

## 2. Fixed Docker environment

Pin the Rust builder and Debian runtime images by digest.
Build one Linux ARM64 image and bind every result to its identifier.

Use the v1.3 containment settings.
Run without a network, with a read-only filesystem, and with all capabilities dropped.

Pin each process to Linux virtual CPU zero.
Do not claim physical-core affinity or bare-metal latency.

## 3. Fixed workload

Run all 12 v1.3 cases.
Run three independent containers for each case.

Store all 36 process results exclusively.
Preserve any valid failed result.

## 4. Hard gates

Require every correctness, authority, corruption, allocation, calibration, source, image, and custody gate.
Require zero NDABI hot-path allocations.

For each point case, require stateless JSON divided by NDABI at or above 7.5 times.
For each point case, require stateless JSON divided by direct at or above 11 times.

For each point case, require prepared JSON divided by NDABI at or above 2.25 times.
Require protected CBOR divided by NDABI at or above 1.05 times.

For every non-point case, require protected CBOR divided by NDABI at or above 0.95 times.
This prevents an NDABI regression above 5%.

Require every causal-ratio coefficient of variation below 10%.
Any hard-gate failure fails the campaign.

## 5. Decision

A pass validates the complete stack-compression speed within this local Docker environment.
It does not establish database, socket, remote, token, energy, or bare-metal performance.

A failure disproves at least one registered v1.4 claim.
Do not rerun this preregistration after a failure.
