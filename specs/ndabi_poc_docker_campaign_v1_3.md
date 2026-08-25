# NDABI POC Docker campaign v1.3

**Status:** FROZEN before the first v1.3 result. **Date:** 2026-08-22.

This campaign tests the unchanged v1.1 measurement binary inside the local Docker Linux environment.
It tests Linux ARM64 portability, containment, repeatability, and relative performance.

It does not test bare-metal Linux. Docker Desktop runs the container inside a LinuxKit virtual machine.
Therefore, the campaign cannot establish publishable absolute latency, energy, NUMA, or physical-core behaviour.

## 1. Fixed environment

Build `research/showdown/docker/Dockerfile.v13` from the repository root.
Use the `rust:1.92-bookworm` builder and the `debian:bookworm-slim` runtime.

Bind every result to the immutable Docker image identifier and release-binary SHA-256 digest.
Require Linux and ARM64 in every result. Refuse an image change during the campaign.

Run each container without a network. Use a read-only root filesystem.
Drop all Linux capabilities. Set `no-new-privileges` and a 64-process limit.

Limit each container to 4 GiB. Pin each container to Linux virtual CPU zero.
This affinity does not prove physical Apple-core affinity outside the LinuxKit virtual machine.

## 2. Fixed workload

Run all 12 v1.2 cases. Run three independent containers for each case.
This produces 36 raw process results.

Use 24 measured batches and two warm-up batches per arm.
Retain the v1.2 operations-per-batch values without changes.

Record the process user time, system time, elapsed time, and maximum resident set size.
Treat these process measurements as Docker-relative evidence only.

## 3. Hard gates

Require every process hard gate to pass. Require every measurement calibration to pass.
Require one source fingerprint across all processes. Require zero NDABI hot-path allocations.

Require prepared JSON to beat stateless JSON by at least 2.5 times in every point-query median.
Require NDABI to beat protected CBOR by at least 1.05 times in every point-query median.

Measure process-repeatability coefficients for `point-100k` and `filter-100k-64k`.
Require each registered causal ratio coefficient of variation to remain at or below 15 percent.

Any correctness, authority, corruption, allocation, calibration, custody, or environment failure fails the campaign.
Do not discard a valid JSON result when its process exits with a failed hard gate.

## 4. Evidence custody

Store every raw result exclusively under one campaign directory.
Store its SHA-256 digest, process exit code, resource usage, case, and replica number.

Store a failure manifest before stopping after a crash, timeout, or invalid JSON result.
Record the runner, Dockerfile, preregistration, image, and release-binary digests.

## 5. Decision rules

A pass proves this POC repeats inside this local Linux ARM64 Docker environment.
It also supports the registered relative speed and allocation claims within that environment.

A failure disproves at least one registered claim for this campaign configuration.
Do not rerun the same preregistration after a failure.

Do not publish absolute latency from this campaign.
Run the later native Linux campaign before making an absolute Linux performance claim.
