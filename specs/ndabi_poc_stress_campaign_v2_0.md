# NDABI POC Docker stress campaign v2.0

**Status:** FROZEN before the first v2.0 result. **Date:** 2026-08-22.

This campaign stress-tests the accepted v1.9 binary without changing its implementation.

## 1. Frozen input

Use the exact `ndabi-showdown:v1.9-local` image and release binary.
Run `point-100k`, `filter-100k-64k`, and `filter-1m-1m`.

Run three logical sessions.
Run ten independent containers for each case in each session.

The campaign therefore contains 90 process results.
Use 63 measured batches and five warm-up batches in each process.

## 2. Hard gates

Require all 90 process hard gates and exit codes to pass.
Require one source fingerprint, one image identifier, and Linux ARM64 execution.

Require zero hot allocations for full NDABI, session-bound NDABI, and direct execution.
Require every registered ratio coefficient of variation at or below 10%.

Require the three session medians for each registered ratio at or below 10% variation.
Retain the v1.9 speed and direct-distance targets.

## 3. Custody

Store every raw result exclusively.
Bind the summary to the runner, preregistration, image, binary, and source digests.

Preserve any valid failed result.
Do not rerun a failed campaign under this version.

## 4. Boundary

This campaign uses Docker Desktop and a fixture query engine.
It does not prove physical-core, native Linux, White Tree, PostgreSQL, socket, remote-model, or production behaviour.
