# NDABI POC fused-view campaign v1.6

**Status:** FROZEN before the first v1.6 result. **Date:** 2026-08-22.

This campaign tests the optimisation selected by the v1.5 phase profile.
It tests a prepared execution handle and a borrowed result view.

## 1. Hypothesis

The full NDABI frame is not the fastest trusted local interface.
Repeated request fields, response copying, CRC scans, and response parsing add removable work.

A trusted local binding can send an execution handle and a nonce.
It can return a read-only result view and an exact receipt.

## 2. Cases

Run `point-100k`, `filter-100k-64k`, and `filter-1m-1m`.
Run three independent Linux ARM64 containers for each case.

Use 63 measured batches and five warm-up batches.
Use 2,000 operations per point batch, four per 64 KiB batch, and one per 1 MiB batch.

## 3. Arms

Measure stateless JSON, full framed NDABI, fused view, and direct typed execution.
Use the same query engine, capability, command, session rules, result bytes, and receipt semantics.

The fused request contains only a fixed header, an execution handle, and a nonce.
The server resolves the prepared capability and command before execution.

The fused response exposes the produced result buffer and receipt without a second payload copy.
The local trust boundary does not add a duplicate frame checksum.

## 4. Correctness and custody

Require identical semantic results, payload bytes, and receipts for all four arms.
Require replay and unknown-handle refusals before query execution.

Require zero hot allocations for NDABI, fused view, and direct execution.
Require the timer p95 below 0.1% of the fastest median batch.

Pin both Docker base images by digest.
Bind every result to the source, runner, binary, image, and preregistration digests.

Store every raw result exclusively.
Preserve any valid failed result.

## 5. Registered speed gates

Require fused view to exceed stateless JSON by 11 times for the point case.
Require fused view to exceed full NDABI by 1.35 times for the point case.

Require fused view to remain within 10% of direct execution for every case.
Require each registered ratio coefficient of variation at or below 10%.

## 6. Boundary

This campaign measures a trusted local binding over a fixture engine.
It does not prove a socket, PostgreSQL, White Tree, remote model, or production result.
