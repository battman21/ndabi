# NDABI PostgreSQL process campaign v2.6

**Status:** FROZEN before the first v2.6 result. **Date:** 2026-08-22.

The v2.5 campaign remains failed and immutable.
Its direct prepared p95 values varied enough to fail one distance gate.

## 1. Fixed campaign

Start one ephemeral PostgreSQL container from the frozen v2.5 image digest.
Run the archived v2.5 binary in five independent client processes.
Use binary SHA-256 `0fb95571ab8f26dbf76fe6b2eaaec1850304ca5518a527ee5e2fe0cf7804b962`.

Each process reloads the same 100,000-row dataset before measurement.
Store each complete result before aggregation.

The binary can exit with status one when its local performance gate fails.
Accept that status only when the complete JSON result and both correctness gates exist.

## 2. Aggregate method and gates

Take the median of the five process p95 values for each arm.
Calculate campaign ratios from those arm medians.

- All five processes must pass literal result, receipt, and frame-refusal gates.
- All five processes must return one canonical response and receipt digest.
- Simple SQL must be at least 1.10 times slower than session NDABI.
- Session NDABI must be no more than 10% slower than native prepared.
- Full NDABI must be no more than 50% slower than session NDABI.
- Native prepared and direct-repeat must remain within 10%.
- Session-native process-ratio variation must remain below 20%.

## 3. Boundary

This campaign uses loopback TCP without TLS.
It does not measure captured wire bytes, server allocations, pipelines, or concurrency.
