# NDABI White Tree repeatability campaign v2.3

**Status:** FROZEN before the first v2.3 result. **Date:** 2026-08-22.

The v2.2 result remains failed and immutable.
Its one-operation p95 made the direct-distance gate sensitive to scheduler outliers.

## 1. Fixed correction

Retain the v2.2 database, workload, arms, correctness gates, and security refusals.
Measure eight complete operations inside each timed sample.
Report latency per operation from each batch.

Use 63 measured samples and five warm-up samples.
Rotate the five arm orders between samples.

## 2. Hard gates

- Every v2.2 semantic, receipt, authority, snapshot, and refusal gate must pass.
- Governed SQL must be at least 2.5 times slower than session NDABI at p95.
- Session NDABI p95 must be no more than 10% slower than native typed p95.
- Native typed and direct-repeat p95 must remain within 10%.
- Full NDABI p95 must be no more than 50% slower than session NDABI p95.

The session arm may measure faster than native because both call the same kernel.
That result does not establish a session-framing speed gain.

## 3. Boundary

This campaign corrects measurement granularity only.
It does not change the operation, dataset, frame formats, or attribution boundary.
