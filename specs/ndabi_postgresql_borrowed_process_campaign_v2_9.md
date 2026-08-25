# NDABI PostgreSQL borrowed process campaign v2.9

**Status:** FROZEN before the first v2.9 result. **Date:** 2026-08-22.

This campaign tests repeatability for the accepted v2.8 binary.
Use binary SHA-256 `41c2647ded238eddbb24e69cdfc97811f73cde00703097d6474097829d813e55`.

## 1. Fixed campaign

Start one ephemeral container from the v2.8 PostgreSQL image.
Run five independent client processes sequentially.
Each process reloads the registered 100,000-row dataset.

Retain every complete process result before aggregation.
Accept process exit status zero or one when complete JSON exists.

## 2. Aggregate method

Take the median of five process p95 values for each arm and batch size.
Calculate campaign speed ratios from those medians.
Calculate process-ratio coefficients of variation separately.

## 3. Hard gates

- All five processes must return complete results.
- Every process must report zero borrowed-decode allocations and bytes.
- Every process must return exact payload and receipt equality.
- Every batch size must return one result and receipt identity across all processes.
- Batch sizes 32 and 128 must reach four times sequential p95 speed.
- Batch sizes 32 and 128 must remain within 10% of native-set p95.
- Both speed-ratio coefficients of variation must remain below 20%.

Batch size 8 remains diagnostic.

## 4. Boundary

This process campaign uses Docker Desktop and loopback TCP without TLS.
It does not prove native Linux latency, concurrency, WAN delay, energy, or another database engine.
