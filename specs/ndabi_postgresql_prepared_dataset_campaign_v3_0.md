# NDABI PostgreSQL prepared-dataset campaign v3.0

**Status:** FROZEN before the first v3.0 result. **Date:** 2026-08-22.

This campaign removes database setup work from every measured client process.
The v2.9 failed evidence remains unchanged.

Use binary SHA-256 `eb2badc86902f4fb37ffa319e82e9998d7f8c8a7e6d5f0965811cae838d681b4`.

## 1. Fixed preparation

Start one ephemeral PostgreSQL container from the registered image.
Run the binary once with `--prepare` before any measured client.
The preparation creates, loads, analyses, and checkpoints the 100,000-row dataset.

Do not modify the dataset between measured processes.
Each measured process must confirm the complete row count before preparing queries.

## 2. Fixed process campaign

Run five independent client processes sequentially.
Retain every complete process result before aggregation.
Use the v2.9 median and coefficient calculations without changes.

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

This campaign removes a known local benchmark contaminant.
It does not prove native Linux, TLS, controlled WAN delay, concurrency, energy, or another engine.
