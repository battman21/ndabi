# NDABI POC literal-lossless campaign v1.9

**Status:** FROZEN before the first v1.9 result. **Date:** 2026-08-22.

This campaign corrects one v1.8 proof defect.
The v1.8 cross-arm gate compared BLAKE3 payload hashes instead of literal payload bytes.

## 1. Correction

Retain the v1.8 session-bound implementation and every measurement setting.
Compare each complete payload vector across all arms before measurement.

Keep semantic equality, receipt equality, deterministic encoding, authority refusal, replay refusal, and allocation gates.
Expose literal payload equality as a separate hard-gate result.

## 2. Frozen campaign

Use the same three cases, three Linux ARM64 replicas, result bytes, and operation counts as v1.8.
Use 63 measured batches and five warm-up batches.

Retain all v1.8 calibration, custody, repeatability, and speed gates.
Reject the campaign when one literal payload differs.

## 3. Boundary

This campaign measures a trusted local session over a fixture engine.
It does not prove a socket, PostgreSQL, White Tree, remote model, or production result.
