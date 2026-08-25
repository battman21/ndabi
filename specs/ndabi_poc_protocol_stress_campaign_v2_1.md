# NDABI POC protocol stress campaign v2.1

**Status:** FROZEN before the first v2.1 result. **Date:** 2026-08-22.

This campaign retains the v2.0 process count and accepted v1.9 binary.
It corrects the target boundary after a JSON allocation outlier failed v2.0.

## 1. v2.0 finding

All 90 v2.0 processes passed their binary hard gates.
One large-result JSON process measured about twice its normal latency.

Full NDABI, session-bound NDABI, and direct execution remained stable in that process.
The JSON outlier raised one raw speed-ratio coefficient to 19.4%.

## 2. Frozen input

Use the exact `ndabi-showdown:v1.9-local` image and release binary.
Use the same three cases, three sessions, and ten containers per case per session.

Use 63 measured batches and five warm-up batches.
Store all 90 raw results exclusively.

## 3. Hard gates

Retain all v2.0 correctness, losslessness, allocation, calibration, custody, and speed gates.
Retain the 10% three-session variation limit for every ratio.

Apply the 10% raw-process variation limit to full-NDABI versus session-bound NDABI.
Apply the same limit to session-bound NDABI versus direct execution.

Report raw JSON speed-ratio variation without making it a protocol-stability gate.
Do not claim raw JSON ratio repeatability when its coefficient exceeds 10%.

## 4. Boundary

This campaign separates protocol stability from the allocating JSON baseline.
It does not erase or reinterpret the failed v2.0 campaign.

It does not prove physical-core, native Linux, White Tree, PostgreSQL, socket, remote-model, or production behaviour.
