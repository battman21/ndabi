# NDABI POC phase profile v1.5

**Status:** FROZEN before the first v1.5 result. **Date:** 2026-08-22.

This diagnostic identifies the remaining costs inside the v1.4 point and large-result paths.
It does not register a production speed target.

## 1. Cases

Run `point-100k`, `filter-100k-64k`, and `filter-1m-1m`.
Run three independent Linux ARM64 containers for each case.

Use 60 measured batches and five warm-up batches for every phase.
Choose a fixed operations-per-batch value for each phase and case before the first result.

## 2. Phases

Measure stateless JSON complete, NDABI complete, and direct complete operations.
Measure NDABI request encoding and decoding separately.

Measure kernel execution, NDABI response encoding, and NDABI response verification separately.
Measure payload copying, CRC32, and BLAKE3 separately.

Measure protected-CBOR response encoding and verification.
Use the same canonical result and receipt for every response phase.

## 3. Calibration and exactness

Measure at least 1,000 back-to-back timer calls.
Require the timer p95 below 0.1% of every phase median batch.

Require stateless JSON, NDABI, and direct operations to return identical results and receipts.
Require zero hot allocations for the complete NDABI path.

## 4. Custody

Pin both Docker base images by digest.
Bind every result to the source, runner, binary, image, and preregistration digests.

Store every raw result exclusively.
Preserve any valid failed result.

## 5. Decision

Use the result to choose the v1.6 optimisation.
Do not use it as an accepted end-to-end performance campaign.

Prioritise any removable phase above 20% of the complete NDABI path.
Treat database execution as a separate engine optimisation when it dominates.
