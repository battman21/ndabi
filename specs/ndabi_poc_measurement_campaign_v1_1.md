# NDABI POC measurement campaign v1.1

**Status:** FROZEN before the first v1.1 result. **Date:** 2026-08-22.

The v1.0 scale campaign passed its registered gates. The audit found two measurement defects.
Canonical CBOR did not perform the NDABI frame-integrity work. Five slow cases also recorded a
zero-duration empty control.

This campaign corrects only those defects. It does not optimise the NDABI frame or set a speed
acceptance target.

## 1. Equalised arms

Run stateless JSON, prepared JSON, canonical CBOR, protected canonical CBOR, protected NDABI, and
the direct kernel. Apply the same CRC32 frame-integrity algorithm to protected CBOR and NDABI.

Attribute generic encoding through prepared JSON versus canonical CBOR. Attribute integrity through
canonical CBOR versus protected CBOR. Attribute specialised encoding through protected CBOR versus
NDABI.

## 2. Calibration correction

Run at least 1,000 empty control batches. Use the p95 empty-control duration. The value must be
non-zero and remain below one percent of the fastest arm median batch.

## 3. Registered cases

Use the same twelve workloads, records, result budgets, and operations-per-batch values as the v1.0
scale campaign. Run 24 measured batches and two warm-up batches per arm.

## 4. Gates

Every v1.0 exactness, refusal, corruption, allocation, source-binding, and evidence-custody gate
remains active. Both protected encodings must refuse every single-bit frame change.

The campaign passes only when all twelve cases pass and all results bind to one binary and source
fingerprint. Do not accept a speed claim from this campaign.

## 5. Decision rule

If protected CBOR matches or beats NDABI, use canonical CBOR as the default NDABI control encoding.
Retain a specialised encoding only when a later registered workload proves a material advantage.
