# NDABI POC preregistration v0.3

**Status:** FROZEN before the first v0.3 benchmark result. **Date:** 2026-08-21.

This experiment replaces the four large v0.2 arm batches with repeated balanced microcycles. It
keeps the v0.2 operations, formats, hard gates and scored targets unchanged. It preserves all v0.1
and v0.2 results.

## 1. Fixed correction

Repeat the four-order Latin schedule ten times. This produces 40 measured blocks for each arm.
Divide every arm's configured samples across its ten blocks. Combine all raw arm samples before the
median and p95 calculations.

Use this schedule in each cycle:

| Round | Order |
|---:|---|
| 1 | human, tuned JSON, NDABI wire, NDABI local |
| 2 | tuned JSON, NDABI wire, NDABI local, human |
| 3 | NDABI wire, NDABI local, human, tuned JSON |
| 4 | NDABI local, human, tuned JSON, NDABI wire |

Require the measured iteration count to be divisible by 40. Divide the configured warm-up count
across the 40 blocks. Run at least four independent default processes for the retained result.

## 2. Receipt rule

Verify the complete semantic digest and complete human-view digest before a response changes client
state. The local binding must produce and verify the same receipt values without a wire boundary.

## 3. Unchanged contract

Use all v0.2 arms, authority fields, semantic operations, negative cases, measurements, disclosures,
hard gates and score weights. Keep zero local transport bytes outside the compression score.

This remains a local POC benchmark. It does not prove PostgreSQL, MongoDB, Supabase, White Tree,
network, provider, model-token or production performance.
