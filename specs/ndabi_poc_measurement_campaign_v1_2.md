# NDABI POC measurement campaign v1.2

**Status:** FROZEN before the first v1.2 result. **Date:** 2026-08-22.

The v1.1 campaign failed at `point-100k`. The empty-control p95 exceeded one percent of the fastest
arm. The runner also discarded the failed process JSON before storage.

This campaign changes only the control-heavy batch sizes and failed-result custody. It uses the
unchanged v1.1 binary and integrity-equalised arms.

## 1. Batch-size correction

Use 2,000 operations per batch for all point and temporal cases. Use 400 operations per batch for
`filter-512-64b`. Retain every other v1.1 case value.

Run 24 measured batches and two warm-up batches per arm. Run at least 1,000 empty control batches.
The non-zero p95 control must remain below one percent of the fastest arm median batch.

## 2. Failed-result custody

If a process returns valid result JSON with a failed hard gate, store it exclusively and continue
the campaign. The campaign summary must identify every failed case.

Stop only when a process crashes, times out, or returns invalid JSON. Record that interruption in a
separate failure manifest before another campaign.

## 3. Gates and decision

Retain every v1.1 exactness, authority, corruption, allocation, binary, source, and evidence gate.
Do not set a speed target.

If all cases pass, use the results only to choose the default control encoding. Freeze optimisation
targets in a later preregistration.
