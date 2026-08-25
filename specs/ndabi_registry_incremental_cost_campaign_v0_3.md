# NDABI registry incremental-cost campaign v0.3

**Status:** Frozen after the v0.2 repeatability failure and before the first v0.3 run.

## Repair

Retain every v0.2 arm, measurement, qualification rule, and gate.
Run the same binary with `--qualified-v03`.

Use a direct equality check when the sealed registry contains exactly one plan.
Use the sorted binary search for every multi-plan registry.
Do not remove any identity, capability, shape, or limit check.

## Rationale

PostgreSQL, Supabase, MongoDB, and White Tree currently register one plan per candidate profile.
The direct lookup removes unnecessary generic search work from their common path.

## Boundary

The campaign remains one local fixed-backend measurement.
Its results do not prove database or remote performance.
