# NDABI registry incremental-cost campaign v0.2

**Status:** Frozen after the v0.1 repeatability failure and before the first v0.2 run.

## Repair

Retain all v0.1 work, measurements, arm ordering, and 1.10 cost gates.
Run the same binary with `--qualified`.

The v0.1 campaign failed one of five processes during scheduler contamination.
That process recorded wall p95 above twice the normal value for both arms.
Its CPU ratios still passed.

## Qualification

Calculate wall time divided by thread CPU for each arm in each paired round.
Retain a pair only when both ratios do not exceed 1.10.
Require at least 25 of 31 paired rounds.
Report every discarded-round count.

Apply every v0.1 wall, CPU, allocation-count, and allocated-byte gate to the retained rounds.
Fail the process when the qualified-round minimum or any cost gate fails.

## Boundary

Qualification removes measured scheduler waiting only.
It does not remove slow CPU execution.
The campaign remains one local fixed-backend measurement.
