# NDABI registry incremental-cost campaign v0.1

**Status:** Frozen before the first release run.

## Purpose

Measure the exact incremental cost of sealed registry validation.
Do not measure database, network, discovery, persistence, or key-provider costs in this campaign.

## Equal-work control

Both arms use the same authenticated frames, backend identity, operation, result, receipt, replay store, limits, and fixed clock.
The direct arm calls the fixed backend after normal protocol admission.
The registered arm adds one sealed registry lookup and its bound checks before calling that backend.
The backend repeats its fixed-operation check in both arms.

## Method

Build the `ndabi_registry_v01` binary with the release profile.
Run one warm-up for both arms.
Run 31 balanced rounds for each arm.
Execute 5,000 operations in each round.
Alternate arm order for each round.

Measure wall time, thread CPU, Rust allocation count, and Rust allocated bytes.
Calculate each value per completed operation.
Report the median and p95 round values for time and CPU.

## Frozen gate

The registered arm MUST remain within 1.10 times the direct arm for all four time and CPU values.
Its median allocation count MUST NOT exceed the direct arm.
Its median allocated bytes MUST NOT exceed the direct arm.
Every operation MUST return the exact result and authenticated receipt.

Fail the process when any gate fails.

## Boundary

This campaign measures one local fixed backend on the current host.
It does not prove PostgreSQL, Supabase, MongoDB, White Tree, remote, or production performance.
Run separate frozen campaigns after each registered adapter uses the control plane.
