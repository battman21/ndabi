# NDABI POC scale campaign v1.0

**Status:** FROZEN before the first scale-campaign result. **Date:** 2026-08-22.

This campaign applies the measurement-validity and exactness rules from the v1.0 preregistration.
It does not set a speed-improvement gate.

## Registered cases

| Case | Workload | Records | Result budget | Operations per batch |
|---|---|---:|---:|---:|
| `point-512` | point | 512 | 64 bytes | 500 |
| `point-10k` | point | 10,000 | 64 bytes | 500 |
| `point-100k` | point | 100,000 | 64 bytes | 500 |
| `point-1m` | point | 1,000,000 | 64 bytes | 500 |
| `temporal-1m` | temporal | 1,000,000 | 64 bytes | 500 |
| `filter-512-64b` | filter | 512 | 64 bytes | 100 |
| `filter-10k-4k` | filter | 10,000 | 4 KiB | 20 |
| `filter-100k-64k` | filter | 100,000 | 64 KiB | 2 |
| `filter-1m-1m` | filter | 1,000,000 | 1 MiB | 1 |
| `aggregate-10k` | aggregate | 10,000 | 64 bytes | 20 |
| `aggregate-100k` | aggregate | 100,000 | 64 bytes | 2 |
| `aggregate-1m` | aggregate | 1,000,000 | 64 bytes | 1 |

Run 20 measured batches and two warm-up batches for each arm in each case. Rotate all five arm
orders through a balanced schedule.

## Campaign gates

Every case must pass semantic equality, receipt equality, deterministic encoding, authority
refusals, protected-frame corruption, measurement calibration, and NDABI hot-allocation gates.

All cases must bind to one source fingerprint and one release-binary digest. The release binary must
not change during the campaign.

Report state-reuse, generic-binary, specialised-encoding, and direct-ceiling ratios separately. A
ratio is evidence, not an acceptance target in this campaign.

Store every raw case result exclusively. Store the campaign summary with the runner and
preregistration SHA-256 digests.

## Required disclosures

These cases use a deterministic fixture query engine. The campaign does not prove White Tree,
PostgreSQL, shared-state concurrency, durability, remote transport, or model-token savings.
