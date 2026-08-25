# NDABI PostgreSQL Linux-container campaign v3.3

**Status:** ACCEPTED. **Date:** 2026-08-22.

## 1. Question

Does the hardened NDABI client retain exactness and relative performance inside Linux ARM64 containers?

This campaign tests a container bridge between the client and PostgreSQL.
It does not prove physical Linux, TLS, WAN behaviour, or production security.

## 2. Frozen environment

The builder uses Rust 1.92 on the pinned Bookworm image.
The runtime uses the pinned Debian Bookworm image.
PostgreSQL uses the pinned version 16 image from campaign v3.2.

One user-defined Docker network connects all containers.
One PostgreSQL container holds one prepared 100,000-row dataset.
Five fresh client containers execute the complete campaign.

## 3. Frozen workloads

The campaign uses batches of 8, 32, and 128 point reads.
Each arm uses five warm-up cycles and 63 measured cycles.
The four arms remain sequential prepared, native set, native pipeline, and NDABI set.

Every arm must return the same canonical bytes and receipt digest.
The borrowed decoder must allocate zero Rust heap bytes.
The adapter must enforce the authenticated result budget.

## 4. Hard gates

| Gate | Target |
|---|---|
| Process completion | Five valid results and five zero exit codes |
| Platform | Five Linux ARM64 client reports |
| Exactness | One result and receipt identity for every batch |
| Decoder allocation | Zero allocations and zero allocated bytes |
| Local process gates | Every process passes its complete hard gate |
| Batch-32 round-trip removal | At least 4.00 times |
| Batch-128 round-trip removal | At least 4.00 times |
| Native-set distance | No more than 1.10 times for batches 32 and 128 |
| Ratio repeatability | Coefficient of variation below 0.15 |
| Evidence custody | Image, binary, sources, runner, raw results, and summary have SHA-256 digests |

Any failed hard gate rejects the campaign.
The runner must not reinterpret a process failure as an aggregate success.

## 5. Promotion boundary

Acceptance promotes one Linux ARM64 container profile only.
It does not promote native physical Linux or any other database profile.

## 6. Result

Five Linux ARM64 client containers passed every process-local and aggregate gate.
Batch 32 measured 22.64 times sequential execution and 1.93% below native-set p95.
Batch 128 measured 51.35 times sequential execution and 0.46% above native-set p95.

The largest gated ratio coefficient was 4.90%.
Every process returned the same canonical result and receipt identities.
The borrowed decoder allocated zero Rust heap bytes.
