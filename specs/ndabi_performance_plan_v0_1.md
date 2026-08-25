# NDABI performance plan and rubric v0.1

**Status:** ADOPTED POC plan. **Date:** 2026-08-22.

This plan separates protocol costs from database, transport, model, and operating-system costs.
No stage can borrow evidence from another stage.

## 1. Execution plan

| Stage | Test | Fixed evidence | Promotion gate |
|---|---|---|---|
| P0 | Correct the timer control in a new v1.4 binary | Separate timer, loop, and operation costs; pinned base-image digests | Completed; all 36 timer gates passed |
| P1 | Run the frozen v1.4 Docker campaign | 36 raw processes, image digest, binary digest, CPU usage, RSS | Failed; eight secondary ratio-repeatability gates failed |
| P2 | Profile and fuse the local path | v1.5 phases; v1.6 to v1.9 fused campaigns | Completed; v1.9 passed all frozen local fixture gates |
| P3 | Stress the Docker profile | 30 processes for each selected case across three sessions | Completed; v2.1 passed all protocol gates |
| P4 | Run native Linux ARM64 and x86-64 | Pinned physical core, governor, thermal state, NUMA, `perf`, RSS | Partial; Linux ARM64 containers passed v3.3, but physical Linux remains untested |
| P5 | Test real White Tree and PostgreSQL adapters | Equal queries, policies, receipts, datasets, and result bytes | Completed for registered read profiles; v4.5 unified their session boundary |
| P6 | Test MongoDB and Supabase profiles | Native driver, prepared state, identity binding, and NDABI adapter | Partial; MongoDB 6.0.26 and the canonical local Supabase data binding passed; MongoDB 8.x did not start |
| P7 | Test local and remote transports | In-process, Unix socket, loopback TCP, LAN TLS, and controlled WAN | Partial; persistent TLS 1.3 and controlled delay passed, but LAN and geographic WAN remain untested |
| P8 | Test concurrency, recovery, writes, and provider tokens | 1 to 128 clients, failures, exact prompts, and usage records | Partial; concurrency, durable read replay, and one write profile passed, but provider tokens remain open |
| P9 | Freeze the RFC candidate | Two independent implementations and one cross-version test matrix | Publish only interoperable, measured, and governed protocol behaviour |

P0 must replace the current per-operation arithmetic control.
Measure back-to-back timer calls for timer cost. Measure loop cost as a separate diagnostic.
Pin the builder and runtime images by digest before the v1.4 build.

The v1.3 campaign remains failed evidence.
Do not alter or rerun it.

## 2. Performance rubric

| Area | Weight | Measurement | Pass target |
|---|---:|---|---|
| Correctness and governance | 30 | Results, receipts, authority refusals, corruption refusals, deterministic replay | 100%; any failure rejects the campaign |
| Measurement integrity | 20 | Frozen contract, raw custody, timer calibration, balanced order, immutable digests | 100%; any missing evidence rejects the campaign |
| Latency and throughput | 20 | p50, p95, p99, operations per second, causal-arm ratios | Meet every registered workload target without a hidden regression |
| Compute and allocation | 10 | CPU time, cycles, instructions, cache misses, branch misses, allocations | Zero NDABI hot allocations and at least 20% fewer instructions at the target boundary |
| Memory | 10 | Retained bytes, peak live bytes, maximum RSS, concurrent working set | At least 30% less memory than tuned JSON under the registered load |
| Wire and model input | 5 | Request bytes, response bytes, provider-counted input tokens | At least 40% fewer request bytes; token claims require provider evidence |
| Portability and repeatability | 5 | Architectures, sessions, implementations, coefficient of variation | Both Linux architectures pass; relative CV stays below 10% |

A score cannot override a hard failure.
Correctness, governance, calibration, evidence custody, and losslessness are hard gates.

## 3. Registered optimisation targets

| Boundary | Primary target | Regression guard |
|---|---|---|
| Stateless JSON to prepared state | At least 2.5 times faster on point-query p95 | No result or policy change |
| Protected CBOR to NDABI | At least 1.25 times faster on small-operation p95 | No workload becomes more than 5% slower |
| Real database end-to-end | At least 20% lower p95 or 20% lower CPU at equal throughput | Native baseline keeps identical indexes and prepared state |
| Concurrent memory | At least 30% lower maximum RSS than tuned JSON | No unbounded growth through 128 clients |
| Request wire size | At least 40% fewer request bytes than tuned JSON | Response comparison uses the same result representation |
| Model input tokens | At least 20% fewer provider-counted input tokens | Prompt, memory, policy, and result meaning remain byte-exact after rehydration |

Later frozen campaigns add measured PostgreSQL, White Tree, TLS, MongoDB, Supabase-binding, batch, and compare-and-swap capabilities.
The v5.8 campaign adds canonical Supabase data-plane security evidence without a performance claim.
Energy, provider tokens, geographic WAN, and general-language targets remain future promotion targets.
Freeze each campaign before its first result.

## 4. Test matrix

| Dimension | Required values |
|---|---|
| Query shape | Point, filter, aggregate, temporal, mutation, transaction |
| Dataset | 512, 10,000, 100,000, 1,000,000, and 10,000,000 records |
| Result size | 64 B, 4 KiB, 64 KiB, 1 MiB, and streaming results |
| Transport | Direct, Unix socket, loopback TCP, LAN TLS, controlled WAN |
| Concurrency | 1, 8, 32, and 128 clients |
| Engine | Fixture, White Tree, PostgreSQL, MongoDB, Supabase PostgreSQL |
| Architecture | Native Linux ARM64 and x86-64 |
| Failure | Invalid capability, replay, corruption, timeout, restart, partial write |

Run the smallest matrix first.
Expand only after the smaller boundary passes every hard gate.
