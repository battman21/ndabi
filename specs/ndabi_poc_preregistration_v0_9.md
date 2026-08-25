# NDABI POC preregistration v0.9

**Status:** FROZEN before the first v0.9 benchmark result. **Date:** 2026-08-21.

The final source-bound v0.8 campaign failed. It passed 25 of 30 process gates. The macOS QoS
request did not prevent performance-core and efficiency-core timing groups.

This experiment tests paired comparison under scheduler movement. It does not claim stable absolute
nanosecond latency on macOS.

## 1. Fixed change

Measure ten operations per arm before rotating to the next arm. Rotate all four arm orders through
the balanced schedule. Repeat until each arm has 10,000 measured operations.

Use the operating-system default scheduler. Do not request a QoS class. Keep preparation outside the
timed operation exactly as v0.7 defined.

Do not change the kernel, frames, workload, warm-up count, exactness checks, or local performance
targets.

## 2. Evidence

Run 30 independent processes. Bind the campaign to one source fingerprint, one release-binary
SHA-256 digest, and the campaign-runner digests.

Store every raw process result in one immutable campaign directory. Record every result SHA-256
digest.

Report absolute p95, p99, p99.9, throughput, and variation. Treat absolute macOS variation as a
disclosure, not a campaign gate.

## 3. Hard gates

All 30 process gates must pass. The conservative prepared and direct speedup coefficients of
variation must not exceed 10%.

The conservative same-executable p95 speedup must remain at least three times for prepared wire and
four times for the direct kernel.

Every exactness, refusal, byte-size, allocation, receipt-time, and control-memory gate remains active.

## 4. Required disclosures

Paired micro-blocks reduce comparison skew. They do not provide CPU affinity or stable absolute
latency.

Linux CPU affinity remains required before publishing absolute latency, throughput, energy, or
hardware-counter claims.

The result remains a local in-memory campaign. It does not prove durable production custody,
shared-state concurrency, remote transport, database adapters, model tokens, or a public RFC.
