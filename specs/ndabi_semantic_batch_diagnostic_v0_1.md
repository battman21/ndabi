# NDABI semantic batch diagnostic v0.1

**Status:** Diagnostic evidence only. **Date:** 2026-08-27.

## 1. Question

Can one registered NDABI graph remove 256 PostgreSQL round trips without changing results or authority checks?

This diagnostic compares three arms:

| Arm | Queries per workflow | Work |
|---|---:|---|
| Repeated native | 256 | One prepared aggregate for each operand |
| Fused native | 1 | One prepared set query for all operands |
| NDABI graph | 1 | The same set query plus frame authentication, replay, receipt, and client verification |

## 2. Fixed diagnostic inputs

PostgreSQL used image digest `sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20`.
Toxiproxy used the Linux ARM64 image digest `sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87`.
The proxy added 1 ms in each direction without jitter.
Each process used ten warm-ups and 100 balanced measured iterations.
Each workflow used 256 typed operands and returned 4,102 exact bytes.
The NDABI request contained 4,260 bytes.

The source started from commit `730634f214fb3649b6621b331435a65b23c94f36`.
The implementation was uncommitted during measurement, so no source or binary identity is accepted.

## 3. Results

| Run | Repeated p95 ns | Fused p95 ns | NDABI p95 ns | Repeated versus NDABI | NDABI versus fused |
|---:|---:|---:|---:|---:|---:|
| 1 | 1,266,203,083 | 9,293,959 | 9,867,666 | 128.32 times | 6.17% slower |
| 2 | 1,038,277,167 | 8,728,000 | 8,874,500 | 117.00 times | 1.68% slower |
| 3 | 1,343,265,042 | 9,079,208 | 10,640,833 | 126.24 times | 17.20% slower |
| 4 | 911,238,083 | 5,737,417 | 5,878,875 | 155.00 times | 2.47% slower |
| 5 | 1,189,355,583 | 8,513,250 | 8,938,416 | 133.06 times | 4.99% slower |

Every iteration produced equal result bytes.
Every NDABI iteration verified its keyed receipt.
The median workflow p95 speedup was 128.32 times.
The median NDABI p95 overhead against fused native was 4.99%.

One direct local run measured 37.54 times p95 speedup against repetition.
That run measured 2.65% NDABI p95 overhead against fused native.

## 4. Interpretation

Binary framing did not create the large gain.
Registered semantic fusion removed 255 database round trips per workflow.
NDABI made the fused operation compact, bounded, authenticated, replay-protected, and reusable by an untrusted agent.

An expert can write the equivalent fused SQL directly.
NDABI does not make that database plan faster.
It provides a governed agent interface that stays close to the fused native floor.

## 5. Evidence limits

The source, binary, and host state were not frozen before measurement.
The test used local Docker with controlled delay, not a geographic network.
CPU, allocations, memory, energy, TLS, Supabase RLS, concurrency, and packet loss were not measured.
The 17.20% tail regression rejects a near-floor p95 acceptance claim.

## 6. Repaired-path smoke

The reusable path now retains its request and result allocations.
The PostgreSQL batch encoder now performs one result bounds check and one exact fill.
The diagnostic also reports client-thread CPU and optional allocation counts.

One contaminated-host run used 200 measured iterations at the controlled 2 ms round trip.
It measured 158.81 times p95 speedup against repetition.
It measured 0.71% p95 overhead and 0.24% mean overhead against fused native.
NDABI client-thread CPU was 98.94% lower than repetition and 37.08% higher than fused native.

One separate local allocation diagnostic measured these values for a 256-operation workflow:

| Arm | Allocations | Allocated bytes |
|---|---:|---:|
| Repeated native | 2,571 | 151,878 |
| Fused native | 286 | 100,830 |
| NDABI graph | 285 | 96,728 |

NDABI made 88.92% fewer allocations than repetition.
It allocated 36.31% fewer bytes than repetition and 4.07% fewer bytes than fused native.
The 4,260-byte request was 65.07% smaller than the equivalent 12,197-byte concise authenticated JSON request.

Other builds and virtual machines were active during these measurements.
These smoke results demonstrate the repaired path, but they do not qualify performance.
