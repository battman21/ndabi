# NDABI POC preregistration v1.0

**Status:** FROZEN before the first v1.0 result. **Date:** 2026-08-22.

This campaign tests bounded scale and measurement validity. It does not test a public standard.
It does not change or replace the accepted v0.9 evidence.

## 1. Profiles

The first profile is a read-only query profile. The trusted runtime supplies authority, purpose,
snapshot, deadline, budget, nonce, and capability state. An agent supplies only an operation and
bounded arguments.

The mutation, application, durable-custody, remote, and model profiles remain separate campaigns.
No result from one profile proves another profile.

Every profile has explicit record, result, batch, operation, and memory bounds. A request cannot
increase its own authority or resource budget.

## 2. Causal arms

Run these arms against one query kernel and one canonical semantic result:

1. Stateless readable JSON with the complete trusted envelope.
2. Prepared compact JSON with an opaque capability handle.
3. Prepared canonical CBOR with the same compact semantics.
4. Prepared NDABI with the same compact semantics.
5. A direct prepared kernel ceiling without wire encoding.

Attribute state reuse through arm one versus arm two. Attribute generic binary encoding through arm
two versus arm three. Attribute specialised encoding through arm three versus arm four. Attribute
all wire work through arm four versus arm five.

## 3. Workloads

Use deterministic point, filtered, aggregate, and temporal queries. Use 512, 10,000, 100,000, and
1,000,000 records. Use result budgets of 64 bytes, 4 KiB, 64 KiB, and 1 MiB.

Do not run one complete Cartesian performance matrix. Run correctness across every supported
boundary. Run performance on twelve registered representative cases. Run stress on the smallest
and largest corners.

## 4. Measurement validation

Measure a complete operation batch with one wall-clock reading. Report elapsed batch time and
derived time per operation. Measure an empty control batch with the same loop structure.

The empty-control median must remain below one percent of the fastest measured arm. If this gate
fails, increase the operations per batch and repeat the measurement-validation campaign.

Use balanced arm rotation. Keep preparation rules equal for arms with equal semantics. Report the
median, p95, p99, throughput, allocations, encoded bytes, and retained Rust bytes.

Do not publish absolute latency from macOS. Linux publication requires CPU affinity, recorded CPU
topology, frequency policy, compiler, binary digest, source digest, and hardware counters.

## 5. Exactness gates

All arms must return one canonical semantic result and one canonical receipt. Each encoding must be
deterministic within its own format. Different formats do not need byte-identical representations.

Every changed protected frame must refuse before query execution. Every expired, revoked,
over-budget, wrong-purpose, wrong-principal, wrong-snapshot, and replayed operation must refuse.

No request may truncate a result silently. It must return a complete bounded result or an explicit
budget refusal.

## 6. Scale gates

All supported scale points must pass exactness and refusal gates. A valid maximum-scale query must
complete without an out-of-memory failure. Retained memory must remain within the declared profile
budget.

Do not set speed-improvement gates before the corrected measurement baseline exists. Freeze a
separate optimisation preregistration after the measurement-validation campaign passes.

## 7. Evidence custody

Bind each result to the source digest, release-binary digest, configuration, environment, and runner
digest. Store raw process results in an exclusive campaign directory. Never overwrite raw evidence.

## 8. Required disclosures

The local scale profile does not prove production White Tree integration, PostgreSQL behaviour,
shared-state concurrency, durable custody, remote transport, provider-token savings, or public
interoperability. Record these capabilities as owed until their separate campaigns pass.
