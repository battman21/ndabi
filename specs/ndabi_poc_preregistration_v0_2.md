# NDABI POC preregistration v0.2

**Status:** FROZEN before the first v0.2 benchmark result. **Date:** 2026-08-21.

This experiment tests NDABI as an execution ABI with local and wire bindings. It preserves the
frozen v0.1 result. It does not define the NDABI RFC or prove production performance.

## 1. Questions

1. Can NDABI wire beat tuned JSON after equal semantic and integrity work?
2. Can NDABI local remove serialisation while preserving the same governed operation?
3. Which time belongs to admission, execution and result processing?
4. Do the gains survive balanced arm ordering and repeated rounds?

## 2. Fixed arms

All arms execute one canonical semantic operation.

| Arm | Database binding | Application binding |
|---|---|---|
| Human reference | SQL in named JSON; named JSON rows | Named JSON command; complete state and render |
| Tuned JSON wire | Prepared handle; compact JSON rows | Compact JSON command and patch |
| NDABI wire | Fixed typed frame; binary row frame | Fixed typed command and patch frames |
| NDABI local | Native typed command; direct result sink | Native typed command; direct patch application |

The local arm uses no request or response wire bytes. Report its transport bytes as not applicable.
Do not score zero local transport bytes as compression.

## 3. Semantic and authority contract

Use the v0.1 database query, fixture and application changes without modification.

All arms carry the same principal, purpose, tenant, snapshot, deadline, nonce and item budget.
Validate the authority before database execution or application state change.

Bind the database handle to the fixed query. The local arm receives the typed handle and arguments
without serialisation. The wire arms decode the same values from their frames.

## 4. Physical work

The tuned and NDABI wire arms include request decoding, authority validation, execution, response
encoding, response decoding, result consumption and semantic receipt verification.

The NDABI local arm includes native command validation, execution, direct result consumption and
semantic receipt production. It excludes wire encoding, checksums and wire decoding by design.

Use caller-owned reusable result buffers. Stream semantic digests over fields. Do not create a
temporary canonical byte vector only for hashing.

Use an optimised checksum implementation for NDABI wire. Keep corruption refusal. Do not remove an
integrity check to obtain a speed result.

## 5. Measurement schedule

Use four balanced rounds. Each arm appears once in each ordinal position.

| Round | Order |
|---:|---|
| 1 | human, tuned, NDABI wire, NDABI local |
| 2 | tuned, NDABI wire, NDABI local, human |
| 3 | NDABI wire, NDABI local, human, tuned |
| 4 | NDABI local, human, tuned, NDABI wire |

Divide the configured samples equally across the four rounds. Combine all raw samples before
calculating median and p95. Report the complete schedule.

Run a separate diagnostic pass for admission, execution and result processing. Diagnostic phase
timings do not contribute to the score.

## 6. Measurements

Measure these quantities for each arm:

- request and response wire bytes where applicable;
- median and p95 complete operation latency;
- operations per second;
- Rust allocation count and requested allocation bytes;
- peak additional live Rust allocation bytes;
- rendered application bytes;
- semantic result and complete human-view digests;
- deterministic wire encoding;
- admission, execution and result-processing diagnostic medians;
- all fixed negative cases and refused database executions.

Exclude fixture generation, database creation, compilation, process startup, network, TLS and model
inference. Report the machine, compiler, SQLite version, fixture size, samples and warm-up count.

## 7. Hard gates

A track is invalid unless all gates pass:

1. All four arms produce the same canonical semantic result.
2. All application arms produce the same complete human view.
3. Every fixed negative case refuses without state change.
4. A refused database operation executes no query.
5. Repeated wire encoding produces identical bytes.
6. Every arm carries one equivalent trusted envelope.
7. Every response receipt verifies the exact result it describes.

No performance result can compensate for a failed hard gate.

## 8. Scored targets

Score the two NDABI bindings against tuned JSON. Award the complete weight only when a target passes.

| Measure | Target | Weight |
|---|---:|---:|
| NDABI wire request bytes | at least 50% fewer | 10 |
| NDABI wire response bytes | at least 30% fewer | 10 |
| NDABI wire p95 | at least 20% lower | 20 |
| NDABI wire allocation bytes | at least 40% fewer | 15 |
| NDABI wire allocation count | at least 50% fewer | 10 |
| NDABI local p95 | at least 50% lower | 20 |
| NDABI local allocation bytes | at least 80% fewer | 10 |
| NDABI wire deterministic encoding | exact repeat | 5 |

Interpret 85-100 as strong support, 65-84 as promising, 40-64 as mixed and below 40 as rejected.
Report human-to-tuned, tuned-to-wire and tuned-to-local attribution separately.

## 9. Fixed negative cases

Reuse the v0.1 negative cases. Apply each semantic case to every applicable binding.
The local binding must refuse the same wrong authority, stale revision and budget excess cases.
Malformed bytes apply only to wire bindings.

## 10. Required disclosures

- This is a local POC benchmark, not a production benchmark.
- SQLite is not PostgreSQL, MongoDB, Supabase or White Tree.
- NDABI local measures removed serialisation, not network transport.
- NDABI wire excludes network, TLS and remote-provider latency.
- Diagnostic phase timings include timer overhead and do not sum exactly to complete latency.
- The allocation counter covers Rust allocations, not SQLite internal allocations.
- The prototype format is not the NDABI RFC.
- The test does not measure model tokenisation or inference.

## 11. Reproduction rule

Store the complete machine-readable result. Treat a changed operation, target, schedule, format or
hard gate as a new benchmark version. Never replace or reinterpret the frozen v0.1 result.
