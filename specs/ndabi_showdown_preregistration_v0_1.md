# NDABI showdown preregistration v0.1

**Status:** FROZEN before the first benchmark result. **Date:** 2026-08-21.

This experiment tests two narrow compression hypotheses. It does not define the NDABI RFC.
It does not prove provider-token savings, remote latency, PostgreSQL performance, or White Tree performance.

## 1. Questions

1. Can a typed binary database operation reduce interface bytes and host work without changing the result?
2. Can a typed application operation reduce state transport and rendering work without changing the human view?
3. Which gains come from reuse and deltas, and which gains come from binary representation?

## 2. Fixed arms

Each track has three arms. All arms execute the same semantic operation.

| Arm | Database surface | Application surface |
|---|---|---|
| Human baseline | SQL inside a named JSON envelope; named JSON rows | Named JSON action; complete JSON state; complete render |
| Tuned baseline | Prepared handle inside compact JSON; JSON row arrays | Compact JSON action; JSON patch; changed-row render |
| NDABI prototype | Versioned typed binary handle; binary row frame | Versioned typed binary action; binary patch |

The tuned baseline prevents a false conclusion that binary syntax caused gains from plan reuse or patches.

## 3. Fixed database operation

Use one in-memory SQLite database. Generate records deterministically from their integer identifier.

Select `id`, `owner`, `score`, `updated_at`, and `title` for one tenant and owner.
Require active records and a minimum score. Order by descending score and ascending identifier.
Apply the same row limit in every arm.

All arms carry the same principal, purpose, tenant, snapshot, deadline, nonce, and row budget.
The runtime verifies this trusted envelope before database execution.

## 4. Fixed application operation

Generate a deterministic task state. Apply eight absolute task changes against one expected revision.

The human baseline returns and renders the complete state.
The tuned and NDABI arms return patches and render only changed rows.
Applying either patch to the prior state must produce the exact complete human view.

## 5. Measurements

Measure the following quantities for each arm:

- request and response wire bytes;
- median and p95 loopback operation latency;
- operations per second;
- Rust allocation count and requested allocation bytes;
- peak additional live Rust allocation bytes;
- rendered application bytes;
- semantic result digest and complete human-view digest;
- malformed or unauthorised request refusals;
- database executions attempted after a refused request.

Exclude database creation, fixture generation, process startup, compilation, network, TLS, and model inference.
Report the machine, operating system, architecture, compiler, fixture size, iterations, and warm-up count.

## 6. Hard gates

A track is invalid unless all gates pass:

1. All three arms produce the same canonical semantic result.
2. All three application arms produce the same complete human view.
3. Every fixed negative case refuses.
4. A refused database request causes zero database executions.
5. Repeated encoding produces identical bytes.
6. The trusted envelope has identical semantic fields in every arm.

No speed or compression result can compensate for a failed hard gate.

## 7. Scored targets

Score NDABI against the tuned baseline. Award the complete weight only when the target passes.

| Measure | Target | Weight |
|---|---:|---:|
| Request bytes | at least 30% fewer | 15 |
| Response bytes | at least 30% fewer | 15 |
| p95 latency | at least 10% lower | 25 |
| Requested allocation bytes | at least 25% fewer | 20 |
| Allocation count | at least 25% fewer | 10 |
| Peak additional live bytes | at least 20% fewer | 10 |
| Deterministic encoding | exact repeat | 5 |

Interpret 85-100 as strong support, 65-84 as promising, 40-64 as mixed, and below 40 as rejected.
Report the human-to-tuned change separately. That change measures reuse, deltas, and compact JSON.

## 8. Fixed negative cases

The database track tests a wrong principal, an expired deadline, an excessive limit, and malformed bytes.
The application track tests a wrong principal, a stale revision, an excessive change count, and malformed bytes.

## 9. Required disclosures

Display these limitations beside every result:

- This is a local microbenchmark, not a production benchmark.
- SQLite is not PostgreSQL, MongoDB, Supabase, or White Tree.
- The prototype binary format is not the NDABI RFC.
- The test does not measure model tokenisation or provider inference.
- The allocation counter covers Rust allocations, not SQLite internal allocations.
- The application track tests state transport and render work, not a complete operating-system stack.

## 10. Reproduction rule

Store the complete machine-readable result. Never copy a selected number into a claim without its result file.
Treat a later format, fixture, threshold, or operation change as a new benchmark version.

## 11. Post-measurement audit disclosure

This disclosure was added after the first run. The runner uses one fixed arm order and reports no
confidence intervals. Treat the latency result as exploratory. The frozen operations, gates, targets
and weights did not change.
