# NDABI POC preregistration v0.5

**Status:** FROZEN before the first v0.5 benchmark result. **Date:** 2026-08-21.

This experiment tests the complete-path compression claim more strictly. It adds statistical
intervals, phase CPU attribution, memory decomposition, and one real White Tree read slice.

## 1. Preserved comparisons

Keep every v0.4 operation, arm, authority check, exactness gate, receipt gate, and balanced schedule.
Do not reinterpret earlier results. Record v0.5 results under a new schema.

## 2. Statistical evidence

Report the measured sample count for every arm. Report deterministic 95% bootstrap intervals for
the median and p95 wall latency. Use a fixed seed and resample complete measured observations.

Report a result as stable only when repeated runs preserve its direction. Do not claim production
performance from a local scheduler, bootstrap interval, or one operating system.

## 3. Phase attribution

Measure wall and thread CPU for admission, execution, and result processing. Keep each phase's
operation equal across comparable arms. Phase measurements remain diagnostic and include timer
overhead.

Separate producer receipt work from consumer verification. Both remain inside the complete wire
path. Never remove consumer verification to manufacture a speed result.

## 4. Memory attribution

Report retained Rust capacity separately for the request, response, rendered view, receipt tree,
and application state. Report process peak RSS as a process-level observation only.

Process peak RSS is not an operation-level delta. It includes the runtime and linked libraries.

## 5. Receipt plan optimisation

Replace repeated staged-node searches with bounded direct lookup. Preserve SHA-256, domain
separation, staged mutation, exact roots, and zero measured allocations.

The optimised plan must match a complete rebuild. A stale plan, wrong root, or changed base must
still refuse before state mutation.

## 6. White Tree slice

Add one read-only White Tree fixture track over real `.olt` storage and the governed context fold.
Compare readable JSON, compact semantic JSON, NDABI wire, and NDABI local bindings.

All arms must use the same store, profile, clocks, hop budget, governed engine operation, result
projection, and receipt data. The local fixture store is not a signed production database.

Report opened partitions, pruned partitions, physical bytes read, result equality, receipt equality,
request bytes, response bytes, latency, CPU, allocations, and retained Rust capacity.

## 7. Targets

Database wire p95 and thread CPU target at least 20% below tuned JSON. Application wire p95 and
thread CPU target at least 20% below tuned JSON with equal complete work.

White Tree wire request bytes target at least 50% below compact JSON. White Tree wire latency must
not regress. White Tree local p95 targets at least 30% below compact JSON.

The application retained-capacity target remains unscored until the memory decomposition identifies
an avoidable duplicated owner. Do not count shared immutable state twice.

## 8. Required disclosures

This remains a local POC. It does not prove Linux isolation, energy, hardware counters, PostgreSQL,
MongoDB, Supabase, remote transport, production custody, or complete model-call token savings.

The White Tree track proves engine integration through fixture storage. It does not prove a signed
generation, Dúnedain, a remote server, or a production deployment.
