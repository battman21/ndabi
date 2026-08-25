# NDABI equal-security White Tree campaign v4.5

Status: frozen before the first formal campaign.

## 1. Purpose

Repair the failed v4.4 comparison without changing its evidence.
Compare NDABI with a named JSON gateway that receives identical session enforcement and receipts.

## 2. Repair

The JSON arm must parse the named request and compile it into the same authenticated NDABI session operation.
Both arms must perform client encoding, frame authentication, replay admission, deadline checks, budget checks, White Tree execution, and receipt generation.
Only the initial agent-facing request representation and JSON translation cost may differ.

Use BLAKE3 for the v2 receipt and frame digest.
Bind the same authority, nonce, complete authenticated frame, and complete result bytes.
Keep the 128-bit keyed frame tag and constant-time tag comparison.

## 3. Measurement

Keep the v4.4 fixture, prepared operation, direct baseline, schedule, iterations, warm-up, and five-process count.
Measure wall latency, thread CPU, allocations, allocated bytes, request bytes, and response bytes.

## 4. Gates

Require exact response-byte equality across direct, JSON, and NDABI arms.
Require all six registered refusals.
Require at least 35 percent request compression against named JSON.
Require NDABI p95 not to exceed JSON p95 in any process.
Require the five-process median NDABI p95 to be at least 5 percent below the JSON median.
Require all focused tests and clippy checks.

Reject the campaign after any failed gate.
Do not replace a failed result with a later v4.5 run.

## 5. Boundaries

This campaign measures local request representation and translation through one real White Tree read profile.
It does not prove network transport, other databases, writes, model tokens, energy, or production custody.
