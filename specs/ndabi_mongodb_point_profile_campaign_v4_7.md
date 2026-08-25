# NDABI MongoDB point-profile campaign v4.7

Status: frozen before the first formal campaign.

## 1. Purpose

Prove one real MongoDB adapter profile through the backend-neutral NDABI session.
Measure request translation without claiming general MongoDB support.

## 2. Dataset and operation

Use an ephemeral local MongoDB 8.0 container with 100,000 deterministic documents.
Store `_id`, bucket, owner, score, and a 64-byte binary payload.
Use the native `_id` index and one prepared `find-by-id` profile.
Return one canonical fixed-width binary row.

## 3. Arms

The native arm executes the typed MongoDB query directly.
The JSON arm parses a complete named authority and operation request, then uses the shared session.
The NDABI arm sends the 76-byte authenticated frame directly through the same session and backend.

## 4. Measurement and gates

Run five independent client processes after one dataset preparation.
Use 10,000 measured operations, 1,000 warm-up operations, and 20 balanced blocks per process.
Require exact result bytes, stable result identity, six session refusals, and zero process failures.
Require at least 50 percent request compression against complete JSON.
Require NDABI p95 to remain within 10 percent of native and JSON p95 in every process.

Reject the campaign after any failed gate.
Do not replace a failed result with a later v4.7 run.

## 5. Boundaries

This campaign proves one unauthenticated local MongoDB read profile.
It does not prove MongoDB writes, Atlas, TLS, replica sets, sharding, transactions, aggregation, or production credentials.
