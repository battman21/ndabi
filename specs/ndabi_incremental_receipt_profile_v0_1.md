# NDABI incremental receipt profile v0.1

Status: candidate profile.

## 1. Purpose

Remove a receipt-only server pass over complete result bytes.
Retain exact result authentication and fail-closed client verification.
Keep the existing v0.1 receipt unchanged.

## 2. Receipt construction

Compute `request_digest` as unkeyed BLAKE3 over the complete authenticated request frame.
Compute `result_digest` incrementally over every canonical result byte, in exact output order.
Compute the receipt with keyed BLAKE3 under the existing receipt key:

```text
"ndabi/wire/v2/execution-receipt"
|| context_digest
|| request_digest
|| LE64(nonce)
|| LE32(rows)
|| result_digest
```

This construction is identical to the existing v0.2 transport execution receipt.
Do not identify it as the v0.1 direct receipt.

## 3. Server rules

Update the result digest only after each bounded output write succeeds.
Hash the final bytes again when a backend patches an earlier output position.
Treat this fallback as correct but not one-pass.
Commit replay state before returning executable work.
Return no result after a deadline, budget, backend, or replay refusal.

## 4. Client rules

Verify the request digest, nonce, row count, result digest, and keyed receipt.
Use constant-time receipt comparison.
Treat decoded streaming values as staged and untrusted.
Commit staged state only after the final receipt verifies.
Refuse a v0.1 receipt on this profile.
Refuse this profile receipt through the v0.1 verifier.

## 5. Security gates

Refuse every changed authenticated frame.
Refuse every replay before database dispatch.
Refuse every changed result byte.
Refuse every changed receipt.
Accept the exact result and receipt.
Retain authority, schema, policy, plan, tenant, principal, purpose, deadline, row, and byte bindings.

## 6. Boundary

The server path is one-pass only when the backend appends immutable canonical bytes.
The current complete-result client still calculates one result digest.
The streaming client can calculate that digest while it stages decoded data.
This profile does not remove cryptographic verification across a trust boundary.
