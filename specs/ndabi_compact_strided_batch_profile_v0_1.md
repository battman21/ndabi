# NDABI compact strided-batch profile v0.1

Status: implemented candidate.

## 1. Purpose

Carry one finite arithmetic sequence of operands through an admitted NDABI session.
Avoid repeating identical tuple fields and the complete authority context in every request.

The trusted plan defines the meaning of each operand.
The instruction cannot contain SQL, collection names, field names, connection details, or policy text.

## 2. Preconditions

Establish the client and server authority before accepting this profile.
Bind the authority to the engine, profile, schema, policy, plan, tenant, principal, purpose, capability, generation, and session.

Use one exclusive replay sequence for each admitted session.
Refuse a backend identity that differs from the authority.

## 3. Wire layout

Encode every integer in little-endian order.
Use a fixed 112-byte frame.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | `NDBI` magic |
| 4 | 1 | major version |
| 5 | 1 | minor version |
| 6 | 1 | compact strided-batch kind |
| 7 | 1 | read access class |
| 8 | 2 | zero flags |
| 10 | 2 | operation code |
| 12 | 4 | frame bytes |
| 16 | 8 | session |
| 24 | 8 | generation |
| 32 | 8 | nonce |
| 40 | 8 | deadline, Unix microseconds |
| 48 | 4 | result-byte budget |
| 52 | 4 | row budget |
| 56 | 4 | plan handle |
| 60 | 4 | result shape |
| 64 | 8 | first operand |
| 72 | 4 | positive stride |
| 76 | 2 | item count |
| 78 | 2 | rows per item |
| 80 | 32 | keyed authentication tag |

Authenticate bytes 0 through 79 under the session frame key and the profile domain.
Bind the complete authority context through the derived session key.

## 4. Canonical reconstruction

Require a positive stride, at least two items, and at least one row per item.
Require the item count to remain within the negotiated batch limit.
Require `row_budget == item_count * rows_per_item`.
Refuse arithmetic overflow before backend dispatch.

Reconstruct item `i` as:

```text
first  = first_operand + i * stride
second = 0
third  = rows_per_item
```

The registered plan can refuse this operand shape.

## 5. Execution and receipt

Authenticate the complete frame before interpreting its operands.
Check authority, deadline, budgets, backend identity, and replay before dispatch.
Execute one fused backend operation.
Authenticate the exact result bytes and row count in the execution receipt.
Commit replay only after successful execution and deadline validation.

## 6. Security refusals

Refuse every frame mutation.
Refuse replay before backend dispatch.
Refuse changed authority, backend identity, plan, result shape, deadline, budgets, stride, count, or row shape.
Refuse a changed result or receipt at the client.

## 7. Boundary

This profile compresses arithmetic operand sequences only.
It does not represent arbitrary predicates, joins, aggregates, writes, or user-authored code.
Use the generic homogeneous-batch frame when operands do not form this profile.
