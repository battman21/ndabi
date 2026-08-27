# NDABI registered graph candidate v0.1

**Status:** Implemented protocol slice. This document is not a public RFC or a production standard.

## 1. Purpose

The profile executes one registered read graph through one authenticated request.
The hot request carries a graph handle, typed parameters, budgets, and a deadline.
It does not repeat the graph topology, query text, schemas, or policy description.

A trusted control plane registers the graph before session creation.
An untrusted model can select only a registered handle and supply bounded parameters.

## 2. Registered graph

A registered graph binds these fields:

| Field | Meaning |
|---|---|
| opcode | Finite operation class |
| graph handle | Compact session operation identity |
| result shape | Canonical final result contract |
| nodes | Ordered native plan handles and intermediate result shapes |
| dependencies | Strictly increasing earlier node indexes |
| parameter schema digest | Exact typed input contract |
| implementation digest | Reviewed native implementation |
| budgets | Maximum parameter bytes, result bytes, and rows |
| capabilities | Required query, graph, and optional read capabilities |

The graph contains between two and 4,096 nodes.
It contains at least one dependency and at most 16,384 dependencies.
Every dependency must reference an earlier node.
The protocol refuses duplicate, forward, and non-canonical dependency lists.

The graph registry digest binds every graph field, node, dependency, and implementation digest.
The authority context binds that registry digest to the backend identity.

## 3. Hot frame

The frame contains `160 + P` bytes.
`P` is the typed parameter block length and cannot exceed 1 MiB.

Authenticate every byte before the final tag with keyed BLAKE3:

```text
"ndabi/wire/v1/graph-frame" || frame[0..tag_offset]
```

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | `NDBI` |
| 4 | 1 | major version | `1` |
| 5 | 1 | minor version | `0` |
| 6 | 1 | frame kind | `4`, registered graph |
| 7 | 1 | access class | `1`, read |
| 8 | 2 | flags | zero |
| 10 | 2 | opcode | non-zero |
| 12 | 4 | complete frame bytes | exact length |
| 16 | 8 | session | authority session |
| 24 | 8 | generation | authority generation |
| 32 | 8 | nonce | next session nonce |
| 40 | 8 | deadline | Unix microseconds |
| 48 | 4 | result-byte budget | non-zero |
| 52 | 4 | result-row budget | non-zero |
| 56 | 4 | graph handle | registered handle |
| 60 | 4 | result shape | registered shape |
| 64 | 4 | parameter bytes | exact `P` |
| 68 | 28 | reserved | zero |
| 96 | 32 | authority context digest | exact binding |
| 128 | `P` | typed parameters | profile-defined canonical bytes |
| `128 + P` | 32 | authentication tag | complete keyed tag |

## 4. Admission order

The server must apply this order:

1. Check the bounded frame length.
2. Authenticate the complete frame.
3. Check the version, kind, access class, and reserved bytes.
4. Check the session, generation, and authority context.
5. Check the deadline and server budgets.
6. Require the next exact nonce.
7. Require the registered backend identity.
8. Resolve the graph handle in the sealed registry.
9. Check the opcode, result shape, capabilities, and registered budgets.
10. Dispatch the complete graph once.
11. Check the deadline again.
12. Commit replay state.
13. Return the exact result and keyed receipt.

Authentication and registry refusal must occur before backend dispatch.
A failed backend or registry check must not commit replay state.

## 5. Backend contract

The backend receives one graph handle and one borrowed parameter block.
It must execute one fused native operation or refuse the graph.
It must not hide sequential remote operations behind one successful graph response.

The current implementation proves one backend dispatch through a fake conformance backend.
The PostgreSQL adapter lowers one three-node review graph into one prepared query.
It also lowers up to 1,024 filtered aggregate operands into one prepared batch query.
The batch profile limits the total selected source rows to 65,536.
The Supabase adapter executes the batch graph through one admitted user session with forced RLS.
It binds the authority tenant, principal, and deadline to the admitted JWT identity.
It does not prove MongoDB or White Tree graph lowering.

## 6. Result contract

The backend writes through the bounded output interface.
The interface enforces byte and row budgets during result construction.

The execution receipt uses the existing keyed NDABI receipt function.
It binds the authority context, complete request digest, nonce, row count, and exact result bytes.
The client must verify the receipt before it commits the result.

## 7. Implemented gates

The Rust tests prove these behaviours:

- One registered graph causes one backend dispatch.
- Every changed graph-frame bit fails authentication.
- Forward, duplicate, and non-canonical dependencies fail.
- Registry identity changes after graph or implementation changes.
- Unknown handles and excessive parameter blocks fail before dispatch.
- Replay fails without repeated backend work.
- The client verifies the exact keyed execution receipt.
- A read-only PostgreSQL role executes the three-node graph through one data query.
- A read-only PostgreSQL role executes four heterogeneous operands through one batch data query.
- Both PostgreSQL paths verify exact results, keyed receipts, and replay refusal.
- The Supabase-compatible path verifies forced RLS results and refuses identity drift before dispatch.

## 8. Unproved boundaries

Five local-Docker diagnostics measured one 256-item batch through a controlled 2 ms round trip.
Their p95 speedup against 256 repeated native prepared queries ranged from 117.00 to 155.00 times.
Their median p95 was 4.99% slower than the equivalent fused native set query.
One run was 17.20% slower than that native floor.
The results are not qualified because the campaign was not frozen before measurement.

This slice does not prove qualified graph performance, durable production replay, remote discovery, or public-key custody.
It does not define graph registration administration or Substrait compatibility.
It permits reads only and does not define atomic write graphs.
