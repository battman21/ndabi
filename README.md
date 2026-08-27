# NDABI

NDABI is the Neural Data Access Binary Interface.

It provides a compact, authenticated interface for finite database operations.
Agents select registered handles and supply typed operands.
Trusted adapters attach authority, policy, budgets, deadlines, and backend identity.

NDABI does not replace PostgreSQL, MongoDB, Supabase, White Tree, or their query planners.
It removes repeated readable query construction from the admitted execution path.

## Current state

The repository contains an implemented research candidate, not a production standard.
The implemented v0.1 profile supports authenticated single reads and homogeneous read batches.
The graph extension executes one registered read graph from one handle and typed parameter block.
The v0.2 transport adds negotiation, results, errors, cancellation, and streaming controls.
The sealed registry binds handles to reviewed implementations, schemas, policies, capabilities, and budgets.
The PostgreSQL adapter executes registered single and heterogeneous batch read graphs.
The Supabase adapter executes the batch graph through one admitted forced-RLS user session.
MongoDB and White Tree do not execute registered graphs yet.

The reusable workspace contains these main components:

| Component | Purpose | State |
|---|---|---|
| `ndabi-protocol` | Frames, authority, replay, receipts, transport, and sealed registries | implemented candidate |
| PostgreSQL adapters | Prepared range, batch, single-graph, and batch-graph operations | implemented research profiles |
| Supabase adapters | PostgreSQL execution with verified JWT identity, row-level security, and registered batch graphs | implemented research profiles |
| MongoDB adapters | Finite identifier-window and batch operations | implemented research profiles |
| registry proof tools | Local registry, PostgreSQL, Supabase, and MongoDB functional proofs | implemented |

Refer to [`specs/ndabi_rfc_candidate_v0_1.md`](specs/ndabi_rfc_candidate_v0_1.md) for the candidate wire contract.
Refer to [`specs/ndabi_plan_registry_candidate_v0_1.md`](specs/ndabi_plan_registry_candidate_v0_1.md) for the registry contract.
Refer to [`specs/ndabi_registered_graph_candidate_v0_1.md`](specs/ndabi_registered_graph_candidate_v0_1.md) for the graph extension.
Refer to [`specs/ndabi_semantic_batch_diagnostic_v0_1.md`](specs/ndabi_semantic_batch_diagnostic_v0_1.md) for the complete diagnostic limits.
Refer to [`specs/ndabi_semantic_batch_campaign_v0_2.md`](specs/ndabi_semantic_batch_campaign_v0_2.md) for the frozen qualification gates.

Run the repository-contained campaign smoke with this command:

```sh
python3 campaigns/semantic_batch_v02.py --smoke
```

The runner creates a pinned one-million-row PostgreSQL fixture and controlled Toxiproxy connection.
It coordinates isolated arms and captures raw latency, client CPU, container CPU, RSS, allocations, source hashes, and binary hashes.
It removes its exact containers, network, and proxy image after each run.
Formal mode refuses a dirty checkout or a host below the frozen quiet-host threshold.

The local diagnostic was 2.65% slower than one fused native query at p95.
Five controlled 2 ms round-trip diagnostics were 117.00–155.00 times faster than 256 sequential queries.
Their median p95 was 4.99% slower than the fused native floor.
One run was 17.20% slower than that floor, so no near-floor p95 claim is accepted.
Every sample verified exact results and keyed receipts.
These values remain diagnostic because the source and host were not frozen before measurement.

The repaired reusable path reached 158.81 times p95 speedup in one contaminated-host 2 ms smoke.
It remained 0.71% above the fused native p95 floor.
It made 88.92% fewer client allocations than repetition.
The request was 65.07% smaller than equivalent concise authenticated JSON.
These later values also remain diagnostic.

## Verify the reusable workspace

```sh
cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
./conformance/verify.sh
```

## Run the registry proof

```sh
cargo run --release --bin ndabi_registry_v01 -- --qualified-v03
```

The Docker-backed PostgreSQL, Supabase, and MongoDB campaigns remain under `research/showdown`.
That directory preserves the full prototype history and its accepted and failed evidence.
The White Tree campaign remains a consumer integration and requires the separate White Tree checkout.

## Security boundary

Treat every model-authored operation as untrusted input.
Use a trusted compiler to select an approved handle.
Protect authority keys outside model context.
Enforce database permissions and row policies independently.
Refuse unknown handles, stale registries, replay, excessive budgets, and changed result shapes before dispatch.

Do not use the public test keys in production.
Remote administration, public-key registry signing, production custody, writes, and arbitrary queries remain outside the implemented candidate.

## Licence

Apache License 2.0. Refer to [`LICENSE`](LICENSE).
