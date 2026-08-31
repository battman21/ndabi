# NDABI

NDABI is the Neural Data Access Binary Interface.

It provides a compact, authenticated interface for finite database operations.
Agents select registered handles and supply typed operands.
Trusted adapters attach authority, policy, budgets, deadlines, and backend identity.

NDABI does not replace PostgreSQL, MongoDB, Supabase, White Tree, or their query planners.
It removes repeated readable query construction from the admitted execution path.

## Repository custody

This repository is the canonical source for the NDABI protocol and its reusable implementations.
Keep protocol specifications, profiles, conformance fixtures, campaign harnesses, and benchmark evidence here.
PostgreSQL, MongoDB, Supabase, White Tree, and Onlife integrations must consume NDABI through documented boundaries.
Keep consumer-specific integration code in its consumer repository.
Do not mirror NDABI source or specifications into consumer repositories.

## Current state

The repository contains an implemented research candidate, not a production standard.
The implemented v0.1 profile supports authenticated single reads and homogeneous read batches.
The graph extension executes one registered read graph from one handle and typed parameter block.
The operand-bundle core implements canonical layouts, session-bound frames, immutable storage, and operand-bound receipts.
The transport negotiates operand-bundle support and correlates authenticated registration and removal acknowledgements.
A PostgreSQL bundle profile and Supabase RLS wrapper pass focused Docker integration tests.
The complete local Supabase stack passes Auth health, forced RLS, exact results, and receipt checks.
The MongoDB bundle adapter passes a real Docker execution with one retained static decode.
The White Tree bundle adapter remains a consumer integration.
The v0.2 transport adds negotiation, results, errors, cancellation, and streaming controls.
Independent Go and TypeScript decoders pass its shared message and mutation vectors.
The sealed registry binds handles to reviewed implementations, schemas, policies, capabilities, and budgets.
The PostgreSQL adapter executes registered single and heterogeneous batch read graphs.
The Supabase adapter executes the batch graph through one admitted forced-RLS user session.
Both adapters support one registered bundle graph with immutable ranges and dynamic thresholds.
MongoDB executes one registered identifier-set bundle with a changing score threshold.
The external White Tree consumer adapter executes one governed bitemporal operand bundle.
Its consumer commit remains outside this repository and is not remotely published yet.

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
Refer to [`specs/ndabi_operand_bundle_candidate_v0_1.md`](specs/ndabi_operand_bundle_candidate_v0_1.md) for the designed operand-reuse extension.
Refer to [`specs/ndabi_operand_bundle_campaign_v0_1.md`](specs/ndabi_operand_bundle_campaign_v0_1.md) for the original comparative campaign.
Refer to [`specs/ndabi_operand_bundle_campaign_v0_2.md`](specs/ndabi_operand_bundle_campaign_v0_2.md) for the corrected beta performance gates.
Refer to [`specs/ndabi_semantic_batch_diagnostic_v0_1.md`](specs/ndabi_semantic_batch_diagnostic_v0_1.md) for the complete diagnostic limits.
Refer to [`specs/ndabi_semantic_batch_campaign_v0_2.md`](specs/ndabi_semantic_batch_campaign_v0_2.md) for the frozen qualification gates.

Run the repository-contained campaign smoke with this command:

```sh
python3 campaigns/semantic_batch_v02.py --smoke
```

Run the operand-bundle campaign smoke with this command:

```sh
python3 campaigns/operand_bundle_v02.py --smoke
```

The latest non-formal bundle smoke reduced 1,024-item requests by 74.23%.
Bundle p95 was 0.47% slower than fused native and 1.39% faster than registered graph execution.
Bundle client CPU was 7.26% lower than graph execution, but allocated bytes were equal.
The old total-CPU gate was impossible because it required savings below the fused database-driver floor.
The v0.2 campaign retains complete CPU and latency limits and measures protocol excess above that floor.
The v0.2 formal campaign remains unexecuted.

The runner creates a pinned one-million-row PostgreSQL fixture and controlled Toxiproxy connection.
It captures raw latency, client CPU, allocations, source identity, binary identity, image identity, and host state.
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
