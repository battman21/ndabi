# NDABI

NDABI is the Neural Data Access Binary Interface.

Its primary target is a compact data instruction set for agents.
Agents compose bounded numeric programs without SQL, JSON keys, REST paths, or backend field names.
Trusted adapters verify each program before they lower it into one native backend operation.
Repeated programs can become compact registered handles with changing typed operands.

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
The dynamic ISA vertical slice implements numeric schemas, eight relational instructions, canonical binary programs, typed operand blocks, fail-closed verification, and scoped cache promotion.
The protocol authenticates complete dynamic programs and operands before it verifies, admits, and dispatches them.
The PostgreSQL executor resolves identifiers through a trusted numeric catalogue and returns canonical binary results with exact receipts.
One focused Docker test proves an unregistered filter, projection, sort, and limit program against native PostgreSQL results.
One focused Docker test proves compact dynamic execution through an admitted Supabase JWT session and forced row-level security.
One repository-contained smoke proves distinct exact results for two admitted users through the same dynamic numeric program.
Repeated full programs reuse one bounded prepared-statement cache entry.
An authenticated promotion receipt converts a verified program into an authority-scoped compact handle.
Later requests send the handle and compact changing operands without resending the program or duplicated metadata.
Each PostgreSQL request runs in one read-only transaction with a database-side deadline bound.
The result encoder reuses one validity bitmap and borrows variable fields without per-row clones.
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
The independent Go sequence enforces negotiation, correlation, cancellation, streaming, budgets, receipts, and bundle acknowledgements.
The independent TypeScript sequence enforces the same state and rejects pending requests that bypass its authenticated verifier.
Independent Go and TypeScript decoders authenticate bundle registration and removal before their state machines accept control metadata.
Both state machines pass the shared negotiation and state-refusal vectors.
The reusable Rustls profile requires TLS 1.3, mutual certificates, NDABI ALPN, and no early data.
Its resolver API supports externally managed certificate signers without weakening the fixed transport policy.
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
| `ndabi-isa` | Dynamic numeric programs, schema binding, verification, and cache promotion | implemented vertical slice |
| `ndabi-protocol` | Dynamic, cached, registered, replay-safe, and receipt-bound execution | implemented candidate |
| `ndabi-transport-rustls` | TLS 1.3 mutual authentication and bounded stream framing | implemented candidate |
| PostgreSQL adapters | Dynamic execution plus prepared range, batch, single-graph, and batch-graph operations | focused dynamic proof and research profiles implemented |
| Supabase adapters | Dynamic and registered PostgreSQL execution with verified JWT identity and row-level security | focused dynamic proof and research profiles implemented |
| MongoDB adapters | Finite identifier-window and batch operations | implemented research profiles |
| registry proof tools | Local registry, PostgreSQL, Supabase, and MongoDB functional proofs | implemented |

Refer to [`specs/ndabi_rfc_candidate_v0_1.md`](specs/ndabi_rfc_candidate_v0_1.md) for the candidate wire contract.
Refer to [`specs/ndabi_dynamic_isa_candidate_v0_1.md`](specs/ndabi_dynamic_isa_candidate_v0_1.md) for the primary dynamic instruction-set contract.
Refer to [`specs/ndabi_plan_registry_candidate_v0_1.md`](specs/ndabi_plan_registry_candidate_v0_1.md) for the registry contract.
Refer to [`specs/ndabi_registered_graph_candidate_v0_1.md`](specs/ndabi_registered_graph_candidate_v0_1.md) for the graph extension.
Refer to [`specs/ndabi_operand_bundle_candidate_v0_1.md`](specs/ndabi_operand_bundle_candidate_v0_1.md) for the designed operand-reuse extension.
Refer to [`specs/ndabi_operand_bundle_campaign_v0_1.md`](specs/ndabi_operand_bundle_campaign_v0_1.md) for the original comparative campaign.
Refer to [`specs/ndabi_operand_bundle_campaign_v0_2.md`](specs/ndabi_operand_bundle_campaign_v0_2.md) for the corrected beta performance gates.
Refer to [`specs/ndabi_semantic_batch_diagnostic_v0_1.md`](specs/ndabi_semantic_batch_diagnostic_v0_1.md) for the complete diagnostic limits.
Refer to [`specs/ndabi_semantic_batch_campaign_v0_2.md`](specs/ndabi_semantic_batch_campaign_v0_2.md) for the frozen qualification gates.
Refer to [`docs/BETA-OPERATIONS.md`](docs/BETA-OPERATIONS.md) for release, installation, upgrade, rollback, and removal procedures.
Refer to [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md) for the independent beta review scope and refusal rules.
Refer to [`docs/WHY-NDABI.md`](docs/WHY-NDABI.md) for the developer value, use cases, evidence, and productisation target.

Run the repository-contained campaign smoke with this command:

```sh
python3 campaigns/semantic_batch_v02.py --smoke
```

Run the operand-bundle campaign smoke with this command:

```sh
python3 campaigns/operand_bundle_v02.py --smoke
```

Run the dynamic ISA control-path diagnostic with this command:

```sh
cargo run --release -p ndabi-postgres --example dynamic_isa_smoke
```

This diagnostic measures verification, PostgreSQL lowering, and cached lookup separately.
It does not measure database execution or complete workflow performance.

Run the dynamic Supabase-compatible RLS smoke with this command:

```sh
python3 campaigns/dynamic_supabase_rls_v01.py --smoke
```

The smoke uses a non-superuser authenticator, forced RLS, two JWT subjects, exact receipts, and refusal checks.
It proves a local Supabase-compatible database boundary, not the complete Supabase platform or performance.

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
Use a trusted numeric schema and verifier to admit each dynamic program.
Use approved handles only after safe program promotion.
Protect authority keys outside model context.
Enforce database permissions and row policies independently.
Apply every request deadline inside the backend transaction.
Refuse unknown handles, stale registries, replay, excessive budgets, and changed result shapes before dispatch.

Do not use the public test keys in production.
Remote administration, public-key registry signing, production custody, writes, and unbounded queries remain outside the implemented candidate.

## Licence

Apache License 2.0. Refer to [`LICENSE`](LICENSE).
