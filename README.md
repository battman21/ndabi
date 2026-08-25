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
The v0.2 transport adds negotiation, results, errors, cancellation, and streaming controls.
The sealed registry binds handles to reviewed implementations, schemas, policies, capabilities, and budgets.

The reusable workspace contains these main components:

| Component | Purpose | State |
|---|---|---|
| `ndabi-protocol` | Frames, authority, replay, receipts, transport, and sealed registries | implemented candidate |
| PostgreSQL adapters | Prepared range and batch operations | implemented research profiles |
| Supabase adapters | PostgreSQL execution with verified JWT identity and row-level security | implemented research profiles |
| MongoDB adapters | Finite identifier-window and batch operations | implemented research profiles |
| registry proof tools | Local registry, PostgreSQL, Supabase, and MongoDB functional proofs | implemented |

Refer to [`specs/ndabi_rfc_candidate_v0_1.md`](specs/ndabi_rfc_candidate_v0_1.md) for the candidate wire contract.
Refer to [`specs/ndabi_plan_registry_candidate_v0_1.md`](specs/ndabi_plan_registry_candidate_v0_1.md) for the registry contract.

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
