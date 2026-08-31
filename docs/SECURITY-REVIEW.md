# NDABI beta security review

**Status:** Review package ready. Independent review not started.

## 1. Review objective

Decide whether the finite read-only NDABI beta has any open critical or high security defect.
Do not approve arbitrary queries, writes, production key custody, or public deployment.

Record the reviewed commit and source-bundle SHA-256 before inspection.
Refuse a dirty checkout or an unsigned source identity.

## 2. In-scope trust boundaries

Review these boundaries:

1. Authenticate every frame before semantic interpretation.
2. Bind authority, session, generation, registry, backend, policy, and operation identity.
3. Refuse replay, deadline, budget, output-shape, sequence, and correlation failures.
4. Keep database permissions and row policies authoritative.
5. Bind receipts to the exact request, result bytes, rows, and operand bundle.
6. Bind bundle acknowledgements to authenticated controls and expected digests.
7. Enforce TLS 1.3, mutual certificates, server names, `ndabi/2` ALPN, and no early data.
8. Refuse altered persisted replay and registry state.
9. Prevent private keys, root keys, customer data, and database contents from logs or diagnostics.
10. Refuse release artefacts that lack the authorised signer or exact digest.

## 3. Adversary model

Assume the model, network peer, request bytes, result bytes, database contents, and local release files are hostile.
Assume an attacker can replay, truncate, reorder, mutate, duplicate, or reflect every frame.
Assume an attacker can crash the process between verification, execution, replay commit, and response delivery.
Assume an attacker can replace local replay or registry files while the process is stopped.
Assume application code can call public APIs incorrectly.

Do not assume resistance to a compromised operating system, database administrator, HSM administrator, or build-signing authority.

## 4. Required review targets

Review these components:

| Component | Required property |
|---|---|
| `ndabi-protocol` | Authentication, replay, registry, bundle, connection, receipt, and persistence correctness |
| `ndabi-transport-rustls` | Fixed TLS policy, peer identity, bounded framing, and external signer isolation |
| Go conformance package | Independent frame, bundle-control, replay, receipt, and sequence parity |
| TypeScript conformance package | Independent frame, bundle-control, replay, receipt, and sequence parity |
| PostgreSQL and Supabase adapters | Native permissions, transaction coupling, RLS, budgets, and exact results |
| MongoDB adapter | Finite operation enforcement, budgets, exact results, and receipts |
| Release tooling | Signed-tag identity, deterministic archive, hashes, path safety, and rollback procedure |

## 5. Required verification

Run only the focused commands for the reviewed boundary.
Run the complete commands once before the final verdict.

```sh
cargo test -p ndabi-protocol --locked
cargo test -p ndabi-transport-rustls --locked
cargo clippy -p ndabi-protocol -p ndabi-transport-rustls --all-targets --locked -- -D warnings
python3 conformance/test_vectors.py
(cd conformance/go && go test ./...)
(cd conformance/typescript && npm ci && npm test)
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
```

Run dependency vulnerability checks with a current advisory database.
Record the advisory database identity and date.
Do not treat an unavailable or stale database as a pass.

## 6. Required adversarial checks

Attempt each failure against every applicable implementation:

- Change every authenticated byte.
- Reflect frames across transport directions.
- Reuse a terminal correlation.
- Skip, duplicate, reorder, and overflow stream sequences.
- End a stream without data.
- Return cancellation code seven before a valid cancellation.
- Change bundle handles, graphs, expiry, result shape, values, or digest.
- Exceed frame, payload, row, result, bundle, and in-flight limits.
- Reuse a nonce after process restart.
- Replace persisted state with an older valid snapshot.
- Change certificate authority, server name, ALPN, expiry, or signer resolver.
- Publish a bundle from a dirty checkout, wrong tag, wrong signer, or changed existing artefact.

## 7. Mandatory findings format

Record each finding with severity, affected commit, path, invariant, exploit path, reproduction, and required repair.
Use `critical`, `high`, `medium`, `low`, or `informational` severity.
Do not close a finding without a regression test that fails when the repair is removed.

## 8. Beta decision rule

Reject the beta when any critical or high finding remains open.
Reject the beta when a required test is skipped, flaky, or lacks exact source custody.
Reject the beta when the review finds an undocumented trust assumption.
Reject the beta when evidence contains production secrets or customer data.

Approve only the finite registered read surface defined in `BETA.md`.
List every excluded production boundary in the approval statement.

## 9. Known exclusions

The candidate does not provide production HSM, KMS, PKCS#11, certificate revocation, or trusted rollback-anchor implementations.
It does not support arbitrary queries, writes, multi-node replay coordination, or public non-repudiation.
Remote performance and formal database performance remain separate acceptance gates.
