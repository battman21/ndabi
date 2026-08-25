# NDABI POC preregistration v0.6

**Status:** FROZEN before the first v0.6 benchmark result. **Date:** 2026-08-21.

This experiment tests architectural stack compression. It preserves every v0.5 source path and
result. It adds a separate executable and result schema.

## 1. Question

Can a stateful execution ABI remove enough application boundaries to outperform tuned JSON by an
order of magnitude without losing exact state, authority, audit data, or human output?

Binary encoding alone is not the tested thesis. Attribute representation, preparation, execution,
receipt, transport, and materialisation costs separately.

## 2. Fixed workload

Use 512 deterministic tasks. Apply eight deterministic changes to status and priority fields.

Use one prepared capability. Bind its handle to the authority digest, kernel version, schema
version, policy version, renderer version, generation, expiry, and change limit.

Reset only the eight changed fields between measured operations. Keep preparation outside the
timed boundary where the arm represents a prepared session.

## 3. Fixed arms

Measure these arms through one balanced schedule:

1. `stateless-json`: parse a complete capability and command, execute, encode, and decode a result.
2. `stateless-wire`: decode the same complete capability and command from a canonical binary frame.
3. `prepared-wire`: decode a capability handle and operands, then use the cached capability.
4. `direct-kernel`: call the prepared state-transition kernel without a message boundary.

Measure these ablations separately:

1. State transition without a receipt.
2. Canonical event construction and receipt production.
3. Exact human patch materialisation.
4. Authenticated checkpoint production and verification.

The transition-only arm is an unsafe performance ceiling. Never describe it as a deployable
profile.

## 4. Canonical event receipt

The local trusted profile uses one canonical event chain. Each event binds the protocol, kernel,
schema, policy, renderer, capability, authority digest, previous revision, next revision, previous
chain root, exact changes, and result handle.

Compute the next chain root from the canonical event bytes. Store those bytes in a fixed event slot.
The POC does not claim durable persistence.

Create authenticated checkpoints with a fixture-only keyed hash. The test key is not production
custody. A changed event, receipt, checkpoint, capability, generation, or revision must refuse.

Keep the v0.5 dual-tree receipt as the untrusted-profile comparison. Do not claim that the local
event chain supplies an independent federated state proof.

## 5. Lossless contract

All arms must produce one canonical application state. Event replay must produce that state from the
same base revision.

All arms must produce byte-identical human patch output under the bound renderer version. The hot
agent path does not materialise that output.

No selective summary can replace the source operation, event bytes, canonical state, or human
output. The benchmark must preserve every changed field.

## 6. Security contract

The model cannot provide the authority digest or capability binding. The trusted runtime creates
the prepared capability.

Validate the complete command before mutation. Refuse stale handles, wrong generations, expired
capabilities, stale revisions, excessive changes, duplicate task identifiers, invalid fields, and
changed receipts.

Measure equal trust profiles. Do not compare the direct trusted profile with an independently
verified federated baseline as a representation claim.

## 7. Measurements

Report request bytes, response bytes, median, p95, deterministic bootstrap intervals, thread CPU,
operations per second, Rust allocations, allocated bytes, and retained control memory.

Report event bytes, event receipt time, transition-only time, materialisation time, checkpoint time,
and refusal results.

Use at least four balanced measurement blocks per arm. Use deterministic fixed-seed bootstrap
intervals. Run the repeatability suite before recording a stable direction.

## 8. Stretch targets

The direct kernel p95 target is 2.5 microseconds. The direct path targets at least eight times the
v0.5 tuned JSON throughput.

The prepared wire p95 target is 6 microseconds. It targets at least four times the v0.5 tuned JSON
throughput.

The repeated prepared command target is at most 64 bytes. The repeated result target is at most 64
bytes.

The direct and prepared hot paths target zero Rust allocations. The local receipt target is 500
nanoseconds. The retained local receipt-control target is 2 KiB.

These targets are preregistered research goals. A missed target is evidence, not permission to
change the target.

## 9. Required disclosures

This experiment is a local in-memory POC. It does not prove durable event persistence, hardware
custody, remote transport, Linux isolation, energy reduction, PostgreSQL, MongoDB, Supabase, or a
public RFC.

The event chain trusts the transition kernel. The federated profile still requires independent
proofs. Model-call token savings remain a separate provider canary.
