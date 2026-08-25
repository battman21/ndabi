# NDABI shared-session White Tree campaign v4.4

Status: frozen before the first formal campaign.

## 1. Purpose

Prove that PostgreSQL and White Tree can use one backend-neutral NDABI session contract.
Measure the complete authenticated White Tree request path against equivalent named JSON and direct prepared execution.

## 2. Fixed operation

Use the real governed White Tree fixture and `ChunkStore::assemble_context_pack`.
Select trajectory 100, seed ordinal 3, snapshot handle 1, and three causal hops.
Resolve the fixed valid and system times behind the snapshot handle.
Return the complete canonical binary context pack and its White Tree receipt fields.

The NDABI request is one 76-byte authenticated frame.
The named JSON request carries the same operation, trajectory, snapshot, seed, and hop values.
The direct arm calls the same prepared backend without request decoding or session admission.

## 3. Measurement

Build the release binary once.
Run five independent processes.
Use 20 balanced measurement blocks per arm, 20,000 measured operations, and 2,000 warm-up operations per process.
Measure wall latency, thread CPU, allocations, allocated bytes, request bytes, and response bytes.
Record the source tree hash and executable SHA-256 with each process result.

## 4. Correctness and security gates

Require exact response-byte equality across all three arms.
Require deterministic encodings and identical White Tree result identities.
Require all changed-frame, replay, wrong-session, expired-deadline, excessive-budget, and unsupported-operation cases to refuse.
Require each refusal before a successful unauthorised backend execution.
Require the shared-session, PostgreSQL-profile, White Tree, and clippy suites to pass.

## 5. Performance gates

Require the NDABI request to be at least 35 percent smaller than the named JSON request.
Require NDABI p95 latency to be no more than 10 percent above named JSON in every process.
Require the five-process median NDABI p95 to be no slower than the five-process median JSON p95.
Report NDABI overhead against direct prepared execution without a pass threshold.
Reject the campaign after any failed gate.
Do not replace a failed result with a later v4.4 run.

## 6. Boundaries

This campaign proves one local macOS White Tree read profile and the shared backend-neutral session boundary.
It does not prove Linux, sockets, TLS, WAN, MongoDB, Supabase, writes, provider tokens, energy, or production key custody.
