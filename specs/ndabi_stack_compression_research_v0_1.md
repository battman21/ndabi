# NDABI stack compression research v0.1

**Status:** IMPLEMENTATION-BACKED RESEARCH. **Date:** 2026-08-22.

## 1. Corrected performance reading

The earlier 5% to 9% result compared NDABI only with protected CBOR.
It did not compare the complete compressed path with stateless JSON.

The failed v1.3 campaign measured the complete NDABI path at 8.24 to 8.40 times faster.
The direct typed-operation ceiling measured 12.77 to 12.95 times faster than stateless JSON.

Prepared JSON to NDABI measured 2.64 to 2.73 times.
NDABI remained 1.53 to 1.56 times slower than the direct typed-operation ceiling.

These ratios passed their registered repeatability checks.
The overall v1.3 campaign still failed its incorrect timer-control gate.

## 2. Why the remaining path is slow

The point-query path still encodes and decodes a request.
It then copies, checksums, parses, and verifies a response.

The large-result path performs more repeated memory passes.
It builds the result, hashes it, copies it into a response, checksums it, and compares it again.

Changing only the binary header cannot remove these passes.
The next gain must remove copies, repeated validation, repeated round trips, and repeated planning.

## 3. Relevant established designs

PostgreSQL retains named prepared statements for a session.
Its extended protocol separates Parse, Bind, and Execute for reuse.

PostgreSQL pipeline mode sends queries without waiting for earlier results.
This reduces network round trips.

Source: [PostgreSQL protocol flow](https://www.postgresql.org/docs/current/protocol-flow.html).
Source: [PostgreSQL pipeline mode](https://www.postgresql.org/docs/current/libpq-pipeline-mode.html).

Apache Arrow uses a shared in-memory columnar representation.
Its C Data Interface supports zero-copy sharing within one process.

Arrow IPC permits reconstruction without copying actual data buffers.
Source: [Apache Arrow format](https://arrow.apache.org/docs/format/Intro.html).

Simple Binary Encoding requires copy-free, allocation-free, sequential, and aligned access.
Generated flyweights operate directly over the transport buffer.

Source: [SBE design principles](https://github.com/aeron-io/simple-binary-encoding/wiki/Design-Principles).

Cap'n Proto promise pipelining collapses dependent remote operations into one round trip.
Its readers apply lazy bounds, traversal, and nesting checks to untrusted input.

Source: [Cap'n Proto RPC](https://capnproto.org/rpc.html).
Source: [Cap'n Proto encoding](https://capnproto.org/encoding.html).

## 4. NDABI design consequences

Keep NDABI as the compact governed control plane.
Do not use it as a custom bulk-result container.

Use prepared capability and operation handles.
Keep sessions and transport connections alive.

Fuse dependent operations into one bounded execution graph.
Return local results through read-only shared views.

Return remote tabular results through Arrow-compatible buffers.
Avoid JSON objects, hexadecimal payloads, and duplicate DTO construction.

Use one integrity mechanism at each trust boundary.
Do not add a frame checksum when an authenticated transport already supplies equivalent corruption detection.

Retain policy-before-bytes, authority binding, replay protection, budgets, and exact receipts.
Stack compression cannot remove these controls.

## 5. Measured local result

The v1.5 diagnostic located request and response framing costs.
The v1.6 and v1.7 campaigns then removed result copying and dynamic frame construction.

The v1.8 campaign binds the prepared handle before the hot operation.
Its eight-byte execute frame contains only the changing nonce.

Its gate passed, but its cross-arm payload proof used hashes instead of literal bytes.
The v1.9 campaign corrected this defect and compared complete payload vectors.

The accepted v1.9 path measured 12.42 times faster than stateless JSON for the point case.
It measured 1.51 times faster than full framed NDABI.

It also measured 1.24 to 1.26 times faster than full NDABI for large results.
All three cases remained within 1.05% of the direct typed ceiling.

## 6. Real-engine result

The v2.4 campaign used five independent signed White Tree databases.
Each database held 10,000 trajectories in 100 partitions.

Governed SQL p95 measured 18.398 milliseconds.
Session NDABI p95 measured 59.854 microseconds.
The ratio was 307.38 times.

Session NDABI was 6.12% slower than native typed execution.
Full NDABI was 15.40% slower than session NDABI.

White Tree SQL creates a DataFusion session and parses and plans each call.
It also serialises Arrow IPC to calculate its output digest.
The typed Arrow path avoids these SQL-specific passes.

The PostgreSQL v2.6 campaign did not reproduce this gain.
Simple SQL was only 2.12% slower than session NDABI.
PostgreSQL already reuses named prepared statements through its extended protocol.

The result establishes a strict design rule.
NDABI must select an existing typed kernel or prepared plan.
NDABI gains little when it wraps an already efficient prepared database protocol.

Arrow also separates trusted same-process sharing from IPC.
The C Data Interface supports zero-copy same-process sharing.
Arrow IPC can require contiguous buffer construction and copying.

Source: [Apache Arrow C Data Interface](https://arrow.apache.org/docs/format/CDataInterface.html).
Source: [Apache Arrow dissociated IPC](https://arrow.apache.org/docs/format/DissociatedIPC.html).

## 7. Next hypotheses

Test the same contract through Unix sockets, loopback TCP, and controlled remote transport.
Test real White Tree and PostgreSQL engines with identical policies, queries, and result bytes.

Use a session-bound control plane with Arrow-compatible remote result buffers.
Measure one, eight, and 32 fused operations under concurrency.
