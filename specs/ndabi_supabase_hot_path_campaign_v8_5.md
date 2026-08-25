# NDABI Supabase hot-path campaign v8.5

Status: candidate preregistration.
Freeze this document with the implementation before performance measurement.

Baseline smoke `20260825T042305Z` selected immutable frame preparation as the first CPU repair.
The repair preserves identical wire bytes and rewrites only the nonce, deadline, and authentication tag.
Functional smoke `20260825T050138Z` passed all 24 security checks after the repair.
Performance smoke `20260825T050406Z` did not prove an end-to-end improvement.

## 1. Purpose

Locate the remaining NDABI CPU cost before another optimisation.
Separate protocol cost from database, governance, result, receipt, and transport costs.
Compare NDABI with both raw-native and equal-security native controls.

## 2. Fixed workload

Use one million PostgreSQL rows and forced row-level security.
Use sixteen indexed operations and eight rows per operation.
Return the complete canonical result bytes.
Use one persistent user session and one prepared set query.
Measure direct PostgreSQL and Supavisor session mode separately.

## 3. Controls

| Arm | Work | Purpose |
|---|---|---|
| Raw native | Prepared query and exact result encoding | Measure the engine and driver floor |
| Governed native | Native typed call with identical authority, replay, deadline, budgets, result digest, and receipt | Measure mandatory governance cost |
| NDABI | Complete authenticated frame, registered dispatch, identical query, result, and receipt | Measure protocol overhead |
| Repeated PostgREST | Sixteen JWT HTTP requests | Measure the conventional layered path |

The governed-native arm MUST use the same security checks as NDABI.
It MUST skip only NDABI frame encoding, decoding, and request authentication.
Every arm MUST return identical declared result bytes.

## 4. Component attribution

Measure these components separately with process CPU and monotonic clocks:

1. Request encoding.
2. Request authentication and decoding.
3. Replay admission.
4. Registered-plan dispatch.
5. PostgreSQL execution.
6. Canonical result encoding.
7. Server result hashing and receipt creation.
8. Client result hashing and receipt verification.
9. Result comparison and benchmark bookkeeping.

Use a fixed in-process backend to measure components one through four without database variance.
Measure the database profiles with result sizes of 84, 672, and 10,758 bytes.
Reject missing, overlapping, negative, or non-monotonic component intervals.

## 5. Candidate optimisations

Do not enable an optimisation before the component baseline identifies its cost.

- Clone precomputed session hash states for request tags and receipts.
- Reuse authenticated frame and output storage without exposing stale bytes.
- Hash immutable result bytes during encoding or transport.
- Bind receipts to the authenticated request tag when the security proof permits it.
- Verify streamed result bytes while the client receives them.
- Retain one scalar replay frontier for one exclusive session.

Every optimisation MUST retain request, result, authority, replay, deadline, row, byte, and plan bindings.

## 6. Security and exactness

Require every existing Supabase security refusal.
Refuse changed frames, operands, results, receipts, nonces, deadlines, budgets, identities, policies, schemas, and plans.
Refuse replay before database dispatch.
Refuse a failed result encoder without exposing partial bytes.
Require exact results across all arms and result sizes.

Run a red-green mutation for each new security test.

## 7. Sampling

Use five qualified repetitions for every boundary, arm, and result size.
Run each measured arm for at least five seconds.
Allow each worker at most ten minutes for the frozen high-concurrency REST workload.
Interleave arms with a fixed Latin square.
Reject any repetition that observes a compiler or another benchmark campaign.
Record source, binary, lockfile, container image, and campaign digests.

## 8. Acceptance gates

Apply each gate within every qualified repetition.

| Metric | Gate |
|---|---:|
| NDABI p95 over governed native | At most 1.03 |
| NDABI client CPU over governed native | At most 1.05 |
| NDABI measured stack CPU over governed native | At most 1.05 |
| Governed-native stack CPU over raw native | Report separately; no hidden subtraction |
| NDABI throughput over raw native | At least 0.95 |
| NDABI throughput over repeated PostgREST | At least 5.00 |
| NDABI allocations over governed native | At most one additional allocation |
| NDABI request bytes against complete JSON | At least 80% smaller |
| P95-ratio variation | At most 10% |

Do not accept a median when one repetition fails.
Do not convert a component improvement into an end-to-end claim.

## 9. Boundaries

This campaign tests local Docker and one fixed Supabase-compatible workload.
It does not test hosted Supabase, geographic WAN, energy, production custody, arbitrary SQL, or general writes.
It does not permit removal of exactness, governance, replay, or receipt verification.
