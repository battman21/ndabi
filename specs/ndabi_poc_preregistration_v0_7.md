# NDABI POC preregistration v0.7

**Status:** FROZEN before the first v0.7 benchmark result. **Date:** 2026-08-21.

This experiment tests whether the v0.6 result survives a controlled local campaign. It repairs the
mutable comparison baseline. It does not change the frozen v0.6 result.

## 1. Question

Does the prepared NDABI architecture remain faster and smaller under repeated independent processes,
without using an external performance result as a baseline?

## 2. Comparison boundary

Compile every measured arm into one release binary. Run every arm through one balanced schedule.
Use the stateless JSON arm from that executable as the performance and representation baseline.

Do not read `results/latest.json` or another mutable result when deciding a v0.7 gate. Preserve any
cross-version measurement only as historical evidence.

Use the same kernel, state, capability, changes, receipt, and exactness contract for every arm.
Preparation remains outside the timed boundary only for prepared profiles.

## 3. Fixed workload

Use 512 deterministic tasks and eight deterministic changes. Use 10,000 measured operations and
500 warm-up operations for each campaign process.

Run 30 independent operating-system processes. Bind every result to one source fingerprint and one
release-binary SHA-256 digest.

## 4. Fixed arms

Measure stateless JSON, stateless wire, prepared wire, and direct kernel execution. Preserve the v0.6
canonical event, result verification, exact replay, and refusal contracts.

The direct arm excludes a message boundary. Describe it as a local kernel ceiling, not remote
performance.

## 5. Statistics

Report median, p95, p99, p99.9, bootstrap intervals, thread CPU, throughput, allocations, and bytes.
Report the minimum, maximum, mean, population deviation, and coefficient of variation across processes.

Store every process result under an immutable campaign directory. Record each result SHA-256 digest.
Refuse a source fingerprint or release-binary digest change during the campaign.

## 6. Local hard gates

Every process must pass exact state, exact replay, exact human output, receipt equality, event equality,
deterministic encoding, and all ten refusal checks.

The prepared p95 upper interval must be at least three times faster than same-process stateless JSON.
The direct p95 upper interval must be at least four times faster than same-process stateless JSON.

The prepared request must remain at most 64 bytes. The result must remain at most 64 bytes.
Prepared and direct execution must allocate no measured Rust heap memory.

All 30 processes must pass. Prepared and direct p95 coefficients of variation must not exceed 10%.

## 7. Adversarial and durability gates

Flip every bit in each compact frame. Every changed frame must refuse before state mutation.
Generate varied valid commands and compare direct execution with event replay.

Persist canonical events through an append-only local log. Verify complete replay after reopening.
Recover the complete prefix after a torn final append. Refuse a changed complete record.

Run concurrent independent sessions and verify every final state. This does not prove shared-state
serialisation or distributed consensus.

## 8. Required disclosures

This campaign remains a local macOS measurement. It does not prove Linux, energy, remote transport,
durable production custody, shared-state concurrency, PostgreSQL, MongoDB, Supabase, or model tokens.

The event chain trusts the local transition kernel. A federated profile still requires an independent
proof.
