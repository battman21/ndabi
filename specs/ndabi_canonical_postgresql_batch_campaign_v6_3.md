# NDABI canonical PostgreSQL batch methodology repair v6.3

Status: frozen before the first formal campaign.

## 1. Repair scope

Retain the v6.1 engine, cases, arms, sample counts, speed, CPU, allocation, compression, correctness, and security gates.
Replace the unstable native p95 distance hard gate with a median distance hard gate.
Keep native p95 distance as a diagnostic.

The v6.2 evidence supports this change.
Its ten median native distances stayed between 0.945 and 1.062.
Its p95 native distances ranged from 0.401 to 1.625 under the same process design.

## 2. Build closure

Build the release binary into a dedicated v6.3 target directory after the campaign guard passes.
Hash the complete bound source set and the resulting dedicated binary.
Do not reuse the default release binary.

## 3. Hard gates

Require five complete, zero-exit, independently validated process reports.
Require complete result bytes and non-zero canonical receipts.
Require the read-only role and direct-write refusal.
Require exact data-query counts and at least 80% request compression.

Require at least 10 times p95 speedup and eight times median CPU speedup for 32 operands.
Require at least 25 times p95 speedup and twenty times median CPU speedup for 128 operands.
Require batch median wall time within 1.25 times native fused execution.
Require batch median CPU within 1.35 times native fused execution.
Require at least 75% fewer allocations and 40% fewer allocated bytes than sequential canonical execution.

Require replay, mutation, inadequate-budget, and non-canonical-order refusals.
Require the batch-to-native median wall ratio coefficient of variation below 10% for each case.

## 4. Evidence closure

Persist every child result before validation.
Preserve every exit code and validation error.
Use digests instead of unparsed child output.
Record source, binary, and resolved PostgreSQL image hashes.
Remove the ephemeral container after the campaign.

## 5. Boundaries

This local Docker campaign measures one finite PostgreSQL read profile.
The native arm remains a non-cryptographic performance floor.
The campaign does not prove hosted Supabase, TLS, LAN, WAN, energy, provider tokens, physical Linux, or general queries.
