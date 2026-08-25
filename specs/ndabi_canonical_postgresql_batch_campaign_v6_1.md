# NDABI canonical PostgreSQL batch campaign v6.1

Status: frozen before the first formal campaign.

## 1. Purpose

Measure canonical batch execution against repeated canonical calls and a native fused floor.
Use one registered PostgreSQL set query for every logical batch.
Separate format compression from database-operation fusion.

## 2. Engine and authority

Use digest-pinned PostgreSQL 16 in one ephemeral Docker container.
Create 10,000 deterministic rows.
Use a dedicated read-only login role without elevated authority.
Require a direct write through that role to refuse.

Bind the canonical frame to the engine, profile, schema, policy, plan, tenant, principal, purpose, and capability.
Use the complete 256-bit keyed frame tag and the keyed result receipt.
Use one server-enforced deadline-setting query before each data query.

## 3. Cases and arms

Test 32 and 128 ordered point operands.
Use five warm-ups and 31 measured samples per arm.
Rotate arm order for each sample.

| Arm | Data query shape | Request form |
|---|---|---|
| Sequential canonical | One prepared point set per operand | One 160-byte frame per operand |
| Batch canonical | One prepared set query per logical batch | One `160 + 20n` byte frame |
| Native fused | One prepared set query per logical batch | No NDABI frame or receipt |

The native arm is a performance floor.
It does not have equal cryptographic work.

## 4. Hard gates

Require complete byte equality across every arm and sample.
Require every canonical receipt to be non-zero.
Require exact data-query counts.
Require at least 80% request-byte reduction.

Require at least 10 times p95 speedup and eight times CPU speedup for 32 operands.
Require at least 25 times p95 speedup and twenty times CPU speedup for 128 operands.
Require batch p95 within 1.25 times the native fused floor.
Require batch median CPU within 1.35 times the native fused floor.
Require at least 75% fewer client allocations than sequential canonical execution.
Require at least 40% fewer allocated client bytes than sequential canonical execution.

Require replay and frame mutation to refuse.
Require inadequate result budgets and non-canonical identifier order to refuse before a data query.

## 5. Campaign rules

Run five fresh client processes against one fresh engine.
Require every process to pass every hard gate.
Require the batch-to-native p95 ratio coefficient of variation below 20% for each case.
Record all raw samples, source and binary hashes, and the resolved image identifier.
Remove the container after the campaign.

## 6. Boundaries

This campaign measures one local PostgreSQL identifier-batch profile on Docker Desktop.
It does not measure hosted Supabase, TLS, LAN, WAN, energy, provider tokens, or physical Linux.
It does not prove heterogeneous batches, dependency graphs, writes, streaming, or arbitrary SQL.
It does not claim that binary encoding alone creates the measured speedup.
