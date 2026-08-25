# NDABI sealed plan registry candidate v0.1

**Status:** Implemented research slice. This document is not a public RFC or a production standard.

**Parent:** `ndabi_rfc_candidate_v0_1.md`.

## 1. Purpose

The registry removes query construction and readable query text from the authenticated execution path.
A trusted compiler registers each permitted operation before a session starts.
An agent sends one compact plan handle, fixed operands, limits, and a deadline.
The database adapter executes only the registered implementation for that handle.

The registry does not replace database planning, indexing, transactions, permissions, or row policies.
It does not permit arbitrary SQL, MongoDB documents, collection names, operators, or machine instructions.

## 2. Implemented boundary

The Rust protocol crate implements the following control-plane objects:

| Object | Purpose |
|---|---|
| `CapabilityManifest` | Declare the finite capabilities of one backend profile. |
| `RegisteredPlan` | Bind one handle to fixed semantics, limits, and digests. |
| `PlanRegistry` | Sort, validate, seal, and identify one plan set. |
| `RegisteredBackend` | Validate one single operation before backend dispatch. |
| `RegisteredBatchBackend` | Validate one homogeneous batch before backend dispatch. |
| authenticated discovery | Publish one bounded binary registry under the session transport key. |
| `FileRegistryStore` | Persist one active digest and a bounded revocation set. |
| `RegistryKeyProvider` | Load registry authentication material from an external custody implementation. |

The existing v0.1 frames remain unchanged.
The existing backend profiles remain unchanged.
Registered profiles use separate profile identifiers.

| Surface | Legacy profile | Registered profile | Built evidence |
|---|---:|---:|---|
| PostgreSQL range | `0x50471001` | `0x50471002` | Registry construction and opt-in backend constructor. |
| Supabase user RLS | PostgreSQL legacy | `0x50471002` | Exact registered-profile refusal before connection setup. |
| MongoDB identifier window | `0x4d471001` | `0x4d471002` | Registry construction and opt-in backend constructor. |
| White Tree context | `0x57541001` | `0x57541002` | Complete governed-result execution through the wrapper. |

## 3. Capability bits

| Bit | Name | Meaning |
|---:|---|---|
| 0 | query | Execute a registered read operation. |
| 1 | batch | Execute one registered homogeneous batch. |
| 2 | aggregate | Execute a registered aggregate. |
| 3 | relationship | Traverse a registered relationship. |
| 4 | mutation | Execute a registered mutation. |
| 5 | transaction | Execute a registered transaction operation. |
| 6 | streaming | Return a registered streamed result. |
| 7 | cancellation | Cancel an admitted request. |
| 8 | explain | Return a registered execution explanation. |

A manifest MUST contain at least one known capability.
A manifest MUST refuse every unknown capability bit.
This implementation creates read plans only.
A read plan MUST require the query capability.
A read plan MUST NOT require mutation or transaction capabilities.
A multi-item plan MUST require the batch capability.

## 4. Registered plan record

Each registered read plan contains these fields:

| Field | Type | Rule |
|---|---|---|
| opcode | `u16` | Non-zero and fixed for the handle. |
| handle | `u32` | Non-zero and unique in the registry. |
| result shape | `u32` | Non-zero and fixed for the handle. |
| maximum batch operations | `u32` | Between one and 4,096. |
| maximum result bytes | `u32` | Non-zero. |
| maximum rows | `u32` | Non-zero. |
| required capabilities | `u64` | Known and supported by the manifest. |
| parameter schema digest | 32 bytes | Non-zero and fixed for the operand schema. |
| implementation digest | 32 bytes | Non-zero and fixed for the executable implementation. |

The parameter schema digest binds operand meaning and validation rules.
The implementation digest binds the selected query, pipeline, or governed engine operation.
The registry contains no readable query text.

## 5. Registry construction

The registry MUST refuse an empty plan set.
The registry MUST refuse more than 4,096 plans.
The registry MUST refuse duplicate handles.
The registry MUST refuse unsupported plan capabilities.
The registry MUST sort plans by handle before digest calculation.
The registry MUST keep the sealed fields immutable after construction.

Input order MUST NOT change the registry digest.
Any bound identity, manifest, plan field, schema digest, or implementation digest MUST change the registry digest.

## 6. Registry digest

Compute the registry digest with unkeyed BLAKE3 over this exact concatenation:

```text
"ndabi/wire/v1/plan-registry"
|| LE16(registry_major) || LE16(registry_minor)
|| LE32(engine) || LE32(profile)
|| schema_digest || policy_digest
|| LE64(capability_bits) || LE32(plan_count)
|| sorted_plan_records
```

Encode each sorted plan record with this exact concatenation:

```text
LE16(opcode) || LE32(handle) || LE32(result_shape)
|| LE32(maximum_batch_operations)
|| LE32(maximum_result_bytes) || LE32(maximum_rows)
|| LE64(required_capabilities)
|| parameter_schema_digest || implementation_digest
```

Store this digest as the `plan_digest` in the existing backend identity.
The existing authority context authenticates that backend identity for every request frame.

## 7. Execution

Apply these checks after frame admission and before backend dispatch:

1. Match the backend identity to the sealed registry identity.
2. Find the authenticated plan handle in the sorted registry.
3. Match the opcode and result shape.
4. Enforce the plan result-byte and row limits.
5. Enforce the plan batch-operation limit.
6. Enforce the required batch capability for a multi-item operation.
7. Dispatch the validated operation to the backend.

Refuse before dispatch when any check fails.
Do not convert an unknown handle into SQL or another readable query language.
Do not create or modify plans in the execution path.

## 8. Error classes

| Class | Meaning |
|---|---|
| `CapabilityMismatch` | The manifest or plan contains unsupported capabilities. |
| `DuplicatePlan` | Two plans use the same handle. |
| `PlanLimitExceeded` | A registry, plan, request, or batch exceeds a registered limit. |
| `PlanNotRegistered` | The authenticated handle is absent. |
| `PlanRegistryEmpty` | The registry contains no plan. |
| `PlanRegistryMismatch` | The backend identity differs from the registry identity. |
| `PlanShapeMismatch` | The opcode or result shape differs from the registered plan. |
| `RegistryGeneration` | An activation or discovery generation is stale. |
| `RegistryInactive` | The digest is not the active registry. |
| `RegistryRevoked` | The digest appears in the revocation set. |
| `RegistryStoreAuthenticationFailed` | The persisted snapshot fails authentication or canonical decoding. |
| `RegistryStoreInsecure` | File or directory permissions permit unauthorised access. |
| `RegistryStoreIo` | Secure file access or persistence failed. |
| `RegistryStoreLockUnavailable` | Another process owns the registry store. |

## 9. Remote discovery

The discovery frame contains the registry generation, expiry, backend identity, capabilities, and complete registered plan records.
It contains no SQL, collection name, database name, policy text, or executable code.

The discovery frame contains `152 + 96N` bytes for `1 <= N <= 4096`.
All multibyte integers use little-endian encoding.

| Offset | Width | Field |
|---:|---:|---|
| 0 | 4 | magic `NDRG` |
| 4 | 2 | registry major version |
| 6 | 2 | registry minor version |
| 8 | 8 | registry generation |
| 16 | 8 | discovery expiry in Unix microseconds |
| 24 | 4 | engine identifier |
| 28 | 4 | profile identifier |
| 32 | 8 | capability bits |
| 40 | 4 | plan count `N` |
| 44 | 4 | plan-record bytes, fixed at 96 |
| 48 | 4 | complete frame bytes |
| 52 | 4 | zero reserved bytes |
| 56 | 32 | authority context digest |
| 88 | 32 | registry digest |
| 120 | `96N` | sorted registered plan records |
| `120 + 96N` | 32 | authentication tag |

Each discovery plan record uses the registry digest field order.
Insert two zero reserved bytes after the `u16` opcode.

Authenticate the complete frame with keyed BLAKE3 under the existing session transport key.
Use `"ndabi/wire/v1/registry-discovery"` as the MAC domain.
Bind the frame to the authority context and registered backend identity.
Refuse mutation, expiry, identity drift, unknown capabilities, invalid plans, and registry digest drift.

The client MUST compare the discovered generation with trusted persistent state.
The current file store performs this comparison through `authorise_discovery`.

## 10. Persistence and revocation

The file store persists one active registry digest, one increasing generation, and up to 4,096 revoked digests.
It authenticates every snapshot byte and replaces each snapshot atomically.
It uses private files, a stable exclusive lock, `O_NOFOLLOW`, and a private parent directory.

Activation MUST use a generation greater than the stored generation.
A revoked digest MUST NOT become active again.
Revocation clears that digest when it is active.
Remote discovery MUST match the current stored generation and active digest.

The snapshot MAC cannot detect replacement with an older valid snapshot.
A production deployment MUST provide an external monotonic rollback anchor.

## 11. Security boundary

The trusted compiler MUST validate agent intent before it selects a handle.
The adapter MUST apply database permissions and row policies independently.
The adapter MUST bind every implementation digest to reviewed executable behaviour.
The deployment MUST protect session keys and registry administration.
The deployment MUST refuse stale or unapproved registry digests.

The current slice uses symmetric session authentication, not public registry signatures.
It does not implement remote administration or a production key provider.
The key-provider trait is an integration boundary, not production custody evidence.
An offline client can accept a previously discovered registry until that discovery expires.
It does not implement mutation or transaction plan constructors.

## 12. Evidence and exclusions

Forty-six Rust protocol tests cover deterministic sealing and all implemented pre-dispatch refusal classes.
One red-green test proves that an unknown handle reaches the backend when registry validation is disabled.
The restored validation refuses that handle before dispatch.
Another red-green test fails when both revocation guards are disabled and passes after restoration.
Every persisted snapshot bit is authenticated in the focused test.

No incremental-cost performance campaign is accepted.
The v0.1 campaign passed four of five processes before one wall-p95 failure.
The v0.2 and v0.3 repairs each passed three of five processes.
Across v0.3, median wall overhead measured 0.96% to 1.42%.
Median thread-CPU overhead measured 0.96% to 1.41%.
Allocation count and allocated bytes remained equal in every process.

The accepted v0.3 local Docker campaign executed fifteen registered PostgreSQL and Supabase-compatible RLS paths.
Every successful process used one data query and returned the exact complete result.
The campaign passed all registered refusal, RLS, JWT, write, and least-privilege gates.
The first v0.1 result was invalid because its source digest omitted imported validator modules.
The v0.2 source commitment became stale after the MongoDB harness changed the shared Cargo manifest.
The v0.3 source digest binds that closure after the shared Cargo manifest reached its final campaign shape.
The accepted MongoDB v0.1 campaign completed five registered executions against MongoDB 6.0.26.
Every MongoDB process returned 128 exact rows through one `find` and issued no `getMore`.
Every MongoDB registry, identity, handle, shape, limit, frame, replay, receipt, and read-only-user gate passed.
The White Tree registered profile returns the complete governed result in its focused test.
Registered database performance, network, production custody, memory, token, and energy remain unproved.
