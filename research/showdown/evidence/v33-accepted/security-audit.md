# NDABI security and logic audit v0.1

**Status:** IMPLEMENTED RESEARCH HARDENING. **Date:** 2026-08-22.

## 1. Scope

This audit covers the core frames, the column profile, the PostgreSQL adapter, and the evidence verifier.
It does not approve NDABI for production use.

The threat model includes untrusted frames, replay, expired authority, budget escalation, malformed evidence, and accidental key disclosure.
The agent does not hold the frame authentication key.
The server resolves authority before execution.

## 2. Fixed findings

| Finding | Repair | Test |
|---|---|---|
| Binding debug output exposed the frame key | Redact debug output and zeroise the stored key | Secret redaction tests |
| A restarted verifier started its nonce at zero | Require the caller to supply the restored nonce | Restart replay tests |
| Frames could exceed server-held deadlines and budgets | Bind both limits to the server session | Escalation refusal tests |
| The PostgreSQL adapter did not enforce result bytes | Refuse an oversized result after canonical encoding | Result budget test |
| Parsers returned semantic errors before authentication | Authenticate bounded frames before semantic inspection | Uniform authentication tests |
| Tag comparison used local comparison code | Use `subtle::ConstantTimeEq` | Complete authenticated-byte tests |
| The evidence verifier omitted one retained manifest | Discover all manifests and report incomplete custody | Evidence registry tests |
| Evidence paths could escape their declared roots | Resolve paths and refuse custody-root escapes | Path escape test |
| The campaign runner trusted incomplete JSON structure | Validate cases, arms, samples, and percentiles | Runner mutation tests |

## 3. Verified state

The current execution profile remains read-only.
It reserves the write bit but refuses it.
The borrowed decoders still avoid parameter allocations.

The local RustSec database reported no known dependency vulnerability.
Its latest local commit has the date 2026-08-18.
The network refresh failed, so this dependency result is not current proof.

## 4. Unproved boundaries

The implementation has no production key manager, TLS profile, capability resolver, or durable nonce store.
The result receipt is a deterministic benchmark digest, not a signature.
The code has no fuzzing campaign, independent cryptographic review, or deployed side-channel test.

The evidence manifests have hashes but no external signature or transparency anchor.
An attacker who can change both evidence and manifests can forge local custody.

## 5. Next gates

1. Add property fuzzing for every parser and state transition.
2. Define the server capability resolver and durable replay-store contract.
3. Run the hardened client inside pinned Linux containers.
4. Measure TLS, concurrency, CPU, memory, and controlled network delay.
5. Design writes as a separate idempotent admission protocol.

