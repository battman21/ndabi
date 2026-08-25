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
| A frame remained valid at its exact expiry | Refuse frames at or after their deadline | Exact-expiry tests |
| Restart replay state was caller-managed only | Add a durable replay contract and authenticated reference store | Reopen and red-green restart tests |
| Parsers lacked repeatable adversarial input coverage | Add a seeded mutation campaign for all three current parsers | 600,000-case release campaign |
| Ephemeral sessions needed a database write for every request | Rotate a derived key and authority generation after restart | Old-frame restart test |
| Database admission could advance before its query committed | Stage verification and commit replay state with the query | Rollback and committed-replay tests |
| A derived session key left an extra stack copy | Zeroise the transient derived-key buffer | Source audit and regression tests |
| Separate concurrency blocks measured database drift | Pair and rotate four arms inside each worker | v3.5 Linux campaign |
| Runner evidence trusted reported derived ratios | Recalculate every ratio from retained measurements | Ratio mutation tests |
| Campaign results remained under an ignored path | Retain raw reports, binaries, sources, and manifests | Evidence verifier |
| Pending work checked handles but not the exact authentication key | Add a constant-time binding tag | Same-identity key-confusion test |
| The gateway repeated session fields in every request | Bind them once and authenticate a 56-byte execute frame | Compact verifier tests |
| A changed result receipt could reach the caller | Recalculate the receipt before accepting the response | Receipt mutation test |

## 3. Verified state

The current execution profile remains read-only.
It reserves the write bit but refuses it.
The borrowed decoders still avoid parameter allocations.
The current source zeroises transient keyed-BLAKE3 state after each tag calculation.

The local RustSec database reported no known dependency vulnerability.
Its latest local commit has the date 2026-08-18.
The network refresh failed, so this dependency result is not current proof.

The PostgreSQL replay table is logged.
The adapter updates the nonce and reads the data in one transaction.
Backend termination before commit leaves no nonce.
A committed nonce refuses the same request.

## 4. Unproved boundaries

The implementation has no production key manager, TLS profile, capability resolver, or trusted rollback anchor.
The result receipt is a deterministic benchmark digest, not a signature.
The code has no coverage-guided fuzzing, independent cryptographic review, or deployed side-channel test.

The reference replay store supports one local writer.
It has no multi-node coordination.
The v3.5 durable performance result failed its repeatability gate.

The benchmark derives keys from fixed research secrets.
This proves protocol behaviour, not production key custody.
The crash proof covers one PostgreSQL rollback point only.

The evidence manifests have hashes but no external signature or transparency anchor.
An attacker who can change both evidence and manifests can forge local custody.

The v3.5 archived source reproduced the retained Linux binary exactly.
The v3.4 source candidate did not reproduce its binary, so its custody remains incomplete.
The v4.0 gateway passed changed-frame, replay, cross-session, and read-only-role checks in all five processes.
Its fixed research key and 128-bit tag do not prove production key custody or a reviewed cryptographic profile.
The v4.1 embedded profile also refused changed, replayed, cross-session, and expired frames in all five processes.
Its staged verifier committed replay state only after successful database execution.

## 5. Next gates

1. Run coverage-guided fuzzing with sanitiser and coverage evidence.
2. Define the server capability resolver and trusted rollback anchor.
3. Inject crashes across every file, process, database, and power boundary.
4. Measure TLS, concurrency, CPU, memory, and controlled network delay.
5. Design writes as a separate idempotent admission protocol.

## 6. Verification result

The isolated workspace passes formatting and Clippy with warnings denied.
All 239 Rust tests and 91 Python tests pass.
The evidence verifier validates all 25 manifests and reports incomplete custody honestly.

The seeded release campaign refused 300,000 malformed frames and 300,000 authenticated mutations.
It also completed 15 replay-state checks.

Disabling volatile commit advancement made its focused test fail.
Removing the pending binding-tag check made its same-identity key-confusion test fail.
Both tests passed after restoration.
