# NDABI replay-state profile v0.1

**Status:** IMPLEMENTED RESEARCH PROFILE. **Date:** 2026-08-22.

## 1. Purpose

This profile prevents an accepted frame from becoming valid again after a process restart.
It defines the required store behaviour, not one production storage engine.

## 2. Replay identity

A replay identity contains the profile, session, capability, schema, and authority generation.
All five values must be non-zero.
The profile prevents nonce collisions between different NDABI wire formats.

## 3. Admission sequence

1. Authenticate and validate the complete frame.
2. Refuse an expired frame.
3. Refuse a nonce that does not exceed the volatile nonce.
4. Atomically persist the greater nonce for the replay identity.
5. Return accepted work only after the durable operation completes.

The verifier must restore its volatile nonce after a persistence failure.
The verifier must fail closed when the store reports replay, corruption, lock loss, or an input/output error.

This order gives at-most-once admission after a durable commit.
A crash after the commit can lose work, but it cannot make the frame valid again.

## 4. Coupled database transaction

A database adapter can couple the nonce update and the query in one transaction.
It must use this order:

1. Authenticate and validate the complete frame without changing volatile state.
2. Start the database transaction.
3. Atomically advance the durable nonce inside that transaction.
4. Execute the query and create the canonical result inside that transaction.
5. Commit the database transaction.
6. Advance volatile state and return the result.

Rollback must remove the nonce update and query effects together.
A crash after commit can lose the response, but the durable state must refuse replay.
The staged work must remain bound to the original authority identity and authentication key.

## 5. Store contract

The store must provide these operations:

- Return the last durable nonce for one replay identity.
- Atomically replace that nonce with a strictly greater nonce.
- Refuse zero, equal, and lower nonces.
- Preserve the last complete state after a process or power interruption.
- Serialise competing writers for the same store.
- Refuse unauthenticated or non-canonical state.

The production service can use a database transaction, a write-ahead log, or a monotonic state service.
The selected implementation must preserve the same observable contract.

## 6. Reference file store

The POC provides a correctness reference for one local writer.
It uses a stable exclusive lock file and one canonical snapshot.
It writes a private temporary file, synchronises it, renames it atomically, and synchronises the parent directory.

The snapshot uses this canonical structure:

| Field | Bytes | Rule |
|---|---:|---|
| magic and version | 8 | `NDRP`, version 1, and zero reserved bytes |
| record count | 4 | Maximum 65,536 |
| total bytes | 4 | Exact snapshot length |
| keyed BLAKE3 tag | 32 | Authenticate the header and every record |
| sorted records | 32 each | Unique replay identity and non-zero nonce |

The file and lock permissions must exclude group and other access.
The implementation refuses symbolic-link targets through `O_NOFOLLOW`.
The store key is redacted from debug output and zeroised on drop.

## 7. Ephemeral restart profile

An ephemeral session can avoid a durable nonce write for each request.
The authority owner must rotate the secret and generation after every restart.
Every old frame must then fail authentication before replay-state inspection.

This profile does not survive a restart.
It is unsuitable when a client needs to resume an issued frame after restart.

## 8. Security boundary

The reference store detects corruption and unauthorised changes without the store key.
It does not prevent an attacker from restoring an older valid snapshot.
A production deployment needs a trusted monotonic anchor to prevent disk rollback.

The file store serialises all identities through one writer.
It is a correctness reference, not a performance result or a production scale design.

## 9. Conformance gates

An implementation must pass these gates:

1. Accept a greater nonce and recover it after reopening.
2. Refuse equal and lower nonces after reopening.
3. Refuse a second concurrent owner.
4. Refuse every single-byte snapshot mutation.
5. Refuse weak permissions, relative paths, and symbolic-link targets.
6. Leave the volatile nonce unchanged after persistence failure.
7. Prove the restart test fails when durable advancement is disabled.
8. Prove a coupled transaction rollback leaves no accepted nonce.
9. Prove a committed transaction refuses the same nonce.
10. Prove an ephemeral restart refuses the old frame.

## 10. Unproved work

The POC has no trusted rollback anchor or multi-node replay service.
The POC terminates one PostgreSQL backend before commit.
It does not inject crashes across every file, process, database, and power boundary.
The v3.5 campaign measured durable admission, but its repeatability gate failed.
