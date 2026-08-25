# NDABI registered MongoDB campaign v0.1

**Status:** Frozen before the first formal campaign.

## 1. Purpose

Prove one sealed MongoDB profile against a fresh authenticated Docker engine.
Prove exact results, single-command execution, least privilege, and pre-dispatch refusal.
Do not compare performance in this campaign.

## 2. Environment

Use the digest-pinned MongoDB 6.0.26 image.
Publish MongoDB on an automatically selected loopback port.
Create one generated ephemeral database containing 256 deterministic documents.
Remove the complete container after every outcome.

## 3. Authority

Create one database-scoped read-only user.
Require that user to read all fixture documents.
Require a direct write from that user to fail.
Never supply root credentials to the measured process.

## 4. Registered execution

Use registered MongoDB profile `0x4d471002`.
Use one sealed identifier-window plan containing no caller-supplied command or field name.
Wrap the live backend with `RegisteredBackend`.
Read 128 identifiers through one projected and sorted single-batch query.
Require one `find` command and zero `getMore` commands.

## 5. Refusal gates

Require every process to refuse these conditions before another database command:

- A changed registry.
- A legacy backend identity.
- An unknown plan handle.
- A changed result shape.
- Limits above the registered plan.
- An authenticated-frame mutation.
- A replayed request.

## 6. Acceptance

Run five fresh client processes against one ephemeral engine.
Require exact result bytes, rows, SHA-256 digest, and receipt verification.
Require one registry digest across all processes.
Require every functional, refusal, command-count, and least-privilege gate.
Bind the producer, validator, protocol, adapter, lockfile, and specification into the source digest.

## 7. Boundaries

This campaign proves one finite MongoDB 6.0.26 read profile.
It does not prove MongoDB 8.x, arbitrary commands, pipelines, writes, hosted MongoDB, WAN, or production custody.
It proves no latency, CPU, memory, allocation, token, energy, or scaling improvement.
