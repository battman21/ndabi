# NDABI canonical MongoDB binding campaign v6.0

Status: frozen before the first formal campaign.

## 1. Purpose

Test the canonical MongoDB identifier-window adapter against a fresh authenticated Docker engine.
Prove exact results, one-command fusion, least privilege, and refusal behaviour.

## 2. Engine fixture

Use the digest-pinned MongoDB 6.0.26 image from the accepted v5.7 campaign.
Start MongoDB with root authentication.
Create a generated campaign database and 256 deterministic documents.
Create a dedicated read-only application user for that database.
Require a direct application-user write to refuse.

## 3. Canonical operation

Use one 160-byte authenticated execute-handle frame.
Read 128 identifiers through one projected, sorted, single-batch query.
Require complete byte equality, 128 rows, a non-zero keyed receipt, one `find`, and zero `getMore` commands.
Require replay, frame mutation, and inadequate budget to refuse before another database query.

## 4. Campaign gates

Run five fresh client processes against one ephemeral engine.
Require every process and aggregate gate to pass.
Record source, binary, and image digests.
Remove the container after the campaign.

## 5. Boundaries

This campaign proves one finite MongoDB 6.0.26 read profile.
It does not prove MongoDB 8.x, arbitrary commands, pipelines, writes, production credentials, or hosted MongoDB.
It makes no new latency, token, memory, energy, or WAN claim.
