# NDABI canonical replay profile v0.1

Status: implemented research slice.

## 1. Purpose

Persist the last accepted canonical NDABI read nonce across process restarts.
Prevent a restarted process from accepting an already completed frame.

## 2. Storage contract

Store records by context digest, session, and generation.
Authenticate the complete canonical snapshot with a dedicated 256-bit keyed BLAKE3 tag.
Write a temporary private file, synchronise it, rename it atomically, and synchronise the parent directory.
Use a stable private lock file to permit one writer.
Refuse relative paths, symbolic-link targets, weak file permissions, and weak directory permissions.

## 3. Execution contract

Read the last nonce before backend dispatch.
Commit the next exact nonce only after a successful read execution.
Do not consume a nonce after backend failure, output-budget failure, or deadline failure.

## 4. Boundaries

The store protects integrity, process exclusion, and restart continuity.
It does not detect rollback to an older valid snapshot without an external trusted anchor.
It does not make database writes atomic with replay-state commitment.
The canonical protocol remains read-only.
