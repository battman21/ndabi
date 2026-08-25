# NDABI PostgreSQL write-admission campaign v5.1

Status: frozen before the first formal campaign.

## 1. Purpose

Prove a separate, finite NDABI write-admission class.
Do not add arbitrary SQL or reuse read authority for writes.

## 2. Protocol

Bind the access class into session key derivation and authenticated frame flags.
Use a write-only compare-and-swap operation with record identifier, expected version, and new value.
Execute one caller-supplied prepared PostgreSQL update.
Return the committed identifier, version, and value with a session receipt.

## 3. Safety gates

Require a read authority to refuse every write frame.
Require changed frames, replay, stale expected versions, expired deadlines, and excessive result budgets to refuse.
Require a replay or stale version to leave the row unchanged.
Require backend failure to preserve the session nonce for an exact retry.
Require write authority and prepared SQL to have no arbitrary command representation.

## 4. Campaign

Run five fresh PostgreSQL client processes against one digest-pinned local PostgreSQL 16 container.
Reset the row before each process.
Require every process to pass all safety gates and finish at the exact expected row version and value.

Reject the campaign after any failed gate.
Do not replace a failed result with a later v5.1 run.

## 5. Boundaries

This campaign proves one local PostgreSQL compare-and-swap write profile.
It does not prove general writes, multi-row transactions, distributed commit, conflict retries, MongoDB writes, Supabase user writes, or production authority custody.
