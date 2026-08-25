# NDABI POC preregistration v0.4

**Status:** FROZEN before the first v0.4 benchmark result. **Date:** 2026-08-21.

This experiment replaces complete application rehashing with an incremental lossless receipt tree.
It adds CPU, retained Rust memory and provider-token evidence. It preserves all earlier results.

## 1. Fixed database track

Keep the v0.3 database operation, bindings, formats, gates, targets and balanced microcycles.
Add thread CPU time and retained Rust buffer bytes. Do not reinterpret earlier database results.

## 2. Incremental application receipt

Use SHA-256 with explicit domain separation. Build ordered semantic and human-view Merkle trees.

Each semantic leaf commits to one task identifier, status, priority and exact title bytes. Each view
leaf commits to the exact rendered task fragment. The root commits to the revision and task count.

Stage changed leaves and affected parents in fixed-capacity memory. Verify both candidate roots before
changing client state. Commit the staged nodes only after every receipt field matches.

The local binding must produce the same roots without request or response serialisation. The tuned
and wire bindings must produce and verify the roots across their wire boundary.

Retain a full-tree rebuild as a diagnostic control. It must produce the same roots as the incremental
update. The incremental receipt target is at least 80% lower median CPU time for eight changes.

## 3. Compute and memory measurements

Measure wall median, wall p95 and thread CPU nanoseconds per operation. Keep Rust allocation count,
allocated bytes and peak additional live bytes.

Report retained Rust bytes for request, response, render and receipt-tree storage. Do not describe
this value as process RSS or total working-set memory.

The allocation counter excludes SQLite and provider internals. A zero allocation count does not mean
zero retained memory.

## 4. Model-token boundary

Use three model-facing forms for one fixed database operation:

1. Verbose named JSON.
2. A compact semantic handle and typed arguments.
3. Raw NDABI hexadecimal bytes with the necessary decoding dictionary.

Use the same decoding instruction and canonical expected answer. Accept a token result only when the
provider reports usage and the model returns the exact canonical answer.

Run providers through installed local subscription CLIs. Do not use API keys or metered API calls.
Record provider, model, CLI version, input, output, cache and total tokens when available.

The compact semantic form targets at least 30% fewer uncached input tokens than verbose JSON. Raw
hexadecimal has no savings target. It tests whether model-authored bytes are token-efficient.

Keep token canaries outside the default benchmark. Never let the loopback web server invoke a remote
model. Import a complete canary result for display.

## 5. Hard gates

All v0.3 gates remain. Add these gates:

1. Full and incremental receipt roots match exactly.
2. A wrong semantic root refuses before state change.
3. A wrong human-view root refuses before state change.
4. Incremental updates allocate no Rust heap memory in the measured loop.
5. Token evidence identifies provider-reported usage and exact semantic output.

Token unavailability does not invalidate the local execution tracks. It leaves the token claim
unproven for that provider.

## 6. Required disclosures

This remains a local POC benchmark. It does not prove production, network, accelerator, energy or
total process-memory performance. SQLite does not prove PostgreSQL, MongoDB, Supabase or White Tree.

The prototype format is not the NDABI RFC. A later isolated Linux run must measure hardware counters,
process RSS and confidence intervals before a production performance claim.
