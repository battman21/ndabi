# NDABI MongoDB closed-evidence campaign v5.6

## 1. Purpose

Close the v5.5 validator gap without changing the binary operation or performance targets.
Require the command proof to exist in every process report.
Require each report to match the frozen campaign shape.

## 2. Frozen execution

Use the v5.5 literal byte comparisons, single-batch adapter, six comparison arms, and eight refusals.
Use MongoDB 6.0.26, one million deterministic documents, five processes, and four batch sizes.
Use the same 76-byte binary instruction and the same performance gates.

## 3. Closed evidence gates

Require every report to identify campaign v5.6, one million rows, and a 76-byte frame.
Require every report to contain batches 1, 8, 32, and 128 exactly once.
Require every process to compare complete bytes across all arms and two executions.
Require exactly one observed `find` command and zero observed `getMore` commands.
Require all eight refusal checks to pass.

Require at least 60% request compression.
Require median typed p95 within 15% of native set p95 at batches 32 and 128.
Require 5 times sequential JSON speed at batch 32 and 20 times speed at batch 128.
Require typed allocated bytes within 5% of native set bytes at batch 128.

Reject a missing field, extra batch, duplicate batch, failed deterministic flag, or failed command proof.
Reject the campaign after any failed gate.
Do not weaken a failed gate or replace the result under this version.

## 4. Attribution and boundaries

Attribute the large gain to a fused operation and one engine round trip.
Attribute request compression to the non-human-readable frame.
Do not claim that binary decoding alone makes MongoDB faster.

This campaign proves one bounded lossless read operation through local Docker.
It does not prove all MongoDB functions, writes, transactions, sharding, Atlas, WAN behaviour, model tokens, energy, or production custody.
