# NDABI MongoDB literal single-batch campaign v5.5

## 1. Purpose

Repair the v5.4 evidence defect without changing its performance targets.
Compare complete result bytes before timing.
Prove that the fused query sends one `find` command and sends no `getMore` command.

## 2. Frozen environment

Use the digest-pinned MongoDB 6.0.26 image from campaign v5.4.
Create exactly 1,000,000 deterministic documents with an indexed signed 64-bit `_id`.
Run five independent benchmark processes against one prepared local Docker database.

## 3. Binary operation

Use one authenticated 76-byte NDABI frame.
Encode only the operation identifier, first identifier, item count, and positive stride.
Permit batch counts of 1, 8, 32, and 128.
Refuse invalid counts, arithmetic overflow, out-of-range identifiers, writes, and unknown operations.

The frame must not contain JSON, BSON, MongoDB commands, collection names, field names, or query text.
The trusted adapter must lower the operation into one ordered indexed MongoDB set query.
The query must close after its first server batch.

## 4. Comparison arms

Measure native sequential reads, governed sequential JSON, governed JSON set execution, native set execution, typed NDABI, and diagnostic raw-BSON NDABI.
Every arm must return two complete byte-identical canonical results before timing.
The JSON and NDABI arms must apply equal authority, replay, deadline, budget, and receipt checks.

## 5. Measurement

Record request bytes, response bytes, median, p95, p99, p99.9, throughput, thread CPU, allocations, allocated bytes, and peak live bytes.
Use ten balanced measurement blocks after warmup.
Retain every raw report, aggregate value, source digest, binary digest, image identifier, and runner source.

## 6. Frozen gates

Require every process to compare complete bytes across all arms and two executions.
Require every process to observe exactly one `find` command and zero `getMore` commands for one fused batch.
Require all eight refusal checks to pass.
Require at least 60% request compression against equal-security JSON.
Require median typed NDABI p95 to remain within 15% of native set p95 at batches 32 and 128.
Require typed NDABI to beat sequential JSON by 5 times at batch 32.
Require typed NDABI to beat sequential JSON by 20 times at batch 128.
Require typed NDABI allocated bytes to remain within 5% of native set bytes at batch 128.

Treat the ordinary raw-BSON cursor only as a diagnostic.
Reject the campaign after any failed gate.
Do not weaken a failed gate or replace the result under this version.

## 7. Attribution and boundaries

Attribute the large latency gain to operation fusion and one engine round trip.
Attribute request-byte savings to the binary instruction format.
Report NDABI overhead against native set execution separately.

This campaign proves one bounded lossless read operation through local Docker.
It does not prove all MongoDB functions, writes, transactions, sharding, Atlas, WAN behaviour, model tokens, energy, or production custody.
