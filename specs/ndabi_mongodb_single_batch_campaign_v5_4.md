# NDABI MongoDB single-batch campaign v5.4

## 1. Purpose

Test a non-human-readable execution operation that fuses many logical reads into one MongoDB command.
Keep the operation finite, authenticated, lossless, and independent from MongoDB command syntax.
Measure the full governed path, not only the 76-byte frame decoder.

## 2. Frozen environment

Use the digest-pinned MongoDB 6.0.26 image from campaign v5.3.
Create exactly 1,000,000 deterministic documents with an indexed signed 64-bit `_id`.
Run five independent benchmark processes against one prepared local Docker database.

## 3. Operation profile

Use one authenticated 76-byte NDABI frame.
Encode only the operation identifier, first identifier, item count, and positive stride.
Permit batch counts of 1, 8, 32, and 128.
Refuse invalid counts, arithmetic overflow, out-of-range identifiers, writes, and unknown operations.

The frame must not contain JSON, BSON, MongoDB commands, collection names, field names, or query text.
The trusted adapter must lower the operation into one ordered indexed MongoDB set query.
The query must set a negative limit and close after its first server batch.

## 4. Comparison arms

Measure these six arms for every batch size:

1. Native sequential typed MongoDB point reads.
2. Equal-security human-readable JSON with sequential point reads.
3. Equal-security human-readable JSON with one typed set query.
4. Native typed MongoDB set execution.
5. NDABI with one typed set query.
6. NDABI with one ordinary raw-BSON cursor as a diagnostic only.

Every arm must return identical ordered canonical bytes.
The JSON and NDABI arms must apply equal authority, replay, deadline, budget, and receipt checks.

## 5. Measurement

Record request bytes, response bytes, median, p95, p99, p99.9, throughput, thread CPU, allocations, allocated bytes, and peak live bytes.
Use ten balanced measurement blocks after warmup.
Retain every raw process report, aggregate value, source digest, binary digest, and image identifier.

## 6. Frozen gates

Require every process to pass exact-result and deterministic-encoding checks.
Require all eight refusal checks to pass.
Require at least 60% request compression against the equal-security JSON set request.
Require the five-process median NDABI typed p95 to remain within 15% of native set p95 at batches 32 and 128.
Require the five-process median NDABI typed path to beat sequential JSON by 5 times at batch 32.
Require the five-process median NDABI typed path to beat sequential JSON by 20 times at batch 128.
Require NDABI typed allocated bytes to remain within 5% of native set bytes at batch 128.

Treat the ordinary raw-BSON cursor only as a diagnostic.
Do not use that cursor as a production profile without a later accepted campaign.
Reject the campaign after any failed gate.
Do not weaken a failed gate or replace the result under this version.

## 7. Attribution

Attribute the large latency gain to operation fusion and one engine round trip.
Attribute request-byte savings to the binary instruction format.
Report NDABI overhead against native set execution separately.
Do not attribute database latency gains to binary decoding alone.

## 8. Boundaries

This campaign tests one bounded read operation on MongoDB 6.0.26 through local Docker.
It does not prove all MongoDB functions, writes, transactions, sharding, Atlas, WAN behaviour, model tokens, energy, or production custody.
