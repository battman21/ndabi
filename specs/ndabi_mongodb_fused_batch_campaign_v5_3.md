# NDABI MongoDB fused-batch campaign v5.3

## 1. Purpose

Test whether one compact admitted operation can remove repeated MongoDB calls and human-shaped request work.
Keep execution semantics finite, authenticated, lossless, and independent from MongoDB command syntax.

## 2. Frozen environment

Use the digest-pinned MongoDB 6.0.26 image proven by v4.9.
Create exactly 1,000,000 deterministic documents with an indexed signed 64-bit `_id`.
Run five independent benchmark processes against one prepared local Docker database.

## 3. Operation profile

Use one 76-byte authenticated NDABI frame.
Encode only the operation identifier, first identifier, item count, and positive stride.
Permit batch counts of 1, 8, 32, and 128.
Refuse zero counts, counts above 128, arithmetic overflow, out-of-range identifiers, writes, and unknown operations.

The frame must not contain JSON, BSON, MongoDB commands, collection names, field names, or query text.
The trusted adapter must lower the operation into one ordered indexed MongoDB set query.

## 4. Comparison arms

Measure these six arms for every batch size:

1. Native sequential typed MongoDB point reads.
2. Equal-security human-readable JSON lowered into sequential point reads.
3. Equal-security human-readable JSON lowered into one typed set query.
4. Native typed MongoDB set execution.
5. NDABI lowered into one typed set query.
6. NDABI lowered into one raw-BSON set query.

Every arm must return identical ordered canonical bytes.
The two JSON arms and two NDABI arms must apply the same authority, replay, deadline, budget, and receipt checks.

## 5. Measurement

Record request bytes, response bytes, median, p95, p99, p99.9, throughput, thread CPU, allocations, allocated bytes, and peak live bytes.
Use ten balanced measurement blocks after warmup.
Retain every raw process report, aggregate values, source digest, binary digest, and image identifier.

## 6. Frozen gates

Require every process to pass exact-result and deterministic-encoding checks.
Require all eight refusal checks to pass.
Require at least 60% request compression against the equal-security JSON set request.
Require NDABI typed p95 to remain within 10% of native typed set execution for every batch size.
Require NDABI raw p95 to remain within 10% of native typed set execution for every batch size.
Require NDABI raw p95 at batch 32 and 128 to be at least five times faster than sequential JSON.
Require NDABI raw to allocate at least 30% fewer bytes than NDABI typed at batch 128.
Require the five-process median p95 ratios to pass the same gates.

Reject the campaign after any failed gate.
Do not weaken a failed gate or replace the result under this version.

## 7. Boundaries

This campaign tests one bounded read operation on MongoDB 6.0.26 through local Docker.
It does not prove arbitrary MongoDB commands, writes, transactions, sharding, Atlas, geographic WAN, provider tokens, or production custody.
