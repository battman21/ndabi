# NDABI Supabase indexed-batch campaign v7.1

Status: frozen before the first formal campaign.

## 1. Repair

Retain the v7.0 authenticated homogeneous batch instruction.
Replace the database-side range join and aggregation with one indexed identifier-array query.
Encode the canonical batch result in the trusted client adapter.
Borrow each PostgreSQL binary payload during encoding.
Reserve the exact bounded output size.

## 2. Equal authority and work

Retain the v7.0 ES256, RLS, least-privilege, refusal, and exactness gates.
Retain batches of 2, 8, and 16 logical range operations.
Retain eight rows in each logical operation and one million database rows.
Use identical ordered identifiers and row values in both arms.
Require one prepared PostgreSQL query per NDABI batch.
Require complete canonical batch equality after every operation.

## 3. Measurements

Retain 7 warm-ups, 63 rotated samples, and five fresh processes.
Record wall p50, p95, and p99.
Record the client-thread CPU and Rust allocations as diagnostics.
Record request bytes, database queries, and PostgreSQL result rows.
Do not compare the client-thread CPU as complete-stack CPU.

## 4. Hard gates

Require every security, exactness, query-count, byte, and evidence gate.
Require NDABI median wall time at most 0.20 times PostgREST for 8-operation and 16-operation batches.
Require each median wall ratio coefficient of variation below 10% across five processes.
Require at least 70% request-byte reduction for each batch.
Require the exact database query reduction of one minus one divided by the batch size.
Require at most 200 mean NDABI allocations for each 16-operation process.
Require at most 100,000 mean allocated NDABI bytes for each 16-operation process.
Treat the two-operation ratio and every tail ratio as diagnostics.
Use identical floor-index percentile calculation in the producer and validator.

## 5. Source custody

Run the formal campaign only after every registered source file exists in `HEAD` with identical bytes.
Record the complete source commit in the aggregate result.
Refuse the campaign when any registered source file differs from `HEAD`.
Build the release binary from those committed source bytes inside the formal runner.
Recheck every registered source file before the acceptance decision.
Commit campaign results separately from the frozen source commit.

## 6. Boundaries

This campaign proves one finite homogeneous batch profile.
It measures removed repeated stack work, not a faster individual database query.
It applies to direct PostgreSQL and Supavisor session mode.
It does not apply to Supavisor transaction mode.
The batch uses the canonical authenticated v0.1 frame and keyed execution receipt.
The v0.2 transport binding remains untested for this batch profile.
It does not prove hosted Supabase, TLS, WAN, tokens, energy, revocation latency, or production key custody.
