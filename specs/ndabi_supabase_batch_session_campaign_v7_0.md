# NDABI Supabase batch-session campaign v7.0

Status: frozen before the first formal campaign.

## 1. Purpose

Measure one authenticated NDABI batch instruction against repeated PostgREST operations.
Keep eight rows in each logical range operation.
Measure batches of 2, 8, and 16 logical operations.
Execute each NDABI batch through one prepared PostgreSQL query.
Return one packed PostgreSQL binary result.

## 2. Equal authority and work

Retain the v6.9 ES256, RLS, least-privilege, refusal, and exactness gates.
Retain one million database rows.
Use identical ordered range starts and row values in both arms.
Use one persistent PostgREST client and one dedicated NDABI database session.
Require complete canonical batch equality after every operation.
Require one PostgreSQL result row per NDABI batch.

## 3. Measurements

Retain 7 warm-ups, 63 rotated samples, and five fresh processes.
Record wall p50, p95, and p99.
Record the client-thread CPU and Rust allocations as diagnostics.
Record request bytes and database query counts.
Do not compare the client-thread CPU as complete-stack CPU.

## 4. Hard gates

Require every security, exactness, query-count, byte, and evidence gate.
Require NDABI median wall time at most 0.35 times PostgREST for 8-operation and 16-operation batches.
Require each median wall ratio coefficient of variation below 10% across five processes.
Require at least 70% request-byte reduction for each batch.
Require the exact database query reduction of one minus one divided by the batch size.
Require at most 50 mean NDABI allocations for each 16-operation process.
Require at most 60,000 mean allocated NDABI bytes for each 16-operation process.
Treat the two-operation ratio and every tail ratio as diagnostics.
Use identical floor-index percentile calculation in the producer and validator.

## 5. Source custody

Run the formal campaign only after every registered source file exists in `HEAD` with identical bytes.
Record the complete source commit in the aggregate result.
Refuse the campaign when any registered source file differs from `HEAD`.
Build the release binary from those committed source bytes inside the formal runner.
Commit campaign results separately from the frozen source commit.

## 6. Boundaries

This campaign proves one finite homogeneous batch profile.
It does not claim that one database query runs faster than the PostgreSQL floor.
It measures the removed repeated stack work.
It applies to direct PostgreSQL and Supavisor session mode.
It does not apply to Supavisor transaction mode.
The batch uses the canonical authenticated v0.1 frame and keyed execution receipt.
The v0.2 transport binding remains untested for this batch profile.
It does not prove hosted Supabase, TLS, WAN, tokens, energy, revocation latency, or production key custody.
