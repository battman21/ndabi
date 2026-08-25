# NDABI Supavisor concurrency campaign v7.6

Status: frozen before the first measured campaign.

## 1. Purpose

Repair the short NDABI measurement windows from v7.5.
Retain the workload shape, security gates, performance thresholds, and five-process repeatability limit.

## 2. Measured defect

The complete v7.5 campaign passed every individual process gate.
Its NDABI arms lasted only 18 to 136 milliseconds.
NDABI p95 variation dominated each failed p95-ratio coefficient.
PostgREST p95 variation remained lower at every concurrency level.

## 3. Stable measurement windows

Use 4,095 measured requests per NDABI worker.
Use 127 measured requests per PostgREST worker.
Retain three warm-up requests per worker.
Require every measured worker and arm to last at least one second.
Reject the campaign when any worker or arm misses this duration gate.

The request counts differ because the surfaces have materially different speeds.
Each request retains the same 16 logical operations and eight rows per operation.
Normalise throughput by completed logical operations and measured wall time.
Calculate latency percentiles from each surface's complete measured request set.

## 4. Workload and execution

Use concurrency levels 1, 8, and 32.
Give each worker a distinct indexed range.
Start all measured workers through one release barrier.
Run each surface separately.
Alternate the surface order across five processes.

## 5. Correctness and security

Compare complete canonical result bytes for every worker and surface.
Require one NDABI data query for each request.
Require sixteen PostgREST data queries for each request.
Run all seventeen v7.2 security checks through Supavisor before load testing.
Require the prepared-statement and session-value proof.
Require forced RLS and least privilege.

## 6. Performance gates

Require NDABI throughput at least three times PostgREST at concurrency one.
Require NDABI throughput at least six times PostgREST at concurrency eight and 32.
Require NDABI p95 latency at most 0.35 times PostgREST p95.
Require NDABI p95 below 25 milliseconds.
Apply every gate at every concurrency level and in every process.

## 7. Repeatability gates

Require five complete processes.
Require each throughput-ratio coefficient of variation below 15%.
Require each p95-ratio coefficient of variation below 15%.
Do not change the v7.5 thresholds after measurement.

## 8. Environment and custody

Use the pinned v7.5 PostgreSQL, PostgREST, and Supavisor images.
Retain equal 64-connection capacities and 200 maximum PostgreSQL connections.
Require no active compiler process before each measured arm.
Poll for compiler processes every 250 milliseconds during each measured arm.
Reject an arm when the monitor finds a compiler process or probe failure.
Record three host CPU-idle samples without an idle-percentage threshold.
Run only from committed registered source bytes.
Require a clean tracked worktree before and after the campaign.
Commit campaign evidence separately from the frozen source.

## 9. Resource boundaries

Record client thread CPU, allocations, allocated bytes, and peak additional live bytes.
Treat these measurements as client diagnostics only.
Do not claim service memory, energy, or complete-stack compute savings.

## 10. Scope boundaries

This campaign tests local Docker on macOS.
It tests Supavisor session mode and a local PostgREST user-JWT control path.
It does not test hosted Supabase, TLS, WAN delay, transaction mode, or geographic distribution.
It does not prove token savings, production key custody, general SQL, or general writes.
