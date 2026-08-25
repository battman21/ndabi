# NDABI Supavisor concurrency campaign v7.5

Status: frozen before the first measured campaign.

## 1. Purpose

Repair the unreliable macOS idle-percentage gate from v7.3 and v7.4.
Retain the frozen concurrent workload, security gates, and performance targets.
Compare pooled NDABI with the PostgREST user-JWT control path.

## 2. Environment repair

Retain the pinned PostgreSQL, PostgREST, and Supavisor images from v7.4.
Retain equal 64-connection capacities and 200 maximum PostgreSQL connections.
Require no active `cargo`, `cargo-tauri`, `clang`, `rustc`, or `swiftc` process.
Record three host CPU-idle samples before each measured arm.
Do not gate on the idle percentage because macOS background services made that value unreliable.

The absolute NDABI p95 gate rejects a slow run.
The paired speed gates reject unequal relative performance.
The five-process coefficient gates reject unstable relative performance.

## 3. Prior administrative failures

The v7.3 attempt refused before all measurements because the host never reached 80% idle.
The first v7.4 attempt retained one passing process before a separate compiler started.
The second v7.4 attempt refused before saving a process.
No accepted v7.3 or v7.4 concurrency result exists.

## 4. Equal work

Use concurrency levels 1, 8, and 32.
Execute 16 logical operations per request and eight rows per operation.
Execute three warm-ups and 31 measured requests per worker.
Give each worker a distinct indexed range.
Start all measured workers through one release barrier.
Compare complete canonical result bytes for each worker and surface.
Run each surface separately and alternate their order across five processes.

## 5. Query, security, and completion gates

Require every worker to return 31 complete measured requests.
Require NDABI to execute one data query per request.
Require PostgREST to execute 16 data queries per request.
Run all seventeen v7.2 security checks through the pooled connection before load testing.
Require the prepared-statement and session-value proof through Supavisor.
Require all returned row bytes and digests to match.

## 6. Hard performance gates

Require NDABI throughput at least three times PostgREST at concurrency one.
Require NDABI throughput at least six times PostgREST at concurrency eight and 32.
Require NDABI p95 latency at most 0.35 times PostgREST at every concurrency level.
Require NDABI p95 below 25 milliseconds at every concurrency level.
Require throughput-ratio and p95-ratio coefficients of variation below 15% across five processes.

## 7. Resource diagnostics

Record client thread CPU, allocations, allocated bytes, and peak additional live bytes.
Treat these values as diagnostics because each worker uses a separate process.
Do not claim comparative service memory savings from these values.

## 8. Source custody

Run the measured campaign only from committed registered source bytes.
Require a clean tracked worktree before and after the campaign.
Build the release binary from those bytes inside the runner.
Commit the campaign results separately from the frozen source commit.

## 9. Boundaries

This campaign tests local Docker on macOS.
It does not test hosted Supabase, TLS, WAN delay, transaction mode, or geographic distribution.
It does not prove production key custody, token savings, energy savings, or general SQL performance.
