# NDABI Supavisor concurrency campaign v7.3

Status: frozen before the first formal campaign.

## 1. Purpose

Test the accepted indexed-batch profile under concurrent Supavisor session load.
Compare pooled NDABI with the PostgREST user-JWT control path.
Determine whether the v7.2 speed gain survives simultaneous agent sessions.

## 2. Environment

Use one local Docker network.
Use the pinned PostgreSQL, PostgREST, and Supavisor images from v7.2.
Use one million indexed rows and the v7.1 ES256 identity boundary.
Configure 64 database connections for both measured surfaces.
Use the Supavisor session endpoint and 200 maximum client connections.
Set PostgreSQL `max_connections` to 200.
Require three consecutive host samples with at least 80% CPU idle before each measured arm.
Refuse the campaign when the host does not become quiet within five minutes.

## 3. Equal work

Use concurrency levels 1, 8, and 32.
Execute 16 logical operations per request and eight rows per operation.
Execute three warm-ups and 31 measured requests per worker.
Give each worker a distinct indexed range.
Start all measured workers through one release barrier.
Compare complete canonical result bytes for each worker and surface.
Run each surface separately and alternate their order across five processes.

## 4. Query and completion gates

Require every worker to return 31 complete measured requests.
Require NDABI to execute one data query per request.
Require PostgREST to execute 16 data queries per request.
Require every process to complete without worker errors or timeouts.
Require all returned row bytes and digests to match.

## 5. Security

Run all seventeen v7.2 security checks through the pooled connection before load testing.
Require least privilege, forced RLS, read-only access, replay refusal, and receipt verification.
Require the prepared-statement and session-value proof through Supavisor.
Fail closed when any security check fails.

## 6. Hard performance gates

Measure combined request latency and logical-operation throughput.
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

Run the formal campaign only from committed registered source bytes.
Build the release binary from those bytes inside the runner.
Recheck all registered source bytes before the acceptance decision.
Commit the campaign results separately from the frozen source commit.

## 9. Boundaries

This campaign tests local Docker on macOS.
It does not test hosted Supabase, TLS, WAN delay, transaction mode, or geographic distribution.
It does not prove production key custody, token savings, energy savings, or general SQL performance.
The speed source remains one authenticated binary request and one indexed query per 16-operation batch.
