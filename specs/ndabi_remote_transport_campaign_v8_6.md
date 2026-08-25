# NDABI remote transport campaign v8.6

Status: candidate preregistration.
Freeze this document with the implementation before performance measurement.

## 1. Purpose

Replace the v8.4 Python delay proxy.
Measure protocol overhead and stack compression as separate effects.
Use kernel network emulation around a real Supabase-compatible database workload.

## 2. Workload

Use one million PostgreSQL rows and forced row-level security.
Use sixteen indexed operations and eight rows per operation.
Return identical complete canonical result bytes from every arm.
Use persistent TLS 1.3 mutual authentication outside the measured request interval.
Measure handshake time separately.

## 3. Network boundary

Use `tc netem` inside an isolated Linux Docker network namespace.
Apply delay, jitter, loss, and bandwidth limits to packets, not application reads.
Record the effective network configuration with every report.
Docker Desktop provides a Linux virtual machine, not physical Linux evidence.

| Condition | RTT | Jitter | Loss | Bandwidth |
|---|---:|---:|---:|---:|
| Local | 0 ms | 0 ms | 0% | Unlimited |
| Metro | 10 ms | 1 ms | 0% | 1 Gbit/s |
| Regional | 50 ms | 5 ms | 0.05% | 100 Mbit/s |
| Long-haul | 100 ms | 10 ms | 0.10% | 25 Mbit/s |

## 4. Arms

| Arm | Requests | Database queries | Purpose |
|---|---:|---:|---|
| NDABI fused | One binary batch | One set query | Measure the complete NDABI path |
| JSON fused | One concise JSON batch | One set query | Isolate binary encoding cost |
| PostgREST concurrent | Sixteen concurrent HTTP requests | Sixteen queries | Compare the best parallel conventional path |
| PostgREST sequential | Sixteen sequential HTTP requests | Sixteen queries | Compare the dependent conventional path |

Use the same JWT identity, RLS policy, result shape, deadline, and receipt work.
Do not compare unequal security or incomplete results.

## 5. Sampling

Run five qualified repetitions for every condition and arm.
Collect at least 1,000 complete operations per arm.
Run every arm for at least sixty seconds.
Interleave arm order with a fixed Latin square.
Record p50, p95, p99, throughput, CPU, allocations, bytes, packets, retransmissions, and database queries.

Refuse active compilers and concurrent benchmark campaigns before measurement.
Monitor the complete interval.
Record source, binary, lockfile, image, network, and campaign digests.

## 6. Acceptance gates

Apply every gate within every repetition and network condition.

| Metric | Gate |
|---|---:|
| NDABI p95 over fused JSON | At most 1.05 |
| NDABI CPU over fused JSON | At most 1.05 |
| NDABI request bytes against fused JSON | At least 80% smaller |
| NDABI p95 over concurrent PostgREST | At most 0.67 |
| NDABI p95 over sequential PostgREST | At most 0.20 |
| NDABI database queries | Exactly one |
| P95-ratio variation | At most 10% |
| Exactness | Every declared result byte identical |

Do not claim binary speed from the PostgREST comparisons.
Attribute those gains to fusion, query reduction, and round-trip reduction.
Use only the fused JSON comparison for a binary-format speed claim.

## 7. Security

Require valid client and server certificates.
Refuse unknown trust, wrong names, expired certificates, revoked authority, changed frames, replays, changed results, and invalid receipts.
Verify receipts before result commitment.
Retain row-level security for every database arm.

## 8. Boundaries

This campaign is not a geographic internet measurement.
It does not prove production certificate custody, hosted Supabase behaviour, energy use, arbitrary SQL, or general writes.
Run a later cross-region campaign without changing these frozen workloads or controls.
