# NDABI beta acceptance

**Current state:** Pre-beta candidate.

The beta must provide a safe, finite, and measurable interface for registered database operations.
It must not claim arbitrary query support or production key custody.

## Acceptance gates

| Area | Beta gate | Current state |
|---|---|---|
| protocol | conformance, replay, limits, exact receipts, and malformed-frame refusal pass | Rust, Go, and TypeScript pass shared frame, bundle-control, and sequence enforcement tests |
| PostgreSQL | one registered bundle profile passes five formal repetitions | v0.2 campaign not executed |
| Supabase | local Auth, forced RLS, exact results, and receipts pass | proven locally |
| MongoDB | real database execution reuses one static bundle decode | proven locally with MongoDB 8.0.4 |
| White Tree | governed bitemporal execution reuses one static bundle decode | proven in an external consumer commit |
| compression | the 1,024-item request is at least 70% smaller than the graph request | one smoke measured 74.23% |
| latency | mean and p95 remain within the v0.2 fused-native floors | one smoke passed; formal proof remains open |
| CPU | complete CPU and floor-adjusted protocol CPU pass v0.2 | one old smoke passes corrected mathematics |
| memory | bundle allocations do not exceed graph allocations | one smoke measured equal allocations |
| repeatability | five repetitions remain below 10% variation at every frozen cell | not executed |
| security | an independent review closes critical and high findings | not started |
| remote transport | authenticated TLS, cancellation, and failure behaviour pass a controlled network campaign | reusable TLS and external-signer paths pass focused tests; controlled campaign remains open |
| release custody | signed source tag, reproducible artefact digest, installation guide, and rollback guide exist | deterministic source-bundle tool and operator guide implemented; signed beta tag remains open |

## Supported beta surface

The beta supports only registered finite profiles.
It does not accept arbitrary SQL, MongoDB query documents, Supabase API requests, or White Tree operations.
Each adapter must publish its operation, operand, result, authority, and budget contract.

## Performance claim

The beta can claim request-byte compression after the v0.2 formal campaign passes.
It can claim protocol-overhead reduction only from floor-adjusted CPU evidence.
It can claim workflow speedups only when a registered operation removes database exchanges.
It must report complete latency, CPU, memory, and result verification beside every derived improvement.
