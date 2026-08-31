# Why implement NDABI

NDABI is a bounded, authenticated, machine-native execution contract for agents and data engines.
It replaces repeated readable query construction with one verified numeric program and typed operands.

NDABI is not compressed SQL.
It preserves native database planning, permissions, indexing, and row policies.
Its value comes from semantic stack compression: fewer calls, decisions, copies, parsers, and intermediate results.

## Developer value

| Developer problem | NDABI answer | Practical payoff |
|---|---|---|
| Agents make many sequential calls | Express one complete bounded operation | Reduce latency and partial failure |
| Tool schemas consume model context | Use numeric capabilities and compact operands | Retain more context for user work |
| Every backend needs custom prompts | Give agents one machine-native protocol | Reduce integration duplication |
| Models can generate unsafe SQL | Verify typed instructions before lowering | Keep agent-authored SQL outside the engine |
| Supabase agents can cross user boundaries | Bind programs to JWT identity and forced RLS | Preserve existing row authority |
| APIs move excessive JSON | Use compact binary programs and results | Reduce bytes and parsing work |
| Repeated queries rebuild the same program | Promote verified programs to scoped handles | Send only changing operands |
| Agent actions are difficult to audit | Return an exact keyed receipt | Bind each request to its exact result |
| Schema changes can break prompts silently | Version and digest numeric catalogues | Refuse unsafe schema drift |
| Models need separate integrations | Generate adapters from one catalogue | Share one data surface across models |

## Practical workflow

A conventional agent can fetch identity, activity, decisions, evidence, and unresolved issues through separate requests.
Each request repeats transport, authentication, policy checks, parsing, and result assembly.

NDABI can represent that bounded workflow as one verified instruction graph:

```text
agent program
    -> authenticated authority envelope
    -> structural and capability verification
    -> one native backend execution
    -> canonical binary result
    -> exact receipt
```

The backend still performs necessary scans, joins, indexing, and planning.
NDABI removes avoidable application and network repetition around that work.

## Measured evidence

| Proven path | Measured result | Claim boundary |
|---|---:|---|
| PostgreSQL, 32-operation finite batch | 25.75 times repeated p95 | One local finite read profile |
| PostgreSQL, 128-operation finite batch | 73.99 times repeated p95 | One local finite read profile |
| PostgreSQL request reduction | 84.38% to 86.72% | Application request bytes |
| PostgreSQL median CPU speed-up | 21.54 to 47.47 times repetition | Same finite batch profile |
| Supavisor, concurrency 1 | 21.30 times repeated PostgREST | Local macOS Docker |
| Supavisor, concurrency 8 | 16.01 times repeated PostgREST | Local macOS Docker |
| Supavisor, concurrency 32 | 43.97 times repeated PostgREST | Local macOS Docker |
| Supavisor query reduction | 93.75% | Sixteen operations become one query |
| Supavisor application-frame reduction | At least 94.39% | Not measured TCP or TLS bytes |
| Dynamic cached frame | 72.48% below the full frame | Deterministic wire measurement only |
| Dynamic Supabase-compatible RLS smoke | 72.73% below the full frame | Local Docker correctness, not performance |

The large speed-ups come mainly from collapsing repeated work into one database operation.
Binary encoding makes that operation compact, deterministic, authenticated, and reusable.

The dynamic ISA has focused correctness proofs but no accepted performance campaign.
Corrected development smokes passed exact-result and compression gates, but failed the CPU gate.
The smoke host was not qualified, so these runs do not support a performance claim.
Do not claim dynamic latency, CPU, memory, token, energy, WAN, or hosted-service savings yet.

Refer to the following formal evidence:

- [`../research/showdown/results/v63/README.md`](../research/showdown/results/v63/README.md) for the PostgreSQL batch campaign.
- [`../research/showdown/results/v76/README.md`](../research/showdown/results/v76/README.md) for the Supavisor concurrency campaign.
- [`../specs/ndabi_dynamic_isa_candidate_v0_1.md`](../specs/ndabi_dynamic_isa_candidate_v0_1.md) for the dynamic frame contract.
- [`../specs/ndabi_dynamic_postgres_campaign_v0_1.md`](../specs/ndabi_dynamic_postgres_campaign_v0_1.md) for the frozen dynamic campaign.
- [`../specs/ndabi_dynamic_supabase_rls_campaign_v0_1.md`](../specs/ndabi_dynamic_supabase_rls_campaign_v0_1.md) for the two-user RLS campaign.

## Strong use cases

NDABI fits systems that perform repeated, bounded, policy-sensitive data work:

- Agent memory retrieval.
- Supabase AI applications with user row-level security.
- Enterprise knowledge and evidence retrieval.
- Security investigations.
- Customer support agents.
- Financial and operational analysis.
- Multi-agent systems.
- Local and private AI.
- High-volume agent platforms.
- Regulated or multi-tenant applications.

NDABI offers less value for one simple prepared query, low-volume human access, or database-dominated scans.
The current dynamic ISA also excludes writes and arbitrary code.

## Security value

The agent can choose approved relations, fields, filters, joins, aggregates, ordering, and result shapes.
The trusted runtime supplies identity, policy, capabilities, budgets, expiry, replay state, and authentication.

The agent cannot choose database credentials, SQL text, arbitrary identifiers, tenant identity, or unlimited resources.
This boundary provides dynamic composition without unrestricted database access.

## Developer experience target

The core protocol must pass its conformance, security, backend, and formal performance gates first.
Productisation must then remove custom integration work.

The target workflow is:

```sh
ndabi init
ndabi connect
ndabi scan
ndabi review
ndabi test
ndabi serve
```

The scanner must discover schemas, types, indexes, relationships, roles, RLS policies, and supported capabilities.
It must generate stable numeric handles, a readable review mapping, a binary catalogue, and native equivalence tests.

Humans review the control-plane mapping and authority boundary once.
Agents use the compiled binary catalogue in the execution path.

The product target is one clear outcome:

> Connect a database, review the discovered authority boundary, and give agents safe binary access within fifteen minutes.

The current repository does not implement this complete installer and scanner experience.
