# NDABI PostgreSQL repaired-adapter campaign v4.3

Status: frozen before the first formal campaign.

## 1. Purpose

Repeat the complete v4.2 campaign after the security and logic audit.
Use the same dataset, operations, arms, samples, gates, Docker environment, and validation rules.

## 2. Required repairs

Refuse a frame at its exact deadline.
Refuse an identifier range that overflows `i64`.
Return a typed refusal when PostgreSQL row decoding finds an unexpected type.

Keep replay commitment after successful backend execution and result-budget validation.
Require red-green proof for deadline equality and backend-failure replay state.

## 3. Gates

Apply every registered v4.2 correctness, security, latency, CPU, allocation, compression, and identity gate.
Require five complete Linux ARM64 client processes with zero exits.
Require the repaired adapter unit and clippy suites to pass.

Reject the campaign after any failed gate.
Do not replace a failed result with a later v4.3 run.

## 4. Boundaries

This repair campaign does not add TLS, WAN, MongoDB, hosted Supabase, tokens, energy, or production key custody.
It does not unify the separate White Tree NDABI profile.
