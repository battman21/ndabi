# NDABI remote model campaign v0.2

**Status:** Frozen candidate campaign. This document is not a public RFC.

## 1. Purpose

Measure the complete remote model boundary instead of only the query suffix.
Keep the human prompt byte-identical across all surfaces.
Keep the complete synthetic memory corpus outside the model only in the governed-recall surfaces.
Require every surface to return the same exact answer.

## 2. Surfaces

| Surface | Memory sent | Result envelope | Purpose |
|---|---:|---|---|
| `full_verbose` | Complete corpus | Verbose JSON | Current broad-context control |
| `selected_verbose` | Governed selection | Verbose JSON | Isolate context selection |
| `selected_semantic` | Governed selection | Compact semantic record set | Isolate the agent-facing envelope |

The compact envelope is not the NDABI wire frame.
The model-facing adapter converts an authenticated NDABI result into a token-efficient semantic record set.
Do not send hexadecimal bytes to the model.

## 3. Frozen fixture

Generate 256 synthetic memory records.
Exactly eight records satisfy the registered owner and score predicate.
Include the same stable instructions and human prompt in every request.
Hash the exact human prompt into the report.

## 4. Measurements

Record provider-reported total input, uncached input, cached input, output, and end-to-end elapsed time.
Record UTF-8 request bytes for the complete submitted prompt.
Run each surface twice in balanced order.
Treat cache use as a separate compute result, not a logical token reduction.

## 5. Gates

All returned identifier sequences MUST match the frozen answer exactly.
Whitespace and separators MAY differ in the human-readable presentation.
The human prompt hash MUST match across all surfaces.
The selected semantic surface MUST reduce complete input tokens by at least 30% against `full_verbose`.
The selected semantic surface MUST reduce submitted prompt bytes by at least 70%.
Report cache use when the provider exposes it.
Do not fail a provider only because it does not expose cache counters.

## 6. Boundaries

This campaign uses local subscription CLIs and real remote provider calls.
It does not prove a provider-native binary model interface.
It does not prove that omitted memory can never affect a different question.
White Tree must retain the complete source and perform the governed selection.
This campaign does not test TLS certificate custody or geographic WAN control.
