# NDABI dynamic ISA candidate v0.1

**Status:** Implemented vertical-slice target. This document is not a public RFC or production standard.

## 1. Purpose

The dynamic ISA is the primary NDABI execution language.
An agent composes a bounded numeric program for each data request.
The normal wire path contains no SQL, JSON keys, REST paths, relation names, or field names.

Registered plans remain an optional cache for repeated dynamic programs.
They do not define the complete language.

## 2. Execution boundary

The first slice defines read-only, acyclic relational programs.
It supports scan, filter, project, join, aggregate, sort, limit, and return instructions.
It carries parameter types but carries parameter values through a separate authenticated execution frame.

The verifier must accept a complete program before a backend can lower or execute it.
The database engine retains physical planning, indexing, isolation, and storage control.

## 3. Numeric schema

A trusted schema binds numeric relation and field handles to scalar types and capabilities.
Relation and field handles are non-zero and unique within one schema.
The schema digest binds every handle, type, nullability rule, and capability requirement.

Human-readable names belong only in a trusted backend catalogue or disassembler.
They never occur in the ISA program.

## 4. Program layout

All multibyte integers use little-endian encoding.
The program starts with one 64-byte header.

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | `NDIP` |
| 4 | 1 | major | `1` |
| 5 | 1 | minor | `0` |
| 6 | 2 | flags | zero |
| 8 | 4 | complete bytes | exact bounded length |
| 12 | 2 | instruction count | `1..=4096` |
| 14 | 2 | parameter count | `0..=4096` |
| 16 | 4 | declared work units | non-zero |
| 20 | 12 | reserved | zero |
| 32 | 32 | schema digest | exact trusted schema digest |

Each parameter descriptor contains eight bytes.
It contains a scalar type, zero flags, zero reserved bytes, and a maximum encoded width.

Each instruction starts with an eight-byte header.
The header contains an opcode, flags, payload-word count, and four zero reserved bytes.
Each payload word contains one `u32`.

Instruction output register `N` equals its one-based instruction index.
An instruction can reference only a lower register.
The final instruction must be the only `RETURN` instruction.
The ISA has no branch, loop, indirect call, pointer, or executable byte sequence.

## 5. Instructions

| Opcode | Instruction | Payload words | Flags |
|---:|---|---|---|
| 1 | `SCAN` | relation | zero |
| 2 | `FILTER` | input, field, parameter | comparison |
| 3 | `PROJECT` | input, field count, fields | zero |
| 4 | `JOIN` | left, right, left field, right field | join kind |
| 5 | `AGGREGATE` | input, field | aggregate function |
| 6 | `SORT` | input, term count, repeated field and direction | zero |
| 7 | `LIMIT` | input, parameter | zero |
| 8 | `RETURN` | input | zero |

Projection fields must be strictly increasing.
Sort fields must be unique.
Filters require an available field and an equal parameter type.
Ordered comparisons require an ordered scalar type.
Join fields must be available and have equal scalar types.
Limits require an unsigned integer parameter.

## 6. Dynamic operands

Parameter values use one compact block that binds the exact verified program digest.
The block starts with one 64-byte header.

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | `NDIV` |
| 4 | 1 | major | `1` |
| 5 | 1 | minor | `0` |
| 6 | 2 | flags | zero |
| 8 | 4 | complete bytes | exact bounded length |
| 12 | 2 | parameter count | exact program count |
| 14 | 18 | reserved | zero |
| 32 | 32 | program digest | exact verified program digest |

Each value contains a `u32` byte length followed by canonical bytes.
Fixed-width values must use their exact width.
Booleans use zero or one.
Floating-point values must be finite and must encode zero without a sign bit.
UTF-8 values must be valid and must not exceed their declared maximum width.

The operand block remains untrusted until an authenticated execution frame admits it.

## 7. Dynamic execution frame

The `NDBI` dynamic frame uses message kind five and read access.
Its first 128 bytes contain the authority, nonce, deadline, budgets, payload lengths, and context digest.
The verified program bytes follow the header.
The operand bytes follow the program.
A 32-byte keyed tag ends the frame.

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | `NDBI` |
| 4 | 2 | version | `1.0` |
| 6 | 1 | message kind | `5` |
| 7 | 1 | access | read |
| 8 | 4 | flags and reserved | zero |
| 12 | 4 | complete bytes | exact frame length |
| 16 | 16 | session and generation | exact authority |
| 32 | 8 | nonce | next replay nonce |
| 40 | 8 | deadline | within authority expiry |
| 48 | 8 | result-byte and row budgets | non-zero admitted limits |
| 56 | 8 | program and operand bytes | exact bounded lengths |
| 64 | 32 | reserved | zero |
| 96 | 32 | context digest | exact authority context |

The server authenticates the complete frame before it parses variable data.
The canonical capability digest binds the granted capability bits to the authority.

## 8. Dynamic result

The first executor returns one canonical row-major `NDIR` result.
Its 64-byte header binds the total bytes, row count, column count, and program digest.
Each eight-byte column descriptor contains a field handle and scalar type.
Scalar aggregate results use field handle zero.

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | `NDIR` |
| 4 | 2 | version | `1.0` |
| 6 | 2 | flags | zero |
| 8 | 4 | complete bytes | exact result length |
| 12 | 4 | row count | exact completed rows |
| 16 | 2 | column count | non-zero |
| 18 | 14 | reserved | zero |
| 32 | 32 | program digest | exact verified program |

Each row starts with a validity bitmap.
A zero bit represents SQL null and contributes no value bytes.
Fixed values use their ISA width.
Variable values use one `u32` length followed by exact bytes.
The receipt authenticates the complete request, result bytes, and row count.

## 9. Admission

The verifier must apply these checks before backend lowering:

1. Check the complete bounded length.
2. Check the magic, version, flags, and reserved bytes.
3. Match the trusted schema digest.
4. Check parameter descriptors and widths.
5. Decode every instruction with an exact payload shape.
6. Refuse unknown opcodes and flags.
7. Refuse forward, absent, or terminal register references.
8. Check field availability and scalar types.
9. Check relation and field capabilities.
10. Check canonical projection and sort terms.
11. Check declared and server work limits.
12. Require one final return instruction.

Successful verification returns an unforgeable program capability.
Backend APIs must accept that capability instead of unverified bytes.

## 10. Backend lowering

PostgreSQL lowers a verified program through a trusted numeric catalogue.
Cached receipts bind the authenticated request tag without hashing the frame again.
The catalogue maps numeric handles to validated SQL identifiers outside the wire program.
The lowerer emits parameter placeholders and never copies an identifier from program bytes.
The first PostgreSQL lowerer limits generated SQL to eight MiB.

Supabase uses the PostgreSQL lowerer inside the admitted JWT and forced-RLS session.
Each PostgreSQL execution uses one read-only transaction.
The transaction applies a database-side timeout from the remaining authenticated deadline.
MongoDB lowers the same verified instructions into native BSON commands and pipelines.
White Tree can execute the verified instruction graph without a human-readable query layer.

## 11. Cache promotion

The complete canonical program has a domain-separated digest.
A scoped cache can promote that digest to a compact non-zero handle.
Later requests can send the handle and changing parameter values only.

Message kind six registers one authenticated program and its expiry.
The server verifies the program before storage and returns one keyed acceptance receipt.
The client verifies that receipt before it can construct a cached request.

Message kind seven carries the handle, compact operand values, deadline, and result budgets.
The server authenticates the complete frame before it resolves the handle.
It opens the stored immutable verified capability and verifies new operands before backend execution.

The cached frame uses one 64-byte header and one 32-byte keyed tag.
The authority-derived key replaces the repeated context and program digests.
The authority-scoped handle selects the immutable program.
Compact operands omit their original 64-byte metadata header.
The current proof reduced a 436-byte full frame to a 120-byte cached frame.
This 72.48% result is a deterministic wire measurement, not a latency claim.

Cache scope must bind the schema, authority, backend, and compiler version.
Unknown, expired, or mismatched handles must fail before backend work.
Handles must not cross their session, generation, or authority context.

## 12. First proof gates

The first PostgreSQL proof must meet these gates:

| Gate | Required result |
|---|---|
| exactness | Dynamic ISA and native SQL return equal canonical results |
| safety | Every malformed or unauthorised program fails before lowering |
| wire content | Program contains no trusted catalogue identifier bytes |
| dynamic coverage | One unregistered filter, projection, sort, and limit program executes |
| promotion | The second equal program resolves through one cached handle |
| Supabase policy | The compact path preserves admitted JWT identity and forced row-level security |
| request bytes | At least 70% below concise authenticated JSON for the same program |
| cached latency | No more than 5% above one equivalent prepared statement |
| dynamic latency | Report verification, lowering, preparation, execution, and result costs separately |

This proof does not establish arbitrary writes, physical-plan generation, production key custody, or general backend parity.
