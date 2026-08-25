# NDABI canonical homogeneous batch profile v0.1

Status: implemented protocol conformance slice. Engine performance remains open.

## 1. Purpose

Carry many operand tuples for one registered plan through one authenticated frame.
Remove repeated session, authority, plan, schema, policy, budget, and tag fields.
Require one fused engine operation or a refusal.

## 2. Canonical frame

Use little-endian integers.
Use a 128-byte header, twenty bytes per operand, and a 32-byte keyed tag.
The complete frame size is `160 + 20n` bytes.
Require between two and 4,096 operands.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | Magic `NDBI` |
| 4 | 1 | Major version `1` |
| 5 | 1 | Minor version `0` |
| 6 | 1 | `EXECUTE_BATCH_HANDLE` |
| 7 | 1 | Read access |
| 8 | 2 | Reserved zero |
| 10 | 2 | Shared opcode |
| 12 | 4 | Complete frame bytes |
| 16 | 8 | Session identifier |
| 24 | 8 | Authority generation |
| 32 | 8 | Monotonic nonce |
| 40 | 8 | Deadline in Unix microseconds |
| 48 | 4 | Maximum result bytes |
| 52 | 4 | Maximum rows |
| 56 | 4 | Prepared plan handle |
| 60 | 4 | Result-shape handle |
| 64 | 4 | Operand count |
| 68 | 4 | Operand width `20` |
| 72 | 4 | Operand payload bytes |
| 76 | 20 | Reserved zero |
| 96 | 32 | Authority-context digest |
| 128 | `20n` | Operand tuples |
| `128 + 20n` | 32 | Complete keyed BLAKE3 tag |

Each operand contains two signed 64-bit values and one unsigned 32-bit value.
The registered profile defines their meanings.

## 3. Security and execution

Authenticate the complete header and payload before semantic decoding.
Use the separate `ndabi/wire/v1/batch-frame` key domain.
Bind the frame to the existing authority context and durable replay key.
Apply server-held deadline, row, result-byte, and global operand limits.
Commit the nonce only after successful read execution.

Decode operands through a borrowed iterator.
Use a caller-owned encoding buffer.
Do not allocate an operand structure during verification.
Dispatch the complete batch once through the registered backend.
Refuse a backend that cannot fuse the operation.

## 4. Compression

Thirty-two operands use 800 bytes instead of 5,120 bytes across separate frames.
This removes 84.38% of request bytes at that boundary.
One hundred twenty-eight operands use 2,720 bytes instead of 20,480 bytes.
This removes 86.72% of request bytes at that boundary.

These calculations prove format size only.
They do not prove lower latency, compute, memory, energy, or provider tokens.

## 5. Evidence and boundaries

Protocol tests authenticate every frame bit and prove replay and backend-binding refusals.
The negative control failed when authentication was disabled and passed after restoration.
The implementation does not support heterogeneous batches, dependency graphs, writes, streaming, or cancellation.
A PostgreSQL Docker performance campaign remains open.
