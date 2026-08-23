# NDABI MongoDB v5.7 result

The frozen campaign passed all aggregate and process gates on 2026-08-23.
Five processes used one million synthetic documents in local Docker.
Every process compared complete result bytes twice.
Every process observed one `find` command, zero `getMore` commands, and eight successful refusals.

| Batch | NDABI p95 | Sequential JSON p95 | Speed | Native set p95 | NDABI/native |
|---:|---:|---:|---:|---:|---:|
| 1 | 0.813 ms | 0.834 ms | 1.03 times | 0.781 ms | 1.042 |
| 8 | 0.899 ms | 5.884 ms | 6.55 times | 0.909 ms | 0.988 |
| 32 | 1.314 ms | 29.753 ms | 22.65 times | 1.150 ms | 1.142 |
| 128 | 1.965 ms | 108.481 ms | 55.20 times | 2.006 ms | 0.979 |

Request compression measured 78.10% to 78.41% against equal-security JSON.
At batch 128, median thread CPU was 97.45% below sequential JSON and 11.07% above native set execution.
Allocation count was 95.75% below sequential JSON and 0.20% above native set execution.
Allocated bytes were 96.01% below sequential JSON and 0.47% above native set execution.
Peak additional live bytes did not improve against native set execution.

The large gain comes from fusing many reads into one engine command.
The binary frame does not create a large point-operation speed gain.
The result proves one bounded MongoDB read profile, not all MongoDB functions.

The aggregate file SHA-256 is `f5c5fb8fb0d030f1d4e8157f8c749b4ad388d7bd6a30f5024a2c5b99ed985abb`.
The aggregate records the source, binary, image, and five raw process reports.
