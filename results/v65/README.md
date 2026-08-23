# NDABI PostgreSQL transport performance v6.5 results

The accepted campaign ran at `20260823T115042Z`.
It retains five complete process reports and one aggregate report.

The campaign measures native prepared, canonical v0.1, and complete v0.2 result transport paths.
It uses a uniquely named ephemeral PostgreSQL container and a one-million-row synthetic dataset.
All five fresh processes passed every frozen performance, repeatability, exactness, and security gate.

The median v0.2 wall distance from native measured 1.035 to 1.207 times across the four result sizes.
The median v0.2 wall distance from v0.1 measured 0.994 to 1.134 times.
The median v0.2 CPU distance from v0.1 measured 1.056 to 1.457 times.
The v0.2 path added no material allocation change against v0.1.

The accepted result proves bounded transport cost, not a PostgreSQL single-query speed gain.
