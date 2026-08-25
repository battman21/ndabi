# NDABI remote transport campaign v8.4

The candidate failed its performance gate.

Separate client, encrypted TCP proxy, and server processes passed TLS 1.3 mutual authentication.
The canonical v0.2 connection negotiated successfully.
All results and receipts passed.
Unknown client trust and a wrong server name failed closed.
A rotated server certificate under the same test CA passed.

An initial run occurred during an unrelated release build and is contaminated.
The source-matched run detected a new compiler process at the end.
Reject all v8.4 speed numbers.
The request was 39.85% smaller than concise JSON and missed the 40% gate.

The final run passed its complete host qualification but retained no source or binary digest.
Treat its transport measurements as unattributed diagnostics.
Its local and 10 ms p95 values were 17.29% and 28.57% faster.
Its 50 ms and 100 ms p95 values were 30.54% and 1.12% slower.
The inconsistent tail result failed the frozen performance gate.
Do not promote any v8.4 speed claim.
The controlled proxy delay is not a geographic WAN.
The ephemeral software test CA is not production key custody.
