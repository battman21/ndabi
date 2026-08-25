# Canonical PostgreSQL batch repair v6.2

The first formal repair campaign preserved all five client reports and failed its gates.
Four clients passed the binary gates.
Two retained native p95 comparisons exceeded the 1.25 limit.

All ten median batch-to-native wall distances stayed between 0.945 and 1.062.
The retained p95 distances ranged from 0.401 to 1.625.
This spread makes p95 unsuitable for the sub-millisecond native-distance hard gate.

The runner also detected a stale release binary.
Its source expected `receipts_valid`, but the built binary did not emit that field.
The v6.3 campaign must rebuild from the bound source before execution.

These results are diagnostic evidence only.
They do not form an accepted performance campaign.
