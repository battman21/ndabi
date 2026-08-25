# NDABI MongoDB compatibility campaign v4.8

Status: frozen after the v4.7 readiness failure and before the first v4.8 formal campaign.

## 1. Repair

Keep the complete v4.7 binary, dataset, operation, arms, measurements, and gates.
Replace MongoDB 8.0 with digest-pinned MongoDB 6.0.26.

MongoDB 8.0 and 8.3 refused Docker Desktop's Linux kernel before accepting connections.
MongoDB 6.0.26 passed the same local `ping` readiness diagnostic.

## 2. Gates and boundaries

Apply every v4.7 correctness, security, compression, latency, and five-process gate.
Reject the campaign after any failed gate.
Do not replace a failed result with a later v4.8 run.

This campaign proves protocol compatibility with MongoDB 6.0.26 only.
It does not prove current MongoDB 8.x runtime compatibility or any broader v4.7 boundary.
