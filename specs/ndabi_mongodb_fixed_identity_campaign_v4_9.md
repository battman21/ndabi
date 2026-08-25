# NDABI MongoDB fixed-identity campaign v4.9

Status: frozen after the v4.8 representative-identity failure and before the first v4.9 campaign.

## 1. Repair

Keep the v4.8 MongoDB image, dataset, adapter, arms, schedule, measurements, and gates.
Use identifier 4,242 for every warm-up and measured operation.

The v4.8 engine queries succeeded, but its rotating identifiers produced different valid result identities.
The shared measurement combiner correctly refused those blocks.

## 2. Gates and boundaries

Apply every v4.7 gate with the v4.8 compatibility boundary.
Reject the campaign after any failed gate.
Do not replace a failed result with a later v4.9 run.
