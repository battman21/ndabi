# NDABI backend-class binding campaign v5.2

Status: frozen after the v5.1 audit and before the first v5.2 campaign.

## 1. Repair

Keep every v5.1 operation, database, process, and safety gate.
Require each backend to declare its access class.
Refuse a server session before frame admission when backend and authority classes differ.

The session key and frame flags already separated read and write authorities.
The v5.1 API did not prevent a caller from pairing a read authority with a write backend.

## 2. Gates

Require a focused test to prove that class mismatch causes zero backend executions.
Apply all v5.1 database gates across five processes.
Reject the campaign after any failed gate.
Do not replace a failed result with a later v5.2 run.
