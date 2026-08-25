# NDABI canonical PostgreSQL batch repair campaign v6.2

Status: frozen before the first formal campaign.

## 1. Repair scope

Repair the v6.1 evidence runner only.
Retain the v6.1 binary, engine fixture, sample counts, cases, arms, and hard performance gates.
Do not reinterpret the four retained v6.1 results as accepted evidence.

## 2. Evidence closure

Run all five planned client processes, including after one client fails.
Capture each child exit code before validation.
Persist each valid JSON report before applying hard gates.
Persist a bounded failure record when JSON parsing fails.
Record a SHA-256 digest instead of unparsed child output.

Require five zero exit codes and five independently validated reports.
Require every database-authority and performance gate from v6.1.
Require the batch-to-native p95 ratio coefficient of variation below 20% for each case.

## 3. Custody and cleanup

Bind the campaign to both runner sources, both frozen contracts, the binary, the adapter, and the protocol implementation.
Record source, binary, and resolved PostgreSQL image hashes.
Remove the ephemeral Docker container after every result.

## 4. Boundaries

This repair changes evidence handling only.
It adds no new query shape, engine, transport, platform, token, energy, or production claim.
