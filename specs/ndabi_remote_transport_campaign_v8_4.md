# NDABI remote transport campaign v8.4

**Status:** Frozen candidate campaign. This document is not a public RFC.

## 1. Purpose

Connect the canonical NDABI v0.1 request and v0.2 result transport across separate processes.
Protect the connection with TLS 1.3 mutual authentication.
Measure persistent request latency under controlled TCP proxy delay.

## 2. Controls

Use the same authenticated authority, registered operation, backend, result bytes, and receipt work.
Compare a canonical NDABI request against a canonical verbose JSON request.
Compile the JSON request into the same authenticated operation at the server boundary.
Return the same canonical v0.2 result frame for both surfaces.

## 3. Conditions

| Condition | One-way proxy delay | Approximate application RTT |
|---|---:|---:|
| `local` | 0 ms | local transport |
| `metro` | 5 ms | 10 ms |
| `regional` | 25 ms | 50 ms |
| `long-haul` | 50 ms | 100 ms |

The proxy applies delay to encrypted TCP forwarding.
This is a controlled WAN-like condition, not a geographic WAN measurement.

## 4. Security gates

Require TLS 1.3 and a client certificate on every accepted connection.
Require the client to validate the server name and test CA.
Refuse a client certificate from an unknown CA.
Refuse a wrong server name.
Accept a rotated server certificate signed by the same test CA.
Verify every NDABI v0.2 result receipt before result commitment.

## 5. Performance gates

Refuse performance measurement while any unrelated Cargo, Rust compiler, or Tauri build process exists.
Monitor the complete measured interval for a new build process.
Require exact result bytes for every measured operation.
Require NDABI request bytes to be at least 40% smaller than JSON.
Require the NDABI p95 to remain within 15% of JSON in every condition.
Do not require binary syntax to beat propagation latency.

## 6. Boundaries

The campaign uses an ephemeral software test CA.
It proves protocol compatibility with standard TLS certificate provisioning and rotation.
It does not prove production KMS custody, revocation delivery, or geographic internet behaviour.
The failed campaign retained no source or binary digest.
Treat its measurements as unattributed diagnostics.
