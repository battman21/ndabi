# NDABI Rustls transport profile v0.1

**Status:** Implemented beta candidate.

## 1. Purpose

This profile protects NDABI v0.2 frames over a reliable byte stream.
It defines one strict Rustls configuration and one bounded frame reader.
It does not provision certificates or NDABI authority.

## 2. TLS requirements

Use TLS 1.3 only.
Require a valid certificate from both peers.
Verify the server name through the client certificate.
Negotiate ALPN value `ndabi/2`.
Refuse the connection when TLS, ALPN, or peer authentication differs.

Disable client early data.
Disable server early data and half-round-trip data.
Disable session tickets in this candidate.
Use the explicit AWS-LC Rustls provider.

The API returns opaque profiles.
The caller cannot weaken the profile through the returned public type.

## 3. Stream framing

Do not add a second length prefix.
Read the existing little-endian frame length from NDABI bytes 12 through 15.
Read only lengths from 160 bytes through the configured maximum.
Clear partial output after a refusal or truncated read.
Pass every complete frame to the authenticated NDABI decoder.

## 4. Proven behaviour

Focused tests prove valid mutual authentication and same-authority certificate rotation.
They refuse wrong server names, unknown client authorities, expired certificates, and missing ALPN.
They prove exact frame transfer without an added prefix.
They refuse oversized and truncated frames without returning partial output.

## 5. Boundaries

The caller owns certificate issuance, private-key custody, revocation delivery, socket timeouts, and network policy.
The profile does not prove production custody, certificate revocation, controlled WAN behaviour, or remote performance.
The v8.6 campaign must test those implemented boundaries that it can control.
