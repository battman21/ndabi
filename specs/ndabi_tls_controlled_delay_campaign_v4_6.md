# NDABI TLS and controlled-delay campaign v4.6

Status: frozen before the first formal campaign.

## 1. Purpose

Measure persistent TLS transport without claiming a real WAN.
Separate loopback transport overhead from a controlled five-millisecond server delay.

## 2. Protocol

Use Rustls TLS 1.3 over persistent loopback TCP connections.
Validate a generated localhost certificate through a dedicated client root store.
Frame each transport message with a four-byte network-order length.

Use the v4.5 fixed operation and a 350-byte deterministic result.
The NDABI arm sends the authenticated 76-byte frame directly.
The JSON gateway parses the 129-byte named request and compiles it through the same session checks and receipt generation.

## 3. Measurement

Run five independent processes.
Measure 10,000 loopback operations and 200 controlled-delay operations per arm and process.
Exclude connection establishment and the TLS handshake from operation latency.
Report handshake time separately.

## 4. Gates

Require TLS 1.3 and exact semantic result bytes.
Require all session operations to authenticate and produce receipts.
Require at least 35 percent request compression.
Require NDABI loopback p95 to remain within 10 percent of equal-security JSON in every process.
Require every process to complete without a transport or protocol error.

Report controlled-delay latency without a speed threshold.
Reject the campaign after any failed gate.
Do not replace a failed result with a later v4.6 run.

## 5. Boundaries

This campaign proves persistent TLS loopback and controlled application delay.
It does not prove geographic WAN, packet loss, bandwidth shaping, public certificates, mutual TLS, or production key custody.
