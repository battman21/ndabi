# NDABI conformance

This directory contains public vectors and independent Go and TypeScript decoders.
The Rust generator uses the canonical implemented protocol.
Neither decoder shares protocol source with Rust.

Run the complete conformance gate from the repository root:

```sh
./conformance/verify.sh
```

Generate the canonical vectors from the repository root:

```sh
cargo run --quiet -p ndabi-protocol --example ndabi_vectors_v01 --locked
cargo run --quiet -p ndabi-protocol --example ndabi_transport_vectors_v02 --locked
```

Run the independent decoder from `conformance/go`:

```sh
go test ./...
```

Run the independent TypeScript decoder from `conformance/typescript`:

```sh
npm ci
npm test
```

Run the committed-vector drift test from the prototype root:

```sh
python3 -m unittest conformance.test_vectors
```

The independent decoders verify both v0.1 request vectors and v0.2 transport vectors.
The v0.2 vectors cover negotiation, results, errors, cancellation, streaming, and operand-bundle acknowledgements.
All keys and identities in both vector sets are public test material.
Do not copy them into a deployment.
