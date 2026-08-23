# NDABI v0.1 conformance

This directory contains public vectors and one independent Go decoder.
The Rust generator uses the canonical implemented protocol.
The Go decoder shares no protocol source with Rust.

Generate the canonical vectors from the prototype root:

```sh
cargo run --quiet --bin ndabi_vectors_v01 --locked
```

Run the independent decoder from `conformance/go`:

```sh
go test ./...
```

Run the committed-vector drift test from the prototype root:

```sh
python3 -m unittest tests.test_conformance_v01
```

All keys and identities in `v0.1/vectors.json` are public test material.
Do not copy them into a deployment.
