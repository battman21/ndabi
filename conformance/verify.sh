#!/usr/bin/env bash
# Verify every committed NDABI conformance implementation and vector set.
set -euo pipefail

CONFORMANCE_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTOTYPE_DIR="$(cd "$CONFORMANCE_DIR/.." && pwd)"

cd "$PROTOTYPE_DIR"
cargo test -p ndabi-protocol --locked
python3 conformance/test_vectors.py

cd "$CONFORMANCE_DIR/go"
go test ./...

cd "$CONFORMANCE_DIR/typescript"
npm ci
npm test
