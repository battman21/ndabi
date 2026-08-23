#!/usr/bin/env bash
# Verify every committed NDABI conformance implementation and vector set.
set -euo pipefail

CONFORMANCE_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTOTYPE_DIR="$(cd "$CONFORMANCE_DIR/.." && pwd)"

cd "$PROTOTYPE_DIR"
cargo test -p ndabi-protocol --locked
python3 -m unittest tests.test_conformance_v01

cd "$CONFORMANCE_DIR/go"
go test ./...

cd "$CONFORMANCE_DIR/typescript"
npm ci
npm test
