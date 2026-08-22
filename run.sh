#!/usr/bin/env bash
set -euo pipefail

showdown_root="$(cd "$(dirname "$0")" && pwd)"

cargo build \
  --release \
  --bins \
  --offline \
  --manifest-path "$showdown_root/Cargo.toml"

exec python3 "$showdown_root/server.py" --open
