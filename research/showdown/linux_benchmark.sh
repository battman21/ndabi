#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "linux_benchmark.sh requires Linux." >&2
  exit 1
fi

for NDABI_COMMAND in cargo taskset perf python3; do
  if ! command -v "$NDABI_COMMAND" >/dev/null 2>&1; then
    echo "$NDABI_COMMAND is required." >&2
    exit 1
  fi
done

NDABI_CPU="${NDABI_CPU:-0}"
NDABI_ROWS="${NDABI_ROWS:-4096}"
NDABI_ITERATIONS="${NDABI_ITERATIONS:-10000}"
NDABI_WARMUP="${NDABI_WARMUP:-500}"
NDABI_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
NDABI_RESULT="results/linux-${NDABI_RUN_ID}.json"
NDABI_PERF="results/linux-${NDABI_RUN_ID}.perf.csv"
NDABI_GOVERNOR="unavailable"

if [ -r "/sys/devices/system/cpu/cpu${NDABI_CPU}/cpufreq/scaling_governor" ]; then
  NDABI_GOVERNOR="$(sed -n '1p' "/sys/devices/system/cpu/cpu${NDABI_CPU}/cpufreq/scaling_governor")"
fi

RUSTFLAGS="-D warnings" cargo build --release --locked
taskset -c "$NDABI_CPU" perf stat -x, \
  -e task-clock,cycles,instructions,cache-misses,branches,branch-misses \
  -- ./target/release/ndabi-showdown \
  --rows "$NDABI_ROWS" \
  --iterations "$NDABI_ITERATIONS" \
  --warmup "$NDABI_WARMUP" \
  >"$NDABI_RESULT" 2>"$NDABI_PERF"

python3 - "$NDABI_RESULT" "$NDABI_CPU" "$NDABI_GOVERNOR" <<'PY'
import json
import sys

path, cpu, governor = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    result = json.load(source)
if result.get("schema") != "ndabi-poc-result-v0.5":
    raise SystemExit("The Linux benchmark returned an unknown schema.")
print(f"result={path}")
print(f"cpu={cpu}")
print(f"governor={governor}")
print(f"verdict={result['overall_verdict']}")
PY

echo "perf=$NDABI_PERF"
