#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/target/parity/full_api"
STORMLIB_HEADER="$ROOT/../StormLib-master/src/StormLib.h"

mkdir -p "$OUT"

cargo run --quiet --bin parity -- full-api extract-stormlib \
  --header "$STORMLIB_HEADER" \
  --out "$OUT/stormlib_api.json"

cargo run --quiet --bin parity -- full-api extract-rust \
  --src "$ROOT/src" \
  --out "$OUT/rust_api.json"

cargo run --quiet --bin parity -- full-api compare \
  --stormlib "$OUT/stormlib_api.json" \
  --rust "$OUT/rust_api.json" \
  --out-json "$OUT/parity_report.json" \
  --out-md "$OUT/parity_report.md"

cat "$OUT/parity_report.md"
