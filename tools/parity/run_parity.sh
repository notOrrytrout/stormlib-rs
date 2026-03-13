#!/usr/bin/env bash
set -euo pipefail

# Example parity harness.
#
# Expected directory layout:
#   fixtures/
#     sample.mpq
#     expected/
#       file1.bin
#
# You must provide:
# - This crate built locally.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURES="$ROOT/fixtures"
OUT="$ROOT/target/parity"

mkdir -p "$OUT/rust"

MPQ="$FIXTURES/sample.mpq"
EXPECTED="$FIXTURES/expected"

if [[ ! -f "$MPQ" ]]; then
  echo "Missing fixture: $MPQ" >&2
  exit 1
fi

if [[ ! -d "$EXPECTED" ]]; then
  echo "Missing expected fixture dir: $EXPECTED" >&2
  exit 1
fi

echo "[1/3] Extract with stormlib-rs"
cargo run --quiet --bin parity -- patch-z extract --mpq "$MPQ" --out "$OUT/rust"

echo "[2/3] Build manifests"
cargo run --quiet --bin parity -- patch-z manifest --root "$EXPECTED" --out "$OUT/expected_manifest.json"
cargo run --quiet --bin parity -- patch-z manifest --root "$OUT/rust" --out "$OUT/rust_manifest.json"

echo "[3/3] Compare manifests"
cargo run --quiet --bin parity -- patch-z compare --expected "$OUT/expected_manifest.json" --actual "$OUT/rust_manifest.json" --out "$OUT/compare.json"

echo "OK"
