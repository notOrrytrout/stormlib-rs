#!/usr/bin/env bash
set -euo pipefail

if cargo test --test verify_raw_full_parity --no-run >/dev/null 2>&1; then
  cargo test --test verify_raw_full_parity
fi
cargo test verify_raw_data_v4 --lib
cargo clippy --all-targets -- -D warnings
cargo run --quiet --bin parity -- checklist
