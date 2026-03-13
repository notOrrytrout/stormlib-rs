#!/usr/bin/env bash
set -euo pipefail

cargo test --test compression_codec_parity
cargo test compression::tests:: --lib
cargo clippy --all-targets -- -D warnings
cargo run --quiet --bin parity -- checklist
