# CLI Guide

This repository ships several utility binaries under `src/bin`.

Build all binaries:

```bash
cargo build --release
```

Run any binary via Cargo:

```bash
cargo run --bin <binary-name> -- <args...>
```

## `storm_extract`

Extracts files listed in a plaintext listfile from an MPQ archive.

Usage:

```bash
storm_extract <mpq> <listfile> <out_dir>
```

Example:

```bash
cargo run --bin storm_extract -- ./input.mpq ./listfile.txt ./out
```

Behavior:

- Skips empty entries.
- Sanitizes `\`, `/`, `.`, and `..` path segments before writing.
- Continues when an individual extract fails; final output reports extracted count.

## `storm_listfile`

Reads `(listfile)` from an MPQ and writes it to disk.

Usage:

```bash
storm_listfile <mpq> <out>
```

Example:

```bash
cargo run --bin storm_listfile -- ./input.mpq ./listfile.txt
```

## `listfile`

Alternative listfile extractor with explicit flags.

Usage:

```bash
listfile --mpq <archive.mpq> --out <out-file>
```

Example:

```bash
cargo run --bin listfile -- --mpq ./input.mpq --out ./listfile.txt
```

Behavior:

- Creates parent directories for `--out` if needed.

## `repack`

Rebuilds an MPQ from extracted files.

Usage:

```bash
repack --out <output.mpq> [--mpq <input.mpq>] [--from-dir <dir>] [--work-dir <dir>]
```

Examples:

```bash
# Extract from source MPQ, then repack
cargo run --bin repack -- --mpq ./in.mpq --out ./out.mpq

# Repack from an existing extracted directory
cargo run --bin repack -- --from-dir ./extracted --work-dir ./extracted --out ./out.mpq
```

Behavior:

- Requires `--out`.
- Requires at least one of `--mpq` or `--from-dir`.
- If both `--from-dir` and `--work-dir` are provided, they must match.
- If `--mpq` is provided without `--from-dir`, it extracts into `--work-dir` (or default work dir) before rebuilding.
- Preserves known file flag behavior when source metadata is available.

## `parity`

Developer parity utility.

Top-level usage:

```bash
parity <command> [args]
```

Commands:

- `checklist [--matrix <path>]`
- `full-api <extract-stormlib|extract-rust|compare> ...`
- `patch-z <extract|manifest|compare|run> ...`
- `codec-vectors --input <path> --out-dir <dir>`

### `parity checklist`

Summarizes status values from a parity matrix JSON.

Default matrix path:

```text
tools/parity/api_parity/feature_matrix.json
```

Example:

```bash
cargo run --bin parity -- checklist
```

### `parity full-api`

Subcommands:

- `extract-stormlib --header <StormLib.h> --out <json>`
- `extract-rust --src <src-dir> --out <json>`
- `compare --stormlib <json> --rust <json> --out-json <json> --out-md <md>`

Example:

```bash
cargo run --bin parity -- full-api extract-rust --src ./src --out ./target/parity/rust_api.json
```

### `parity patch-z`

Subcommands:

- `extract --mpq <archive.mpq> --out <dir>`
- `manifest --root <dir> --out <json>`
- `compare --expected <json> --actual <json> --out <json>`
- `run --mpq <archive.mpq> --golden <expected-manifest.json> --out <dir>`

Example:

```bash
cargo run --bin parity -- patch-z run --mpq ./input.mpq --golden ./expected_manifest.json --out ./target/parity/run
```

### `parity codec-vectors`

Encodes an input blob into codec vector files in `--out-dir`.

Usage:

```bash
parity codec-vectors --input <path> --out-dir <dir>
```

Output always includes:

- `input.bin`
- `huffman.bin`
- `adpcm_mono.bin`
- `adpcm_stereo.bin`
- `sparse.bin`

Output also includes `pkware.bin` when built with feature `compression-pkware`.

## Exit Behavior

- Commands print human-readable output.
- Failures print `error: ...` to stderr and return a non-zero exit code.
