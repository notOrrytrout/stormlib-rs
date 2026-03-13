# stormlib-rs

Rust-native MPQ archive toolkit implemented without FFI wrappers.

`stormlib-rs` is a Rust port of the StormLib C code, implementing core MPQ behavior for reading, writing, patch-chain resolution, and verification.

## Documentation

- [CLI Guide](./docs/CLI_GUIDE.md)

## Current Scope

Implemented and tested:

- Archive lifecycle: `MpqArchive::open`, `MpqArchive::create`
- Read/list/find: `read_file`, `extract_file`, `extract_all`, `list`, `list_all`, wildcard `find`
- Rewrite-based mutation API: `add_file_from_bytes`, `remove_file`, `rename_file`, locale/platform updates, table-size updates, `rewrite_from_manifest`
- Streaming write API: `create_file` -> `write_file` -> `finish_file`
- Patch archives: `open_patch_archive`, `apply_patch_chain`, patch-aware listing and reads
- Verification: `verify`, `verify_archive`, `verify_file`, `verify_raw_data`, `verify_archive_signature`
- MPQ crypto helpers and table/hash primitives
- Attribute helpers: parse/serialize/sync of `(attributes)`

This crate is intentionally not a C-ABI/FFI compatibility wrapper.

## Compression Support

Feature-gated codecs:

- `compression-zlib` (default)
- `compression-zlib-native` (system zlib backend for `flate2`)
- `compression-bzip2` (default)
- `compression-pkware` (default)
- `compression-lzma` (optional)

Always-available MPQ codec implementations:

- Huffman
- ADPCM (mono/stereo)
- Sparse

## Build

```bash
cargo build
```

Disable defaults (minimal compression features):

```bash
cargo build --no-default-features
```

Enable all optional compression features:

```bash
cargo build --all-features
```

## Library Quick Start

```rust
use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = MpqArchive::create("demo.mpq", CreateOptions::default())?;
    a.add_file_from_bytes("hello.txt", b"hello", AddFileOptions::default())?;

    let mut b = MpqArchive::open("demo.mpq")?;
    let data = b.read_file("hello.txt")?;
    assert_eq!(data, b"hello");
    Ok(())
}
```

## CLI Binaries

This repo ships utility binaries under `src/bin`:

- `storm_extract`
- `storm_listfile`
- `listfile`
- `repack`
- `parity`

See [docs/CLI_GUIDE.md](./docs/CLI_GUIDE.md) for exact usage.

## Development

Run all tests:

```bash
cargo test
```

Run checks for all targets:

```bash
cargo check --all-targets
```

Run benchmarks:

```bash
cargo bench --all-features
```

## MSRV

Rust `1.74`.
