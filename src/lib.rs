//! `stormlib-rs` is a Rust-native reader/writer for MPQ archives.
//!
//! This crate is a **from-scratch Rust port** of the core MPQ logic found in StormLib.
//! It is intentionally **not** an FFI wrapper.
//!
//! ## Status
//! - The implementation focuses on structural correctness and fidelity to StormLib algorithms.
//! - Core read/write, patch-chain, and verify APIs are implemented and covered by deterministic tests.
//! - Some MPQ-specific codecs and niche compatibility paths remain intentionally bounded or unsupported.
//!
//! ## High-level API
//! - [`MpqArchive::open`] opens an archive for reading.
//! - [`MpqArchive::create`] creates an archive (rewrite-based writer).
//! - [`MpqArchive::read_file`] reads an entire file by name.
//! - [`MpqArchive::extract_file`] extracts a file to disk.
//!
//! See [`MpqArchive`] for details.

#![forbid(unsafe_code)]

mod archive;
mod compression;
mod crypto;
mod error;
mod file;
mod internal;
mod stream;
mod types;

pub use archive::attributes::AttributesFile;
pub use archive::patch::PatchChain;
pub use compression::{compress, decompress, CompressionMethod};
pub use crypto::{decrypt_mpq_block, derive_file_key, encrypt_mpq_block};
pub use error::{ErrorKind, Result, StormError};
pub use internal::file_table::lookup_file_name;
pub use types::{
    AddFileCallback, AddFileOptions, ArchiveListItem, ArchiveSignatureKind, BlockTableEntry,
    CompactCallback, CreateOptions, FileEntry, HashTableEntry, Header, ListCallback, ManifestEntry,
    MpqArchive, MpqFile, MpqFileFlags, MpqWriteFile, SearchScope, Tables, VerifyMode,
    VerifyRawDataTarget, VerifyReport, WriteManifest,
};
