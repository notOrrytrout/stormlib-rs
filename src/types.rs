use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use bitflags::bitflags;

use crate::compression::CompressionMethod;
use crate::stream::FileStream;

/// Parsed MPQ header (V1 fields).
///
/// Notes:
/// - All offsets are normalized to absolute file offsets.
/// - Extended header variants (v2-v4) are only partially supported.
#[derive(Debug, Clone)]
pub struct Header {
    pub archive_offset: u64,
    pub header_size: u32,
    pub archive_size_32: u32,
    pub format_version: u16,
    pub sector_size_shift: u16,
    pub hash_table_pos: u64,
    pub block_table_pos: u64,
    pub hash_table_entries: u32,
    pub block_table_entries: u32,
    pub hi_block_table_pos_64: Option<u64>,
    pub hash_table_pos_hi: Option<u16>,
    pub block_table_pos_hi: Option<u16>,
    pub archive_size_64: Option<u64>,
    pub bet_table_pos_64: Option<u64>,
    pub het_table_pos_64: Option<u64>,
    pub hash_table_size_64: Option<u64>,
    pub block_table_size_64: Option<u64>,
    pub hi_block_table_size_64: Option<u64>,
    pub het_table_size_64: Option<u64>,
    pub bet_table_size_64: Option<u64>,
    pub raw_chunk_size: Option<u32>,
}

impl Header {
    pub const V1_SIZE: u32 = 32;

    /// Returns the logical sector size in bytes (`512 << sector_size_shift`).
    pub fn sector_size(&self) -> u32 {
        let shift = self.sector_size_shift as u32;
        if shift >= u64::BITS {
            return u32::MAX;
        }

        let expanded = 512u64 << shift;
        expanded.min(u32::MAX as u64) as u32
    }
}

/// In-memory representation of MPQ hash and block tables.
#[derive(Debug, Clone, Default)]
pub struct Tables {
    pub hash_table: Vec<HashTableEntry>,
    pub block_table: Vec<BlockTableEntry>,
}

/// An opened MPQ archive.
///
/// This struct owns the underlying file handle. If you need concurrent access to files within
/// an archive, clone and share it via `Arc` (as done by [`MpqFile`]).
#[derive(Debug)]
pub struct MpqArchive {
    pub stream: FileStream,
    pub path: PathBuf,
    pub header: Header,
    pub tables: Tables,

    /// Optional mapping from hash table indices to resolved filenames (typically sourced from
    /// `(listfile)` or external listfiles).
    pub file_names: BTreeMap<usize, String>,

    /// Writer-only manifest used by rewrite-based update flows.
    pub write_manifest: Option<WriteManifest>,

    /// Ordered list of attached patch archives (base -> newest patch).
    pub patch_chain: Vec<PatchArchiveEntry>,

    /// Writer behavior toggles used for rewrite-based mutations.
    pub create_listfile: bool,
    pub create_attributes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchArchiveEntry {
    pub path: PathBuf,
    pub prefix: Option<String>,
}

/// Resolved per-file entry information.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: Option<String>,
    pub block_index: usize,
    pub locale: u16,
    pub platform: u8,
    pub flags: MpqFileFlags,
}

/// A cursor-based file handle within an MPQ archive.
#[derive(Debug, Clone)]
pub struct MpqFile {
    pub archive: Arc<MpqArchive>,
    pub entry: FileEntry,
    pub cursor: u64,
}

/// Options for creating a new archive.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub sector_size_shift: u16,
    pub hash_table_entries: u32,
    pub block_table_entries: u32,
    pub create_listfile: bool,
    pub create_attributes: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            sector_size_shift: 3,
            hash_table_entries: 128,
            block_table_entries: 4,
            create_listfile: true,
            create_attributes: true,
        }
    }
}

/// Options for adding a file.
#[derive(Debug, Clone)]
pub struct AddFileOptions {
    pub compression: Option<CompressionMethod>,
    pub encrypted: bool,
    pub fix_key: bool,
    pub locale: u16,
    pub platform: u8,

    /// If true, write as a single-unit file (no sector table).
    /// If false and compression is enabled, the writer emits a sector offset table.
    pub single_unit: bool,

    /// If true, write a sector checksum table for non-single-unit compressed files.
    pub sector_crc: bool,
}

impl Default for AddFileOptions {
    fn default() -> Self {
        Self {
            compression: None,
            encrypted: false,
            fix_key: false,
            locale: 0,
            platform: 0,
            single_unit: true,
            sector_crc: false,
        }
    }
}

/// Captured content for rewrite-based archive updates.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub name: String,
    pub data: Vec<u8>,
    pub options: AddFileOptions,
}

/// In-memory handle for streaming-style archive writes.
#[derive(Debug, Clone)]
pub struct MpqWriteFile {
    pub name: String,
    pub data: Vec<u8>,
    pub expected_size: Option<usize>,
    pub options: AddFileOptions,
}

/// A set of entries used to reconstruct an archive during rewrite-based updates.
#[derive(Debug, Clone, Default)]
pub struct WriteManifest {
    pub entries: Vec<ManifestEntry>,
}

/// Item returned from [`crate::archive::MpqArchiveExt::list`] (or [`MpqArchive::list`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveListItem {
    pub hash_index: usize,
    pub block_index: usize,
    pub name: Option<String>,
    pub locale: u16,
    pub platform: u8,
    pub flags: MpqFileFlags,
}

/// Callback type invoked during list/find iteration.
pub type ListCallback = fn(&ArchiveListItem);
pub type AddFileCallback = fn(usize, usize);
pub type CompactCallback = fn(usize, usize);

/// Structured result from archive verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub table_errors: Vec<String>,
    pub file_errors: Vec<String>,
}

impl VerifyReport {
    pub fn is_ok(&self) -> bool {
        self.table_errors.is_empty() && self.file_errors.is_empty()
    }
}

/// Verification class selector analogous to StormLib verify entry points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyMode {
    Archive,
    File {
        name: String,
    },
    RawData {
        target: VerifyRawDataTarget,
        file_name: Option<String>,
    },
}

/// Raw-data verification target analogous to `SFILE_VERIFY_*` targets in StormLib.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyRawDataTarget {
    MpqHeader,
    HetTable,
    BetTable,
    HashTable,
    BlockTable,
    HiBlockTable,
    File,
}

/// Archive signature class detected in MPQ data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveSignatureKind {
    None,
    Weak,
    Strong,
}

/// Scope used by list/find iteration APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    AllEntries,
    NamedEntries,
}

/// Raw hash table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashTableEntry {
    pub hash_a: u32,
    pub hash_b: u32,
    pub locale: u16,
    pub platform: u8,
    pub flags: u8,
    pub block_index: u32,
}

impl HashTableEntry {
    pub const SERIALIZED_LEN: usize = 16;
    pub const BLOCK_INDEX_DELETED: u32 = 0xFFFF_FFFE;
    pub const BLOCK_INDEX_FREE: u32 = 0xFFFF_FFFF;

    pub fn is_free(self) -> bool {
        self.block_index == Self::BLOCK_INDEX_FREE
    }

    pub fn is_deleted(self) -> bool {
        self.block_index == Self::BLOCK_INDEX_DELETED
    }
}

/// Raw block table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockTableEntry {
    pub file_pos: u32,
    pub compressed_size: u32,
    pub file_size: u32,
    pub flags: MpqFileFlags,
}

impl BlockTableEntry {
    pub const SERIALIZED_LEN: usize = 16;

    pub fn file_end(&self) -> u64 {
        self.file_pos as u64 + self.compressed_size as u64
    }
}

bitflags! {
    /// MPQ block flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MpqFileFlags: u32 {
        const IMPLODE       = 0x0000_0100;
        const COMPRESS      = 0x0000_0200;
        const ENCRYPTED     = 0x0001_0000;
        const FIX_KEY       = 0x0002_0000;
        const PATCH_FILE    = 0x0010_0000;
        const SINGLE_UNIT   = 0x0100_0000;
        const DELETE_MARKER = 0x0200_0000;
        const SECTOR_CRC    = 0x0400_0000;
        const EXISTS        = 0x8000_0000;
    }
}
