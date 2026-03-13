use std::collections::BTreeMap;
use std::path::Path;

use crate::archive::attributes::build_default_attributes_stub;
use crate::compression::{compress_masked_best_effort, CompressionMethod};
use crate::crypto::{derive_file_key, encrypt_mpq_block};
use crate::error::{Result, StormError};
use crate::file::callbacks::invoke_add_file_callback;
use crate::internal::common::{hash_string, MPQ_HASH_FILE_KEY};
use crate::internal::file_table::{
    empty_block_table, empty_hash_table, insert_hash_entry, serialize_block_table,
    serialize_hash_table,
};
use crate::stream::FileStream;
use crate::types::{
    AddFileOptions, BlockTableEntry, Header, ManifestEntry, MpqArchive, MpqFileFlags, MpqWriteFile,
    Tables, WriteManifest,
};

#[derive(Debug, Clone)]
pub(crate) struct RewriteResult {
    pub header: Header,
    pub tables: Tables,
    pub file_names: BTreeMap<usize, String>,
}

impl MpqArchive {
    pub fn create_file(
        &self,
        name: &str,
        expected_size: Option<usize>,
        options: AddFileOptions,
    ) -> Result<MpqWriteFile> {
        if name.is_empty() {
            return Err(StormError::InvalidInput("file name must be non-empty"));
        }
        Ok(MpqWriteFile {
            name: name.to_string(),
            data: Vec::with_capacity(expected_size.unwrap_or(0)),
            expected_size,
            options,
        })
    }

    pub fn write_file(&self, handle: &mut MpqWriteFile, data: &[u8]) -> Result<()> {
        if let Some(expected) = handle.expected_size {
            let next = handle
                .data
                .len()
                .checked_add(data.len())
                .ok_or(StormError::Bounds("streaming write size overflow"))?;
            if next > expected {
                return Err(StormError::InvalidInput(
                    "streaming write exceeds expected file size",
                ));
            }
        }
        handle.data.extend_from_slice(data);
        Ok(())
    }

    pub fn finish_file(&mut self, handle: MpqWriteFile) -> Result<()> {
        if let Some(expected) = handle.expected_size {
            if handle.data.len() != expected {
                return Err(StormError::InvalidInput(
                    "streaming write final size does not match expected file size",
                ));
            }
        }
        self.add_file_from_bytes(&handle.name, &handle.data, handle.options)
    }

    pub fn add_file_from_bytes(
        &mut self,
        name: &str,
        data: &[u8],
        options: AddFileOptions,
    ) -> Result<()> {
        let mut manifest = self.capture_or_init_manifest()?;
        if let Some(existing) = manifest
            .entries
            .iter_mut()
            .find(|e| e.name.eq_ignore_ascii_case(name))
        {
            existing.data = data.to_vec();
            existing.options = options;
        } else {
            manifest.entries.push(ManifestEntry {
                name: name.to_string(),
                data: data.to_vec(),
                options,
            });
        }

        self.apply_manifest_rewrite(manifest, self.header.clone())
    }

    pub fn remove_file(&mut self, name: &str) -> Result<()> {
        let mut manifest = self.capture_or_init_manifest()?;
        let before = manifest.entries.len();
        manifest
            .entries
            .retain(|e| !e.name.eq_ignore_ascii_case(name));
        if manifest.entries.len() == before {
            return Err(StormError::NotFound(name.to_string()));
        }

        self.apply_manifest_rewrite(manifest, self.header.clone())
    }

    pub fn rename_file(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        if new_name.is_empty() {
            return Err(StormError::InvalidInput("new name must be non-empty"));
        }
        let mut manifest = self.capture_or_init_manifest()?;
        let Some(idx) = manifest
            .entries
            .iter()
            .position(|e| e.name.eq_ignore_ascii_case(old_name))
        else {
            return Err(StormError::NotFound(old_name.to_string()));
        };
        if manifest
            .entries
            .iter()
            .enumerate()
            .any(|(i, e)| i != idx && e.name.eq_ignore_ascii_case(new_name))
        {
            return Err(StormError::InvalidInput("target file name already exists"));
        }

        manifest.entries[idx].name = new_name.to_string();
        self.apply_manifest_rewrite(manifest, self.header.clone())
    }

    pub fn set_file_locale(&mut self, name: &str, locale: u16, platform: u8) -> Result<()> {
        let mut manifest = self.capture_or_init_manifest()?;
        let Some(entry) = manifest
            .entries
            .iter_mut()
            .find(|e| e.name.eq_ignore_ascii_case(name))
        else {
            return Err(StormError::NotFound(name.to_string()));
        };

        entry.options.locale = locale;
        entry.options.platform = platform;
        self.apply_manifest_rewrite(manifest, self.header.clone())
    }

    pub fn set_max_file_count(
        &mut self,
        hash_table_entries: u32,
        block_table_entries: u32,
    ) -> Result<()> {
        if hash_table_entries == 0 || block_table_entries == 0 {
            return Err(StormError::InvalidInput(
                "table entry counts must be non-zero",
            ));
        }

        let manifest = self.capture_or_init_manifest()?;
        let mut hint = self.header.clone();
        hint.hash_table_entries = hash_table_entries;
        hint.block_table_entries = block_table_entries;
        self.apply_manifest_rewrite(manifest, hint)
    }

    pub fn rewrite_from_manifest(&mut self, manifest: WriteManifest) -> Result<()> {
        self.apply_manifest_rewrite(manifest, self.header.clone())
    }

    pub fn export_manifest(&mut self) -> Result<WriteManifest> {
        self.capture_or_init_manifest()
    }

    fn apply_manifest_rewrite(
        &mut self,
        manifest: WriteManifest,
        header_hint: Header,
    ) -> Result<()> {
        let rewrite = rewrite_archive_from_manifest_with_policy(
            &self.path,
            &manifest,
            Some(&header_hint),
            self.create_listfile,
            self.create_attributes,
        )?;
        self.stream = FileStream::open(&self.path)?;
        self.header = rewrite.header;
        self.tables = rewrite.tables;
        self.file_names = rewrite.file_names;
        self.write_manifest = Some(manifest);
        Ok(())
    }

    pub(crate) fn capture_or_init_manifest(&mut self) -> Result<WriteManifest> {
        if let Some(m) = &self.write_manifest {
            return Ok(m.clone());
        }

        let mut named_entries = Vec::new();
        for item in self.list()? {
            let Some(name) = item.name.clone() else {
                return Err(StormError::UnsupportedFeature(
                    "cannot mutate archive with unnamed entries; provide (listfile) or create a new archive",
                ));
            };
            if name.eq_ignore_ascii_case("(listfile)") {
                continue;
            }
            let data = self.read_file(&name)?;
            let compression = if item.flags.contains(MpqFileFlags::COMPRESS) {
                Some(CompressionMethod::Zlib)
            } else {
                None
            };
            named_entries.push(ManifestEntry {
                name,
                data,
                options: AddFileOptions {
                    compression,
                    encrypted: item.flags.contains(MpqFileFlags::ENCRYPTED),
                    fix_key: item.flags.contains(MpqFileFlags::FIX_KEY),
                    locale: item.locale,
                    platform: item.platform,
                    single_unit: item.flags.contains(MpqFileFlags::SINGLE_UNIT),
                    sector_crc: item.flags.contains(MpqFileFlags::SECTOR_CRC),
                },
            });
        }

        Ok(WriteManifest {
            entries: named_entries,
        })
    }
}

pub(crate) fn rewrite_archive_from_manifest(
    path: impl AsRef<Path>,
    manifest: &WriteManifest,
    header_hint: Option<&Header>,
) -> Result<RewriteResult> {
    rewrite_archive_from_manifest_with_policy(path, manifest, header_hint, true, false)
}

pub(crate) fn rewrite_archive_from_manifest_with_policy(
    path: impl AsRef<Path>,
    manifest: &WriteManifest,
    header_hint: Option<&Header>,
    ensure_listfile: bool,
    ensure_attributes: bool,
) -> Result<RewriteResult> {
    let path = path.as_ref();
    let mut entries = manifest.entries.clone();

    let has_listfile = entries
        .iter()
        .any(|e| e.name.eq_ignore_ascii_case("(listfile)"));
    if ensure_listfile && !has_listfile {
        let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable_by_key(|s| s.to_ascii_lowercase());
        let mut listfile = names.join("\r\n");
        if !listfile.is_empty() {
            listfile.push_str("\r\n");
        }
        entries.push(ManifestEntry {
            name: "(listfile)".to_string(),
            data: listfile.into_bytes(),
            options: AddFileOptions {
                compression: internal_default_compression(),
                encrypted: true,
                fix_key: true,
                locale: 0,
                platform: 0,
                single_unit: true,
                sector_crc: false,
            },
        });
    }
    let has_attributes = entries
        .iter()
        .any(|e| e.name.eq_ignore_ascii_case("(attributes)"));
    if ensure_attributes && !has_attributes {
        let attributes = build_default_attributes_stub(&entries)?;
        entries.push(ManifestEntry {
            name: "(attributes)".to_string(),
            data: attributes,
            options: AddFileOptions {
                compression: internal_default_compression(),
                encrypted: true,
                fix_key: true,
                locale: 0,
                platform: 0,
                single_unit: false,
                sector_crc: false,
            },
        });
    }

    let min_hash = entries.len().saturating_mul(2).max(8).next_power_of_two();
    let hash_table_entries = header_hint
        .map(|h| h.hash_table_entries as usize)
        .unwrap_or(min_hash)
        .max(min_hash);
    let block_table_entries = header_hint
        .map(|h| h.block_table_entries as usize)
        .unwrap_or(entries.len().max(4))
        .max(entries.len());
    let sector_size_shift = header_hint.map(|h| h.sector_size_shift).unwrap_or(3);
    let sector_size = (512usize)
        .checked_shl(sector_size_shift as u32)
        .ok_or(StormError::Bounds("sector size shift overflow"))?;
    let format_version = header_hint.map(|h| h.format_version).unwrap_or(0);
    let header_size = header_hint.map(|h| h.header_size.max(32)).unwrap_or(32);

    let hash_bytes_len = hash_table_entries * 16;
    let block_bytes_len = block_table_entries * 16;
    let data_start = header_size as usize;

    let mut file_data = Vec::new();
    let mut block_table = empty_block_table(block_table_entries);
    let mut hash_table = empty_hash_table(hash_table_entries);
    let mut file_names = BTreeMap::new();

    for (block_index, entry) in entries.iter().enumerate() {
        let file_pos = (data_start + file_data.len()) as u32;
        let (stored, mut flags) = encode_manifest_entry(entry, file_pos, sector_size)?;

        flags |= MpqFileFlags::EXISTS;

        block_table[block_index] = BlockTableEntry {
            file_pos,
            compressed_size: stored.len() as u32,
            file_size: entry.data.len() as u32,
            flags,
        };
        insert_hash_entry(
            &mut hash_table,
            block_table.len(),
            &entry.name,
            block_index as u32,
            entry.options.locale,
            entry.options.platform,
        )?;
        file_names.insert(block_index, entry.name.clone());
        file_data.extend_from_slice(&stored);
        invoke_add_file_callback(block_index + 1, entries.len());
    }

    let mut hash_bytes = serialize_hash_table(&hash_table);
    let mut block_bytes = serialize_block_table(&block_table);
    let hash_key = hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    let block_key = hash_string("(block table)", MPQ_HASH_FILE_KEY);
    encrypt_mpq_block(&mut hash_bytes, hash_key);
    encrypt_mpq_block(&mut block_bytes, block_key);

    let hash_table_pos = data_start + file_data.len();
    let block_table_pos = hash_table_pos + hash_bytes_len;
    let archive_size = (block_table_pos + block_bytes_len) as u32;
    let header = Header {
        archive_offset: 0,
        header_size,
        archive_size_32: archive_size,
        format_version,
        sector_size_shift,
        hash_table_pos: hash_table_pos as u64,
        block_table_pos: block_table_pos as u64,
        hash_table_entries: hash_table_entries as u32,
        block_table_entries: block_table_entries as u32,
        hi_block_table_pos_64: header_hint.and_then(|h| h.hi_block_table_pos_64),
        hash_table_pos_hi: header_hint.and_then(|h| h.hash_table_pos_hi),
        block_table_pos_hi: header_hint.and_then(|h| h.block_table_pos_hi),
        archive_size_64: header_hint.and_then(|h| h.archive_size_64),
        bet_table_pos_64: header_hint.and_then(|h| h.bet_table_pos_64),
        het_table_pos_64: header_hint.and_then(|h| h.het_table_pos_64),
        hash_table_size_64: header_hint.and_then(|h| h.hash_table_size_64),
        block_table_size_64: header_hint.and_then(|h| h.block_table_size_64),
        hi_block_table_size_64: header_hint.and_then(|h| h.hi_block_table_size_64),
        het_table_size_64: header_hint.and_then(|h| h.het_table_size_64),
        bet_table_size_64: header_hint.and_then(|h| h.bet_table_size_64),
        raw_chunk_size: header_hint.and_then(|h| h.raw_chunk_size),
    };

    let mut bytes = Vec::with_capacity(archive_size as usize);
    bytes.extend_from_slice(&0x1A51_504Du32.to_le_bytes());
    bytes.extend_from_slice(&header.header_size.to_le_bytes());
    bytes.extend_from_slice(&header.archive_size_32.to_le_bytes());
    bytes.extend_from_slice(&header.format_version.to_le_bytes());
    bytes.extend_from_slice(&header.sector_size_shift.to_le_bytes());
    bytes.extend_from_slice(&(header.hash_table_pos as u32).to_le_bytes());
    bytes.extend_from_slice(&(header.block_table_pos as u32).to_le_bytes());
    bytes.extend_from_slice(&header.hash_table_entries.to_le_bytes());
    bytes.extend_from_slice(&header.block_table_entries.to_le_bytes());
    if header.header_size > 32 {
        bytes.resize(header.header_size as usize, 0);
        let put_u16 = |buf: &mut Vec<u8>, off: usize, value: u16| {
            if off + 2 <= buf.len() {
                buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
            }
        };
        let put_u32 = |buf: &mut Vec<u8>, off: usize, value: u32| {
            if off + 4 <= buf.len() {
                buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
            }
        };
        let put_u64 = |buf: &mut Vec<u8>, off: usize, value: u64| {
            if off + 8 <= buf.len() {
                buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
            }
        };

        // V2 extension starts at byte 0x20.
        put_u64(&mut bytes, 0x20, header.hi_block_table_pos_64.unwrap_or(0));
        put_u16(&mut bytes, 0x28, header.hash_table_pos_hi.unwrap_or(0));
        put_u16(&mut bytes, 0x2A, header.block_table_pos_hi.unwrap_or(0));
        // V3 extension fields.
        put_u64(&mut bytes, 0x2C, header.archive_size_64.unwrap_or(0));
        put_u64(&mut bytes, 0x34, header.bet_table_pos_64.unwrap_or(0));
        put_u64(&mut bytes, 0x3C, header.het_table_pos_64.unwrap_or(0));
        // V4 extension fields.
        put_u64(&mut bytes, 0x44, header.hash_table_size_64.unwrap_or(0));
        put_u64(&mut bytes, 0x4C, header.block_table_size_64.unwrap_or(0));
        put_u64(&mut bytes, 0x54, header.hi_block_table_size_64.unwrap_or(0));
        put_u64(&mut bytes, 0x5C, header.het_table_size_64.unwrap_or(0));
        put_u64(&mut bytes, 0x64, header.bet_table_size_64.unwrap_or(0));
        put_u32(&mut bytes, 0x6C, header.raw_chunk_size.unwrap_or(0));
    }
    bytes.extend_from_slice(&file_data);
    bytes.extend_from_slice(&hash_bytes);
    bytes.extend_from_slice(&block_bytes);

    let mut stream = FileStream::create(path)?;
    stream.write_all(&bytes)?;
    stream.flush()?;

    Ok(RewriteResult {
        header,
        tables: Tables {
            hash_table,
            block_table,
        },
        file_names,
    })
}

#[cfg(feature = "compression-zlib")]
fn internal_default_compression() -> Option<CompressionMethod> {
    Some(CompressionMethod::Zlib)
}

#[cfg(not(feature = "compression-zlib"))]
fn internal_default_compression() -> Option<CompressionMethod> {
    None
}

fn compression_flag_for_method(method: CompressionMethod) -> MpqFileFlags {
    match method {
        CompressionMethod::PkwareImplode => MpqFileFlags::IMPLODE,
        CompressionMethod::None => MpqFileFlags::empty(),
        _ => MpqFileFlags::COMPRESS,
    }
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut s1 = 1u32;
    let mut s2 = 0u32;

    for &b in data {
        s1 = (s1 + b as u32) % MOD_ADLER;
        s2 = (s2 + s1) % MOD_ADLER;
    }
    (s2 << 16) | s1
}

fn encode_sector_crc_words(words: &[u32]) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(words.len() * 4);
    for &word in words {
        raw.extend_from_slice(&word.swap_bytes().to_le_bytes());
    }

    #[cfg(feature = "compression-zlib")]
    {
        use std::io::Write as _;

        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&raw)
            .map_err(|e| StormError::CompressionOwned {
                message: e.to_string(),
            })?;
        let compressed = enc.finish().map_err(|e| StormError::CompressionOwned {
            message: e.to_string(),
        })?;
        if compressed.len() < raw.len() {
            return Ok(compressed);
        }
    }

    Ok(raw)
}

fn encode_manifest_entry(
    entry: &ManifestEntry,
    file_pos: u32,
    sector_size: usize,
) -> Result<(Vec<u8>, MpqFileFlags)> {
    let requested = entry.options.compression.unwrap_or(CompressionMethod::None);
    let mut flags = MpqFileFlags::empty();
    let use_single_unit = entry.options.single_unit && requested == CompressionMethod::None;
    if use_single_unit {
        flags |= MpqFileFlags::SINGLE_UNIT;
        let (mut stored, used_compression) = compress_masked_best_effort(requested, &entry.data)?;
        if used_compression {
            flags |= compression_flag_for_method(requested);
        }
        if entry.options.encrypted {
            flags |= MpqFileFlags::ENCRYPTED;
            if entry.options.fix_key {
                flags |= MpqFileFlags::FIX_KEY;
            }
            let key = derive_file_key(
                &entry.name,
                file_pos as u64,
                entry.data.len() as u32,
                entry.options.fix_key,
            );
            encrypt_mpq_block(&mut stored, key);
        }
        return Ok((stored, flags));
    }

    if requested == CompressionMethod::None {
        let mut stored = entry.data.clone();
        if entry.options.encrypted {
            flags |= MpqFileFlags::ENCRYPTED;
            if entry.options.fix_key {
                flags |= MpqFileFlags::FIX_KEY;
            }
            let key = derive_file_key(
                &entry.name,
                file_pos as u64,
                entry.data.len() as u32,
                entry.options.fix_key,
            );
            for (i, chunk) in stored.chunks_mut(sector_size).enumerate() {
                encrypt_mpq_block(chunk, key.wrapping_add(i as u32));
            }
        }
        return Ok((stored, flags));
    }

    let include_sector_crc = entry.options.sector_crc;
    let mut sector_blobs = Vec::new();
    let mut sector_checksums = Vec::new();
    let mut offsets = Vec::new();
    let sector_count = entry.data.len().div_ceil(sector_size);
    let table_words = sector_count + 1 + usize::from(include_sector_crc);
    let table_bytes = (table_words * 4) as u32;
    let mut running = table_bytes;
    offsets.push(running);

    for chunk in entry.data.chunks(sector_size) {
        let (stored, used_compression) = compress_masked_best_effort(requested, chunk)?;
        let blob = if used_compression {
            stored
        } else {
            chunk.to_vec()
        };
        if include_sector_crc {
            sector_checksums.push(adler32(&blob));
        }
        running = running.saturating_add(blob.len() as u32);
        offsets.push(running);
        sector_blobs.push(blob);
    }

    flags |= compression_flag_for_method(requested);
    if include_sector_crc {
        flags |= MpqFileFlags::SECTOR_CRC;
    }

    if entry.options.encrypted {
        flags |= MpqFileFlags::ENCRYPTED;
        if entry.options.fix_key {
            flags |= MpqFileFlags::FIX_KEY;
        }
        let key = derive_file_key(
            &entry.name,
            file_pos as u64,
            entry.data.len() as u32,
            entry.options.fix_key,
        );
        for (i, blob) in sector_blobs.iter_mut().enumerate() {
            encrypt_mpq_block(blob, key.wrapping_add(i as u32));
        }

        let crc_bytes = if include_sector_crc {
            let out = encode_sector_crc_words(&sector_checksums)?;
            running = running.saturating_add(out.len() as u32);
            offsets.push(running);
            Some(out)
        } else {
            None
        };
        let mut table_bytes_enc = Vec::with_capacity(offsets.len() * 4);
        for v in &offsets {
            table_bytes_enc.extend_from_slice(&v.to_le_bytes());
        }
        encrypt_mpq_block(&mut table_bytes_enc, key.wrapping_sub(1));

        let mut out = Vec::with_capacity(
            table_bytes_enc.len() + sector_blobs.iter().map(Vec::len).sum::<usize>(),
        );
        out.extend_from_slice(&table_bytes_enc);
        for blob in sector_blobs {
            out.extend_from_slice(&blob);
        }
        if let Some(crc) = crc_bytes {
            out.extend_from_slice(&crc);
        }
        return Ok((out, flags));
    }

    let crc_bytes = if include_sector_crc {
        let out = encode_sector_crc_words(&sector_checksums)?;
        running = running.saturating_add(out.len() as u32);
        offsets.push(running);
        Some(out)
    } else {
        None
    };

    let mut out =
        Vec::with_capacity((offsets.len() * 4) + sector_blobs.iter().map(Vec::len).sum::<usize>());
    for v in offsets {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for blob in sector_blobs {
        out.extend_from_slice(&blob);
    }
    if let Some(crc) = crc_bytes {
        out.extend_from_slice(&crc);
    }
    Ok((out, flags))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::tempdir;

    #[cfg(feature = "compression-zlib")]
    use crate::compression::CompressionMethod;
    #[cfg(feature = "compression-zlib")]
    use crate::types::MpqFileFlags;
    use crate::types::{AddFileOptions, Header, MpqArchive, WriteManifest};

    use super::rewrite_archive_from_manifest;

    static ADD_FILE_HITS: AtomicUsize = AtomicUsize::new(0);

    fn bump_add_file_callback(_: usize, _: usize) {
        ADD_FILE_HITS.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn rewrite_manifest_produces_archive_with_listfile() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.mpq");
        let manifest = WriteManifest {
            entries: vec![crate::types::ManifestEntry {
                name: "foo.txt".into(),
                data: b"bar".to_vec(),
                options: AddFileOptions::default(),
            }],
        };
        let out = rewrite_archive_from_manifest(&path, &manifest, None).unwrap();
        assert!(out.file_names.values().any(|n| n == "(listfile)"));
    }

    #[cfg(feature = "compression-zlib")]
    #[test]
    fn rewrite_manifest_supports_non_single_unit_compressed_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("multi.mpq");
        let data = vec![0x41u8; 9000];
        let manifest = WriteManifest {
            entries: vec![crate::types::ManifestEntry {
                name: "multi.bin".into(),
                data: data.clone(),
                options: AddFileOptions {
                    compression: Some(CompressionMethod::Zlib),
                    single_unit: false,
                    ..AddFileOptions::default()
                },
            }],
        };

        let _ = rewrite_archive_from_manifest(&path, &manifest, None).unwrap();
        let mut archive = MpqArchive::open(&path).unwrap();
        let roundtrip = archive.read_file("multi.bin").unwrap();
        assert_eq!(roundtrip, data);

        let item = archive
            .list()
            .unwrap()
            .into_iter()
            .find(|it| it.name.as_deref() == Some("multi.bin"))
            .unwrap();
        assert!(item.flags.contains(MpqFileFlags::COMPRESS));
        assert!(!item.flags.contains(MpqFileFlags::SINGLE_UNIT));
    }

    #[cfg(feature = "compression-zlib")]
    #[test]
    fn rewrite_manifest_writes_sector_crc_table_when_enabled() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("crc.mpq");
        let data = vec![0xCDu8; 9000];
        let manifest = WriteManifest {
            entries: vec![crate::types::ManifestEntry {
                name: "crc.bin".into(),
                data: data.clone(),
                options: AddFileOptions {
                    compression: Some(CompressionMethod::Zlib),
                    single_unit: false,
                    sector_crc: true,
                    ..AddFileOptions::default()
                },
            }],
        };

        let _ = rewrite_archive_from_manifest(&path, &manifest, None).unwrap();
        let mut archive = MpqArchive::open(&path).unwrap();
        let roundtrip = archive.read_file("crc.bin").unwrap();
        assert_eq!(roundtrip, data);

        let item = archive
            .list()
            .unwrap()
            .into_iter()
            .find(|it| it.name.as_deref() == Some("crc.bin"))
            .unwrap();
        assert!(item.flags.contains(MpqFileFlags::SECTOR_CRC));
    }

    #[test]
    fn rewrite_manifest_invokes_add_file_callback() {
        ADD_FILE_HITS.store(0, Ordering::Relaxed);
        MpqArchive::set_add_file_callback(Some(bump_add_file_callback));

        let dir = tempdir().unwrap();
        let path = dir.path().join("cb.mpq");
        let manifest = WriteManifest {
            entries: vec![crate::types::ManifestEntry {
                name: "foo.txt".into(),
                data: b"bar".to_vec(),
                options: AddFileOptions::default(),
            }],
        };

        let _ = rewrite_archive_from_manifest(&path, &manifest, None).unwrap();
        assert!(ADD_FILE_HITS.load(Ordering::Relaxed) >= 1);
        MpqArchive::set_add_file_callback(None);
    }

    #[test]
    fn rewrite_manifest_preserves_header_size_and_version_hint() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v4-layout.mpq");
        let manifest = WriteManifest {
            entries: vec![crate::types::ManifestEntry {
                name: "foo.txt".into(),
                data: b"bar".to_vec(),
                options: AddFileOptions::default(),
            }],
        };
        let header_hint = Header {
            archive_offset: 0,
            header_size: 0xD0,
            archive_size_32: 0,
            format_version: 3,
            sector_size_shift: 3,
            hash_table_pos: 32,
            block_table_pos: 32 + 16,
            hash_table_entries: 8,
            block_table_entries: 8,
            hi_block_table_pos_64: None,
            hash_table_pos_hi: Some(0x0000),
            block_table_pos_hi: Some(0x0000),
            archive_size_64: Some(0x2222),
            bet_table_pos_64: None,
            het_table_pos_64: None,
            hash_table_size_64: Some(0x5555),
            block_table_size_64: Some(0x6666),
            hi_block_table_size_64: Some(0x7777),
            het_table_size_64: Some(0x8888),
            bet_table_size_64: Some(0x9999),
            raw_chunk_size: Some(0x10000),
        };

        let out = rewrite_archive_from_manifest(&path, &manifest, Some(&header_hint)).unwrap();
        assert_eq!(out.header.format_version, 3);
        assert_eq!(out.header.header_size, 0xD0);
        assert!(out.header.hash_table_pos >= out.header.header_size as u64);
        assert!(out.header.block_table_pos > out.header.hash_table_pos);
        assert_eq!(out.header.raw_chunk_size, Some(0x10000));

        let reopened = MpqArchive::open(&path).unwrap();
        assert_eq!(reopened.header.raw_chunk_size, Some(0x10000));
        assert_eq!(reopened.header.hash_table_size_64, Some(0x5555));
    }
}
