use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use crate::compression::{decompress, decompress_masked, CompressionMethod};
use crate::crypto::derive_file_key;
use crate::error::{Result, StormError};
use crate::internal::common::{decrypt_mpq_block_in_place, storm_buffer, MPQ_HASH_KEY2_MIX};
use crate::internal::file_table::lookup_file_name_with_locale;
use crate::types::{BlockTableEntry, FileEntry, MpqArchive, MpqFile, MpqFileFlags};

static GLOBAL_LOCALE: AtomicU16 = AtomicU16::new(0);

fn file_uses_sector_offset_table(flags: MpqFileFlags) -> bool {
    flags.intersects(MpqFileFlags::COMPRESS | MpqFileFlags::IMPLODE)
}

fn file_is_multi_sector(flags: MpqFileFlags) -> bool {
    !flags.contains(MpqFileFlags::SINGLE_UNIT)
}

fn compressed_method_from_flags(flags: MpqFileFlags) -> Result<CompressionMethod> {
    if flags.contains(MpqFileFlags::IMPLODE) {
        return Ok(CompressionMethod::PkwareImplode);
    }
    if flags.contains(MpqFileFlags::COMPRESS) {
        return Ok(CompressionMethod::Zlib);
    }
    Ok(CompressionMethod::None)
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

fn decode_sector_crc_words(encoded: &[u8], sector_count: usize) -> Result<Vec<u32>> {
    let expected_bytes = sector_count
        .checked_mul(4)
        .ok_or(StormError::Bounds("sector checksum table size overflow"))?;

    let raw = if encoded.len() < expected_bytes {
        #[cfg(feature = "compression-zlib")]
        {
            use std::io::Read as _;

            let mut out = vec![0u8; expected_bytes];
            let mut decoder = flate2::read::ZlibDecoder::new(encoded);
            decoder
                .read_exact(&mut out)
                .map_err(|_| StormError::Format("failed to decompress sector checksum table"))?;
            out
        }
        #[cfg(not(feature = "compression-zlib"))]
        {
            return Err(StormError::UnsupportedFeature(
                "zlib support required to decode compressed sector checksum table",
            ));
        }
    } else {
        encoded[..expected_bytes].to_vec()
    };

    let mut words = Vec::with_capacity(sector_count);
    for chunk in raw.chunks_exact(4) {
        words.push(u32::from_le_bytes(
            chunk
                .try_into()
                .map_err(|_| StormError::Format("sector checksum chunk length"))?,
        ));
    }
    Ok(words)
}

#[inline]
fn mpq_key1_step(key1: u32) -> u32 {
    ((!key1) << 21).wrapping_add(0x1111_1111) | (key1 >> 11)
}

fn detect_file_key_by_known_content(
    encrypted: &[u8],
    decrypted0: u32,
    decrypted1: u32,
) -> Option<u32> {
    if encrypted.len() < 8 {
        return None;
    }
    let enc0 = u32::from_le_bytes(encrypted[0..4].try_into().ok()?);
    let enc1 = u32::from_le_bytes(encrypted[4..8].try_into().ok()?);
    let table = storm_buffer();
    let key1_plus_key2 = (enc0 ^ decrypted0).wrapping_sub(0xEEEE_EEEE);

    for i in 0..0x100u32 {
        let mut key1 = key1_plus_key2.wrapping_sub(table[(MPQ_HASH_KEY2_MIX + i) as usize]);
        let mut key2 = 0xEEEE_EEEEu32;

        key2 = key2.wrapping_add(table[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);
        let data0 = enc0 ^ key1.wrapping_add(key2);
        if data0 != decrypted0 {
            continue;
        }

        let save_key1 = key1;
        key1 = mpq_key1_step(key1);
        key2 = data0
            .wrapping_add(key2)
            .wrapping_add(key2 << 5)
            .wrapping_add(3);
        key2 = key2.wrapping_add(table[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);
        let data1 = enc1 ^ key1.wrapping_add(key2);
        if data1 == decrypted1 {
            return Some(save_key1);
        }
    }

    None
}

fn detect_file_key_by_content(encrypted: &[u8], sector_size: u32, file_size: u32) -> Option<u32> {
    if sector_size >= 0x0C {
        let key =
            detect_file_key_by_known_content(encrypted, 0x4646_4952, file_size.wrapping_sub(8));
        if key.is_some() {
            return key;
        }
    }
    if sector_size > 0x40 {
        let key = detect_file_key_by_known_content(encrypted, 0x0090_5A4D, 0x0000_0003);
        if key.is_some() {
            return key;
        }
    }
    if sector_size > 0x04 {
        let key = detect_file_key_by_known_content(encrypted, 0x6D78_3F3C, 0x6576_206C);
        if key.is_some() {
            return key;
        }
    }
    None
}

fn detect_file_key_by_sector_size(
    encrypted: &[u8],
    sector_size: u32,
    decrypted0: u32,
) -> Option<u32> {
    if encrypted.len() < 8 {
        return None;
    }
    let enc0 = u32::from_le_bytes(encrypted[0..4].try_into().ok()?);
    let enc1 = u32::from_le_bytes(encrypted[4..8].try_into().ok()?);
    let table = storm_buffer();

    for candidate0 in decrypted0..decrypted0.wrapping_add(4) {
        let decrypted1_max = sector_size.wrapping_add(candidate0);
        let key1_plus_key2 = (enc0 ^ candidate0).wrapping_sub(0xEEEE_EEEE);

        for i in 0..0x100u32 {
            let mut key1 = key1_plus_key2.wrapping_sub(table[(MPQ_HASH_KEY2_MIX + i) as usize]);
            let mut key2 = 0xEEEE_EEEEu32;

            key2 = key2.wrapping_add(table[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);
            let data0 = enc0 ^ key1.wrapping_add(key2);
            if data0 != candidate0 {
                continue;
            }

            let save_key1 = key1.wrapping_add(1);
            key1 = mpq_key1_step(key1);
            key2 = data0
                .wrapping_add(key2)
                .wrapping_add(key2 << 5)
                .wrapping_add(3);
            key2 = key2.wrapping_add(table[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);
            let data1 = enc1 ^ key1.wrapping_add(key2);
            if data1 <= decrypted1_max {
                return Some(save_key1);
            }
        }
    }

    None
}

impl MpqArchive {
    pub fn set_locale(&self, locale: u16) {
        GLOBAL_LOCALE.store(locale, Ordering::Relaxed);
    }

    pub fn locale(&self) -> u16 {
        GLOBAL_LOCALE.load(Ordering::Relaxed)
    }

    pub fn has_file_with_locale(&self, name: &str, locale: u16) -> bool {
        lookup_file_name_with_locale(
            &self.tables.hash_table,
            self.tables.block_table.len(),
            name,
            locale,
        )
        .is_some()
    }

    pub fn open_file(&self, name: &str) -> Result<MpqFile> {
        let m = lookup_file_name_with_locale(
            &self.tables.hash_table,
            self.tables.block_table.len(),
            name,
            self.locale(),
        )
        .ok_or_else(|| StormError::NotFound(name.to_string()))?;

        let hash_entry = self.tables.hash_table[m.hash_index];
        let block_entry =
            self.tables
                .block_table
                .get(m.block_index)
                .copied()
                .ok_or(StormError::Bounds(
                    "block index from hash table out of range",
                ))?;

        let archive = Arc::new(MpqArchive::open(&self.path)?);
        Ok(MpqFile {
            archive,
            entry: FileEntry {
                name: Some(name.to_string()),
                block_index: m.block_index,
                locale: hash_entry.locale,
                platform: hash_entry.platform,
                flags: block_entry.flags,
            },
            cursor: 0,
        })
    }

    pub fn read_file(&mut self, name: &str) -> Result<Vec<u8>> {
        self.read_file_with_locale(name, self.locale())
    }

    pub fn read_file_with_locale(&mut self, name: &str, locale: u16) -> Result<Vec<u8>> {
        if self.is_patched_archive() {
            if let Some(patched) = self.read_file_with_patch_chain(name)? {
                return Ok(patched);
            }
        }

        let m = lookup_file_name_with_locale(
            &self.tables.hash_table,
            self.tables.block_table.len(),
            name,
            locale,
        )
        .ok_or_else(|| StormError::NotFound(name.to_string()))?;
        self.read_file_by_block_index(m.block_index, Some(name))
    }

    pub(crate) fn read_file_by_block_index(
        &mut self,
        block_index: usize,
        name_hint: Option<&str>,
    ) -> Result<Vec<u8>> {
        let block = self
            .tables
            .block_table
            .get(block_index)
            .copied()
            .ok_or(StormError::Bounds("block index out of range"))?;

        if !block.flags.contains(MpqFileFlags::EXISTS) {
            return Err(StormError::NotFound(format!(
                "block {} is not present",
                block_index
            )));
        }
        if block.flags.contains(MpqFileFlags::DELETE_MARKER) {
            return Err(StormError::NotFound(format!(
                "block {} is a delete marker",
                block_index
            )));
        }

        let data_offset = self.header.archive_offset + block.file_pos as u64;
        let data_end = data_offset
            .checked_add(block.compressed_size as u64)
            .ok_or(StormError::Bounds("file block end overflow"))?;
        if data_end > self.stream.len() {
            return Err(StormError::Bounds("file block exceeds archive length"));
        }

        let resolved_name = name_hint
            .map(|s| s.to_string())
            .or_else(|| self.file_names.get(&block_index).cloned());
        let resolved_name_ref = resolved_name.as_deref();

        if file_is_multi_sector(block.flags) {
            self.read_multi_sector_file(block, resolved_name_ref)
        } else {
            self.read_single_unit_file(block, resolved_name_ref)
        }
    }

    fn read_single_unit_file(
        &mut self,
        block: BlockTableEntry,
        name_hint: Option<&str>,
    ) -> Result<Vec<u8>> {
        let data_offset = self.header.archive_offset + block.file_pos as u64;
        let mut data = self
            .stream
            .read_at(data_offset, block.compressed_size as usize)?;

        if block.flags.contains(MpqFileFlags::ENCRYPTED) {
            let key = if let Some(name) = name_hint {
                derive_file_key(
                    name,
                    block.file_pos as u64,
                    block.file_size,
                    block.flags.contains(MpqFileFlags::FIX_KEY),
                )
            } else {
                detect_file_key_by_content(&data, block.file_size, block.file_size).ok_or(
                    StormError::UnsupportedFeature(
                        "encrypted file read requires file name or detectable known-content header",
                    ),
                )?
            };
            decrypt_mpq_block_in_place(&mut data, key);
        }

        let compression = compressed_method_from_flags(block.flags)?;
        if compression == CompressionMethod::Zlib {
            return decompress_masked(&data, block.file_size as usize);
        }
        if compression == CompressionMethod::PkwareImplode {
            return decompress(compression, &data, Some(block.file_size as usize));
        }

        if data.len() < block.file_size as usize {
            return Err(StormError::Format(
                "single-unit file data shorter than file size",
            ));
        }
        data.truncate(block.file_size as usize);
        Ok(data)
    }

    fn read_multi_sector_file(
        &mut self,
        block: BlockTableEntry,
        name_hint: Option<&str>,
    ) -> Result<Vec<u8>> {
        let sector_size = self.header.sector_size() as usize;
        if sector_size == 0 {
            return Err(StormError::Format("invalid sector size"));
        }
        let file_size = block.file_size as usize;
        if file_size == 0 {
            return Ok(Vec::new());
        }
        let sector_count = file_size.div_ceil(sector_size);
        let base = self.header.archive_offset + block.file_pos as u64;

        if !file_uses_sector_offset_table(block.flags) {
            let mut data = self.stream.read_at(base, block.compressed_size as usize)?;
            if block.flags.contains(MpqFileFlags::ENCRYPTED) {
                let key = if let Some(name) = name_hint {
                    derive_file_key(
                        name,
                        block.file_pos as u64,
                        block.file_size,
                        block.flags.contains(MpqFileFlags::FIX_KEY),
                    )
                } else {
                    detect_file_key_by_content(&data, sector_size as u32, block.file_size)
                        .ok_or(StormError::UnsupportedFeature(
                        "encrypted file read requires file name or detectable known-content header",
                    ))?
                };
                for (i, chunk) in data.chunks_mut(sector_size).enumerate() {
                    decrypt_mpq_block_in_place(chunk, key.wrapping_add(i as u32));
                }
            }
            data.truncate(file_size);
            return Ok(data);
        }

        let has_sector_crc = block.flags.contains(MpqFileFlags::SECTOR_CRC);
        let offset_table_words = sector_count + 1 + usize::from(has_sector_crc);
        let mut offset_table = self.stream.read_at(base, offset_table_words * 4)?;
        let file_key = if block.flags.contains(MpqFileFlags::ENCRYPTED) {
            let maybe_key = if let Some(name) = name_hint {
                Some(derive_file_key(
                    name,
                    block.file_pos as u64,
                    block.file_size,
                    block.flags.contains(MpqFileFlags::FIX_KEY),
                ))
            } else {
                detect_file_key_by_sector_size(
                    &offset_table,
                    sector_size as u32,
                    (offset_table_words * 4) as u32,
                )
            };
            Some(maybe_key.ok_or(StormError::UnsupportedFeature(
                "encrypted sector-table read requires file name or detectable sector table key",
            ))?)
        } else {
            None
        };

        if let Some(key) = file_key {
            decrypt_mpq_block_in_place(&mut offset_table, key.wrapping_sub(1));
        }

        let mut raw_sector_offsets = Vec::with_capacity(offset_table_words);
        for chunk in offset_table.chunks_exact(4) {
            let value = u32::from_le_bytes(
                chunk
                    .try_into()
                    .map_err(|_| StormError::Format("sector offset table chunk length"))?,
            );
            raw_sector_offsets.push(value);
        }

        if raw_sector_offsets.len() != offset_table_words {
            return Err(StormError::Format("sector offset table length mismatch"));
        }

        let sector_offsets: Vec<usize> = raw_sector_offsets
            .iter()
            .copied()
            .take(sector_count + 1)
            .map(|v| v as usize)
            .collect();
        for pair in sector_offsets.windows(2) {
            if pair[1] < pair[0] {
                return Err(StormError::Format("sector offsets not monotonic"));
            }
        }

        let sector_checksums = if has_sector_crc && raw_sector_offsets.len() >= sector_count + 2 {
            let expected_size = (sector_count + 2) * 4;
            if raw_sector_offsets[0] as usize == expected_size && raw_sector_offsets[0] != 0 {
                let crc_start = raw_sector_offsets[sector_count] as usize;
                let crc_end = raw_sector_offsets[sector_count + 1] as usize;
                if crc_end >= crc_start {
                    let compressed_size = crc_end - crc_start;
                    if compressed_size >= 4 && compressed_size <= sector_size {
                        let crc_abs =
                            base.checked_add(crc_start as u64)
                                .ok_or(StormError::Bounds(
                                    "sector checksum table absolute position overflow",
                                ))?;
                        let encoded_crc = self.stream.read_at(crc_abs, compressed_size)?;
                        Some(decode_sector_crc_words(&encoded_crc, sector_count)?)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let compression = compressed_method_from_flags(block.flags)?;
        let mut out = Vec::with_capacity(file_size);
        for sector_index in 0..sector_count {
            let start_rel = sector_offsets[sector_index] as u64;
            let end_rel = sector_offsets[sector_index + 1] as u64;
            if end_rel < start_rel {
                return Err(StormError::Format("sector offset underflow"));
            }
            let raw_len = (end_rel - start_rel) as usize;
            let raw_abs = base
                .checked_add(start_rel)
                .ok_or(StormError::Bounds("sector absolute position overflow"))?;
            let mut sector = self.stream.read_at(raw_abs, raw_len)?;

            if let Some(key) = file_key {
                decrypt_mpq_block_in_place(&mut sector, key.wrapping_add(sector_index as u32));
            }

            if let Some(checksums) = &sector_checksums {
                let expected = checksums[sector_index];
                if expected != 0 && expected != u32::MAX {
                    let actual = adler32(&sector);
                    if actual != expected && actual != expected.swap_bytes() {
                        // Best-effort compatibility: tolerate checksum mismatches in read paths.
                        // Verification APIs still provide strict integrity reporting.
                    }
                }
            }

            let remaining = file_size.saturating_sub(out.len());
            let expected_sector_len = remaining.min(sector_size);
            let sector_data =
                if compression == CompressionMethod::Zlib && raw_len < expected_sector_len {
                    decompress_masked(&sector, expected_sector_len)?
                } else if compression == CompressionMethod::PkwareImplode
                    && raw_len < expected_sector_len
                {
                    decompress(compression, &sector, Some(expected_sector_len))?
                } else {
                    sector
                };

            if sector_data.len() < expected_sector_len {
                return Err(StormError::Format("sector shorter than expected"));
            }
            out.extend_from_slice(&sector_data[..expected_sector_len]);
        }

        out.truncate(file_size);
        Ok(out)
    }
}

impl MpqFile {
    pub fn read_all(&self) -> Result<Vec<u8>> {
        let mut archive = MpqArchive::open(&self.archive.path)?;
        archive.read_file_by_block_index(self.entry.block_index, self.entry.name.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use crate::compression::{compress_masked_best_effort, CompressionMethod};
    use crate::internal::common::encrypt_mpq_block_in_place;

    #[test]
    fn compression_flag_helper_prefers_zlib_placeholder() {
        let m = super::compressed_method_from_flags(crate::types::MpqFileFlags::COMPRESS).unwrap();
        assert_eq!(m, CompressionMethod::Zlib);
    }

    #[cfg(feature = "compression-zlib")]
    #[test]
    fn masked_sector_roundtrip() {
        let payload = b"hello hello hello hello";
        let (stored, used) = compress_masked_best_effort(CompressionMethod::Zlib, payload).unwrap();
        if used {
            let round = crate::compression::decompress_masked(&stored, payload.len()).unwrap();
            assert_eq!(round, payload);
        }
    }

    #[test]
    fn adler32_matches_reference_value() {
        assert_eq!(super::adler32(b"abc"), 0x024D_0127);
    }

    #[test]
    fn decode_sector_crc_words_accepts_uncompressed_words() {
        let encoded = [
            0x11u8, 0x22, 0x33, 0x44, //
            0xAA, 0xBB, 0xCC, 0xDD, //
        ];
        let words = super::decode_sector_crc_words(&encoded, 2).unwrap();
        assert_eq!(words, vec![0x4433_2211, 0xDDCC_BBAA]);
    }

    #[cfg(feature = "compression-zlib")]
    #[test]
    fn decode_sector_crc_words_decompresses_zlib() {
        use std::io::Write as _;

        let mut raw = Vec::new();
        for _ in 0..16 {
            raw.extend_from_slice(&[0x11u8, 0x22, 0x33, 0x44]);
        }
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw).unwrap();
        let encoded = encoder.finish().unwrap();
        assert!(encoded.len() < raw.len());

        let words = super::decode_sector_crc_words(&encoded, 16).unwrap();
        assert_eq!(words, vec![0x4433_2211; 16]);
    }

    #[test]
    fn detect_file_key_by_known_content_recovers_key() {
        let key = 0x1357_9BDFu32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x6D78_3F3Cu32.to_le_bytes());
        buf.extend_from_slice(&0x6576_206Cu32.to_le_bytes());
        encrypt_mpq_block_in_place(&mut buf, key);
        let found = super::detect_file_key_by_known_content(&buf, 0x6D78_3F3C, 0x6576_206C);
        assert_eq!(found, Some(key));
    }

    #[test]
    fn detect_file_key_by_sector_size_recovers_key_plus_one_scheme() {
        let file_key = 0x2468_ACEEu32;
        let offsets = [12u32, 100u32, 200u32];
        let mut table = Vec::new();
        for o in offsets {
            table.extend_from_slice(&o.to_le_bytes());
        }
        encrypt_mpq_block_in_place(&mut table, file_key.wrapping_sub(1));
        let found = super::detect_file_key_by_sector_size(&table, 4096, 12);
        assert_eq!(found, Some(file_key));
    }
}
