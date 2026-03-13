use crate::crypto::md5_digest;
use crate::error::{Result, StormError};
use crate::internal::file_table::lookup_file_name;
use crate::types::{
    ArchiveSignatureKind, HashTableEntry, MpqArchive, MpqFileFlags, VerifyMode,
    VerifyRawDataTarget, VerifyReport,
};

const WEAK_SIGNATURE_NAME: &str = "(signature)";
const WEAK_SIGNATURE_FILE_SIZE: usize = 64 + 8;
const STRONG_SIGNATURE_TOTAL_SIZE: usize = 256 + 4;
const MPQ_HEADER_SIZE_V4: u32 = 0xD0;
const RAW_MD5_V4_HEADER_SIZE: u64 = (MPQ_HEADER_SIZE_V4 as u64) - 16;

impl MpqArchive {
    pub fn verify(&self) -> Result<VerifyReport> {
        self.verify_archive()
    }

    pub fn verify_archive(&self) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();

        if self.tables.hash_table.is_empty() || !self.tables.hash_table.len().is_power_of_two() {
            report
                .table_errors
                .push("hash table length must be non-zero power of two".into());
        }
        if self.tables.block_table.is_empty() {
            report
                .table_errors
                .push("block table length must be non-zero".into());
        }

        for (i, h) in self.tables.hash_table.iter().copied().enumerate() {
            if !is_active_hash(h) {
                continue;
            }
            if (h.block_index as usize) >= self.tables.block_table.len() {
                report.table_errors.push(format!(
                    "hash[{i}] points to invalid block index {}",
                    h.block_index
                ));
                continue;
            }
            let b = self.tables.block_table[h.block_index as usize];
            if !b.flags.contains(MpqFileFlags::EXISTS) {
                report.file_errors.push(format!(
                    "hash[{i}] points to non-existing block {}",
                    h.block_index
                ));
            }
        }

        for (i, b) in self.tables.block_table.iter().copied().enumerate() {
            if !b.flags.contains(MpqFileFlags::EXISTS) {
                continue;
            }
            let start = self.header.archive_offset + b.file_pos as u64;
            let end = start.saturating_add(b.compressed_size as u64);
            if end > self.stream.len() {
                report
                    .file_errors
                    .push(format!("block[{i}] data range exceeds archive length"));
            }
            if b.compressed_size == 0 && b.file_size != 0 {
                report.file_errors.push(format!(
                    "block[{i}] zero compressed size with non-zero file size"
                ));
            }
        }

        let mut seen = std::collections::HashSet::new();
        for (i, h) in self.tables.hash_table.iter().copied().enumerate() {
            if !is_active_hash(h) {
                continue;
            }
            let key = (h.hash_a, h.hash_b, h.locale);
            if !seen.insert(key) {
                report
                    .table_errors
                    .push(format!("duplicate hash tuple at hash[{i}]"));
            }
        }

        Ok(report)
    }

    pub fn verify_file(&mut self, name: &str) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();
        if self.read_file(name).is_err() {
            report
                .file_errors
                .push(format!("failed to read file `{name}`"));
        }
        Ok(report)
    }

    pub fn verify_raw_data(
        &mut self,
        target: VerifyRawDataTarget,
        file_name: Option<&str>,
    ) -> Result<VerifyReport> {
        // StormLib returns success when no raw-chunk MD5 support is present.
        if self.header.raw_chunk_size.unwrap_or(0) == 0 {
            return Ok(VerifyReport::default());
        }

        let mut report = VerifyReport::default();

        match target {
            VerifyRawDataTarget::MpqHeader => {
                if self.header.header_size >= RAW_MD5_V4_HEADER_SIZE as u32 {
                    verify_raw_md5_block(
                        self,
                        &mut report,
                        "v4 header raw-data",
                        self.header.archive_offset,
                        RAW_MD5_V4_HEADER_SIZE,
                    );
                }
            }
            // StormLib reports success for these targets: their raw blocks are not MD5-protected.
            VerifyRawDataTarget::HashTable => {}
            VerifyRawDataTarget::BlockTable => {}
            VerifyRawDataTarget::HiBlockTable => {}
            VerifyRawDataTarget::HetTable => verify_optional_raw_md5_block(
                self,
                &mut report,
                "HET table",
                self.header.het_table_pos_64,
                self.header.het_table_size_64,
            ),
            VerifyRawDataTarget::BetTable => verify_optional_raw_md5_block(
                self,
                &mut report,
                "BET table",
                self.header.bet_table_pos_64,
                self.header.bet_table_size_64,
            ),
            VerifyRawDataTarget::File => {
                let Some(name) = file_name else {
                    return Err(StormError::InvalidInput(
                        "raw file verification requires file name",
                    ));
                };
                let Some(m) =
                    lookup_file_name(&self.tables.hash_table, self.tables.block_table.len(), name)
                else {
                    return Err(StormError::NotFound(name.to_string()));
                };
                let Some(block) = self.tables.block_table.get(m.block_index).copied() else {
                    return Err(StormError::Format(
                        "raw-data file points to invalid block index",
                    ));
                };
                verify_raw_md5_block(
                    self,
                    &mut report,
                    "file raw-data",
                    self.header.archive_offset + block.file_pos as u64,
                    block.compressed_size as u64,
                );
            }
        }

        Ok(report)
    }

    pub fn verify_mode(&mut self, mode: VerifyMode) -> Result<VerifyReport> {
        match mode {
            VerifyMode::Archive => self.verify_archive(),
            VerifyMode::File { name } => self.verify_file(&name),
            VerifyMode::RawData { target, file_name } => {
                self.verify_raw_data(target, file_name.as_deref())
            }
        }
    }

    pub fn verify_archive_signature(&mut self) -> Result<ArchiveSignatureKind> {
        if self.has_file(WEAK_SIGNATURE_NAME) {
            let weak = self.read_file(WEAK_SIGNATURE_NAME)?;
            if weak.len() == WEAK_SIGNATURE_FILE_SIZE {
                return Ok(ArchiveSignatureKind::Weak);
            }
        }

        let end_mpq = self
            .header
            .archive_offset
            .saturating_add(self.header.archive_size_32 as u64);
        if self.stream.len() >= end_mpq.saturating_add(STRONG_SIGNATURE_TOTAL_SIZE as u64) {
            let trailer = self.stream.read_at(end_mpq, STRONG_SIGNATURE_TOTAL_SIZE)?;
            if trailer.get(0..4) == Some(b"NGIS") {
                return Ok(ArchiveSignatureKind::Strong);
            }
        }

        Ok(ArchiveSignatureKind::None)
    }
}

fn validate_raw_range(
    report: &mut VerifyReport,
    label: &'static str,
    pos: u64,
    size: u64,
    archive_len: u64,
) {
    let Some(end) = pos.checked_add(size) else {
        report
            .table_errors
            .push(format!("{label} raw-data range overflow"));
        return;
    };
    if end > archive_len {
        report
            .table_errors
            .push(format!("{label} raw-data range exceeds archive length"));
    }
}

fn verify_raw_md5_block(
    archive: &mut MpqArchive,
    report: &mut VerifyReport,
    label: &'static str,
    pos: u64,
    size: u64,
) {
    validate_raw_range(report, label, pos, size, archive.stream.len());
    if !report.table_errors.is_empty() {
        return;
    }
    let raw_chunk_size = archive.header.raw_chunk_size.unwrap_or(0) as u64;
    if raw_chunk_size == 0 || size == 0 {
        return;
    }

    let chunk_count = ((size - 1) / raw_chunk_size) + 1;
    let md5_array_len = chunk_count.saturating_mul(16);
    let md5_pos = pos.saturating_add(size);
    let md5_end = md5_pos.saturating_add(md5_array_len);
    if md5_end > archive.stream.len() {
        report
            .table_errors
            .push(format!("{label} raw-data range exceeds archive length"));
        return;
    }

    let Ok(expected_md5) = archive.stream.read_at(md5_pos, md5_array_len as usize) else {
        report
            .table_errors
            .push(format!("{label} raw-data range exceeds archive length"));
        return;
    };

    for i in 0..chunk_count {
        let chunk_start = pos + i * raw_chunk_size;
        let remaining = size.saturating_sub(i * raw_chunk_size);
        let chunk_len = remaining.min(raw_chunk_size);
        let Ok(data_chunk) = archive.stream.read_at(chunk_start, chunk_len as usize) else {
            report
                .table_errors
                .push(format!("{label} raw-data range exceeds archive length"));
            return;
        };
        let digest = md5_digest(&data_chunk);
        let expected_off = (i * 16) as usize;
        if expected_md5[expected_off..expected_off + 16] != digest {
            report
                .table_errors
                .push(format!("{label} raw-data md5 mismatch"));
            return;
        }
    }
}

fn verify_optional_raw_md5_block(
    archive: &mut MpqArchive,
    report: &mut VerifyReport,
    label: &'static str,
    pos: Option<u64>,
    size: Option<u64>,
) {
    if let (Some(pos), Some(size)) = (pos, size) {
        if pos == 0 || size == 0 {
            return;
        }
        verify_raw_md5_block(archive, report, label, pos, size);
    }
}

pub(crate) fn is_active_hash(entry: HashTableEntry) -> bool {
    !(entry.is_free() || entry.is_deleted())
}

#[cfg(test)]
mod tests {
    use super::{
        is_active_hash, STRONG_SIGNATURE_TOTAL_SIZE, WEAK_SIGNATURE_FILE_SIZE, WEAK_SIGNATURE_NAME,
    };
    use crate::types::{
        AddFileOptions, ArchiveSignatureKind, CreateOptions, VerifyMode, VerifyRawDataTarget,
    };
    use crate::MpqArchive;
    use std::io::{Seek, SeekFrom, Write};

    #[test]
    fn active_hash_helper_matches_sentinels() {
        let free = crate::types::HashTableEntry {
            hash_a: 0,
            hash_b: 0,
            locale: 0,
            platform: 0,
            flags: 0,
            block_index: crate::types::HashTableEntry::BLOCK_INDEX_FREE,
        };
        assert!(!is_active_hash(free));
    }

    #[test]
    fn verify_mode_archive_and_file_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-mode.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive
            .add_file_from_bytes("a.txt", b"abc", AddFileOptions::default())
            .unwrap();

        let archive_report = archive.verify_mode(VerifyMode::Archive).unwrap();
        assert!(archive_report.is_ok());

        let file_report = archive
            .verify_mode(VerifyMode::File {
                name: "a.txt".to_string(),
            })
            .unwrap();
        assert!(file_report.is_ok());
    }

    #[test]
    fn verify_raw_data_returns_ok_for_pre_v4_archives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-raw.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();

        let report = archive
            .verify_raw_data(VerifyRawDataTarget::MpqHeader, None)
            .unwrap();
        assert!(report.is_ok());
    }

    #[test]
    fn verify_raw_data_v4_header_reports_missing_md5_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-raw-v4-header.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive.header.format_version = 3;
        archive.header.header_size = super::MPQ_HEADER_SIZE_V4;
        archive.header.raw_chunk_size = Some(16);

        let report = archive
            .verify_raw_data(VerifyRawDataTarget::MpqHeader, None)
            .unwrap();
        assert!(!report.is_ok());
    }

    #[test]
    fn verify_raw_data_v4_hash_table_is_noop_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-raw-v4-hash.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive.header.format_version = 3;
        archive.header.header_size = super::MPQ_HEADER_SIZE_V4;
        archive.header.raw_chunk_size = Some(4096);

        let report = archive
            .verify_raw_data(VerifyRawDataTarget::HashTable, None)
            .unwrap();
        assert!(report.is_ok());
    }

    #[test]
    fn verify_raw_data_v4_hash_table_ignores_table_range_for_raw_md5() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-raw-v4-hash-ignore.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive.header.format_version = 3;
        archive.header.header_size = super::MPQ_HEADER_SIZE_V4;
        archive.header.raw_chunk_size = Some(4096);
        archive.header.hash_table_size_64 = Some(u64::MAX / 2);

        let report = archive
            .verify_raw_data(VerifyRawDataTarget::HashTable, None)
            .unwrap();
        assert!(report.is_ok());
    }

    #[test]
    fn verify_raw_data_v4_block_table_is_noop_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-raw-v4-block.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive.header.format_version = 3;
        archive.header.header_size = super::MPQ_HEADER_SIZE_V4;
        archive.header.raw_chunk_size = Some(4096);

        let report = archive
            .verify_raw_data(VerifyRawDataTarget::BlockTable, None)
            .unwrap();
        assert!(report.is_ok());
    }

    #[test]
    fn verify_raw_data_v4_hiblock_table_is_noop_when_pos_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-raw-v4-hiblock.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive.header.format_version = 3;
        archive.header.header_size = super::MPQ_HEADER_SIZE_V4;
        archive.header.raw_chunk_size = Some(4096);

        let report = archive
            .verify_raw_data(VerifyRawDataTarget::HiBlockTable, None)
            .unwrap();
        assert!(report.is_ok());
    }

    #[test]
    fn verify_raw_data_v4_hash_table_ignores_zero_64_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-raw-v4-hash-zero-size64.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive.header.format_version = 3;
        archive.header.header_size = super::MPQ_HEADER_SIZE_V4;
        archive.header.raw_chunk_size = Some(4096);
        archive.header.hash_table_size_64 = Some(0);

        let report = archive
            .verify_raw_data(VerifyRawDataTarget::HashTable, None)
            .unwrap();
        assert!(report.is_ok());
    }

    #[test]
    fn verify_raw_data_v4_het_table_reports_out_of_bounds_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-raw-v4-het.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        let len = archive.stream.len();
        archive.header.format_version = 3;
        archive.header.header_size = super::MPQ_HEADER_SIZE_V4;
        archive.header.raw_chunk_size = Some(4096);
        archive.header.het_table_pos_64 = Some(len.saturating_sub(2));
        archive.header.het_table_size_64 = Some(16);

        let report = archive
            .verify_raw_data(VerifyRawDataTarget::HetTable, None)
            .unwrap();
        assert!(report
            .table_errors
            .iter()
            .any(|e| e.contains("HET table raw-data range exceeds archive length")));
    }

    #[test]
    fn verify_raw_data_v4_file_target_checks_file_presence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-raw-v4-file.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive
            .add_file_from_bytes("a.txt", b"abc", AddFileOptions::default())
            .unwrap();
        archive.header.format_version = 3;
        archive.header.header_size = super::MPQ_HEADER_SIZE_V4;
        archive.header.raw_chunk_size = Some(4096);

        let file_report = archive
            .verify_raw_data(VerifyRawDataTarget::File, Some("a.txt"))
            .unwrap();
        assert!(!file_report.table_errors.is_empty());

        let missing_err = archive
            .verify_raw_data(VerifyRawDataTarget::File, Some("missing.txt"))
            .unwrap_err();
        assert!(matches!(missing_err, crate::error::StormError::NotFound(_)));
    }

    #[test]
    fn verify_archive_signature_detects_weak_signature_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-weak-signature.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive
            .add_file_from_bytes(
                WEAK_SIGNATURE_NAME,
                &[0u8; WEAK_SIGNATURE_FILE_SIZE],
                AddFileOptions::default(),
            )
            .unwrap();

        let sig = archive.verify_archive_signature().unwrap();
        assert_eq!(sig, ArchiveSignatureKind::Weak);
    }

    #[test]
    fn verify_archive_signature_detects_strong_signature_marker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-strong-signature.mpq");
        let archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        let end_mpq = archive.header.archive_offset + archive.header.archive_size_32 as u64;

        let mut trailer = vec![0u8; STRONG_SIGNATURE_TOTAL_SIZE];
        trailer[0..4].copy_from_slice(b"NGIS");
        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(end_mpq)).unwrap();
        f.write_all(&trailer).unwrap();
        f.flush().unwrap();

        let mut reopened = MpqArchive::open(&path).unwrap();
        let sig = reopened.verify_archive_signature().unwrap();
        assert_eq!(sig, ArchiveSignatureKind::Strong);
    }
}
