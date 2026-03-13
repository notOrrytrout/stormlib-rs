use std::path::Path;

use crate::error::Result;
use crate::types::{CreateOptions, MpqArchive, WriteManifest};

impl MpqArchive {
    pub fn create(path: impl AsRef<Path>, options: CreateOptions) -> Result<Self> {
        let header_hint = crate::types::Header {
            archive_offset: 0,
            header_size: 32,
            archive_size_32: 0,
            format_version: 0,
            sector_size_shift: options.sector_size_shift,
            hash_table_pos: 32,
            block_table_pos: 32 + (options.hash_table_entries as u64 * 16),
            hash_table_entries: options.hash_table_entries,
            block_table_entries: options.block_table_entries,
            hi_block_table_pos_64: None,
            hash_table_pos_hi: None,
            block_table_pos_hi: None,
            archive_size_64: None,
            bet_table_pos_64: None,
            het_table_pos_64: None,
            hash_table_size_64: None,
            block_table_size_64: None,
            hi_block_table_size_64: None,
            het_table_size_64: None,
            bet_table_size_64: None,
            raw_chunk_size: None,
        };

        let manifest = WriteManifest::default();
        crate::file::add::rewrite_archive_from_manifest(
            path.as_ref(),
            &manifest,
            Some(&header_hint),
        )?;
        let mut archive = MpqArchive::open(path)?;
        archive.write_manifest = Some(manifest);
        archive.create_listfile = options.create_listfile;
        archive.create_attributes = options.create_attributes;
        Ok(archive)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::types::CreateOptions;

    #[test]
    fn create_writes_openable_empty_archive() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.mpq");
        let a = crate::types::MpqArchive::create(&path, CreateOptions::default()).unwrap();
        assert!(a.has_file("(listfile)"));
    }
}
