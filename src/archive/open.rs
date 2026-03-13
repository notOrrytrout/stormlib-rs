use std::path::Path;

use crate::crypto::decrypt_mpq_block;
use crate::error::{Result, StormError};
use crate::internal::common::{hash_string, MPQ_HASH_FILE_KEY};
use crate::internal::file_table::{parse_block_table, parse_hash_table};
use crate::stream::FileStream;
use crate::types::{Header, MpqArchive, Tables};

const MPQ_SIGNATURE: u32 = 0x1A51_504D;
const MPQ_HEADER_SIZE_V1: u32 = 0x20;
const MPQ_HEADER_SIZE_V2: u32 = 0x2C;
const MPQ_HEADER_SIZE_V3: u32 = 0x44;
const MPQ_HEADER_SIZE_V4: u32 = 0xD0;

impl MpqArchive {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let mut stream = FileStream::open(&path_buf)?;
        let file_len = stream.len();

        let header = read_header_at(&mut stream, 0)?;
        validate_header_basic(&header, file_len)?;
        let tables = read_tables(&mut stream, &header)?;

        let mut archive = Self {
            stream,
            path: path_buf,
            header,
            tables,
            file_names: Default::default(),
            write_manifest: None,
            patch_chain: Vec::new(),
            create_listfile: false,
            create_attributes: false,
        };

        let _ = crate::file::list::populate_names_from_listfile(&mut archive);
        Ok(archive)
    }
}

pub fn read_header_at(stream: &mut FileStream, archive_offset: u64) -> Result<Header> {
    let mut raw = [0u8; 32];
    stream.read_exact_at(archive_offset, &mut raw)?;

    let sig = u32::from_le_bytes(
        raw[0..4]
            .try_into()
            .map_err(|_| StormError::Format("header signature slice"))?,
    );
    if sig != MPQ_SIGNATURE {
        return Err(StormError::Format(
            "missing MPQ signature at archive offset",
        ));
    }

    let header_size = u32::from_le_bytes(
        raw[4..8]
            .try_into()
            .map_err(|_| StormError::Format("header size slice"))?,
    );
    let archive_size_32 = u32::from_le_bytes(
        raw[8..12]
            .try_into()
            .map_err(|_| StormError::Format("archive size slice"))?,
    );
    let format_version = u16::from_le_bytes(
        raw[12..14]
            .try_into()
            .map_err(|_| StormError::Format("format version slice"))?,
    );
    let sector_size_shift = u16::from_le_bytes(
        raw[14..16]
            .try_into()
            .map_err(|_| StormError::Format("sector size shift slice"))?,
    );
    let mut hash_table_pos = u32::from_le_bytes(
        raw[16..20]
            .try_into()
            .map_err(|_| StormError::Format("hash table pos slice"))?,
    ) as u64;
    let mut block_table_pos = u32::from_le_bytes(
        raw[20..24]
            .try_into()
            .map_err(|_| StormError::Format("block table pos slice"))?,
    ) as u64;
    let hash_table_entries = u32::from_le_bytes(
        raw[24..28]
            .try_into()
            .map_err(|_| StormError::Format("hash table entries slice"))?,
    );
    let block_table_entries = u32::from_le_bytes(
        raw[28..32]
            .try_into()
            .map_err(|_| StormError::Format("block table entries slice"))?,
    );

    let mut hi_block_table_pos_64 = None;
    let mut hash_table_pos_hi = None;
    let mut block_table_pos_hi = None;
    let mut archive_size_64 = None;
    let mut bet_table_pos_64 = None;
    let mut het_table_pos_64 = None;
    let mut hash_table_size_64 = None;
    let mut block_table_size_64 = None;
    let mut hi_block_table_size_64 = None;
    let mut het_table_size_64 = None;
    let mut bet_table_size_64 = None;
    let mut raw_chunk_size = None;

    if header_size > MPQ_HEADER_SIZE_V1 {
        let extra = stream.read_at(
            archive_offset + MPQ_HEADER_SIZE_V1 as u64,
            (header_size - MPQ_HEADER_SIZE_V1) as usize,
        )?;
        let rd16 = |off: usize, what: &'static str| -> Result<u16> {
            let bytes = extra.get(off..off + 2).ok_or(StormError::Format(what))?;
            Ok(u16::from_le_bytes(
                bytes.try_into().map_err(|_| StormError::Format(what))?,
            ))
        };
        let rd32 = |off: usize, what: &'static str| -> Result<u32> {
            let bytes = extra.get(off..off + 4).ok_or(StormError::Format(what))?;
            Ok(u32::from_le_bytes(
                bytes.try_into().map_err(|_| StormError::Format(what))?,
            ))
        };
        let rd64 = |off: usize, what: &'static str| -> Result<u64> {
            let bytes = extra.get(off..off + 8).ok_or(StormError::Format(what))?;
            Ok(u64::from_le_bytes(
                bytes.try_into().map_err(|_| StormError::Format(what))?,
            ))
        };

        if format_version >= 1 && header_size >= MPQ_HEADER_SIZE_V2 {
            hi_block_table_pos_64 =
                Some(rd64(0, "extended hi-block table pos slice")?.saturating_add(archive_offset));
            hash_table_pos_hi = Some(rd16(8, "extended hash table pos hi slice")?);
            block_table_pos_hi = Some(rd16(10, "extended block table pos hi slice")?);

            if let Some(hash_hi) = hash_table_pos_hi.filter(|v| *v != 0) {
                hash_table_pos |= (hash_hi as u64) << 32;
            }
            if let Some(block_hi) = block_table_pos_hi.filter(|v| *v != 0) {
                block_table_pos |= (block_hi as u64) << 32;
            }
        }

        if format_version >= 2 && header_size >= MPQ_HEADER_SIZE_V3 {
            archive_size_64 = Some(rd64(12, "extended archive size64 slice")?);
            bet_table_pos_64 =
                Some(rd64(20, "extended bet table pos64 slice")?.saturating_add(archive_offset));
            het_table_pos_64 =
                Some(rd64(28, "extended het table pos64 slice")?.saturating_add(archive_offset));
        }

        if format_version >= 3 && header_size >= MPQ_HEADER_SIZE_V4 {
            hash_table_size_64 = Some(rd64(36, "extended hash table size64 slice")?);
            block_table_size_64 = Some(rd64(44, "extended block table size64 slice")?);
            hi_block_table_size_64 = Some(rd64(52, "extended hi-block table size64 slice")?);
            het_table_size_64 = Some(rd64(60, "extended het table size64 slice")?);
            bet_table_size_64 = Some(rd64(68, "extended bet table size64 slice")?);
            raw_chunk_size = Some(rd32(76, "extended raw chunk size slice")?);
        }
    }

    hash_table_pos = hash_table_pos.saturating_add(archive_offset);
    block_table_pos = block_table_pos.saturating_add(archive_offset);

    Ok(Header {
        archive_offset,
        header_size,
        archive_size_32,
        format_version,
        sector_size_shift,
        hash_table_pos,
        block_table_pos,
        hash_table_entries,
        block_table_entries,
        hi_block_table_pos_64,
        hash_table_pos_hi,
        block_table_pos_hi,
        archive_size_64,
        bet_table_pos_64,
        het_table_pos_64,
        hash_table_size_64,
        block_table_size_64,
        hi_block_table_size_64,
        het_table_size_64,
        bet_table_size_64,
        raw_chunk_size,
    })
}

pub fn read_tables(stream: &mut FileStream, header: &Header) -> Result<Tables> {
    let hash_len = header.hash_table_entries as usize * 16;
    let block_len = header.block_table_entries as usize * 16;

    let mut hash_bytes = stream.read_at(header.hash_table_pos, hash_len)?;
    let mut block_bytes = stream.read_at(header.block_table_pos, block_len)?;

    let hash_key = hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    let block_key = hash_string("(block table)", MPQ_HASH_FILE_KEY);
    decrypt_mpq_block(&mut hash_bytes, hash_key);
    decrypt_mpq_block(&mut block_bytes, block_key);

    Ok(Tables {
        hash_table: parse_hash_table(&hash_bytes)?,
        block_table: parse_block_table(&block_bytes)?,
    })
}

pub fn validate_header_basic(header: &Header, file_len: u64) -> Result<()> {
    if header.header_size < Header::V1_SIZE {
        return Err(StormError::Format("header too small"));
    }
    match header.format_version {
        0 if header.header_size < MPQ_HEADER_SIZE_V1 => {
            return Err(StormError::Format("v1 header too small"));
        }
        1 if header.header_size < MPQ_HEADER_SIZE_V2 => {
            return Err(StormError::Format("v2 header too small"));
        }
        2 if header.header_size < MPQ_HEADER_SIZE_V3 => {
            return Err(StormError::Format("v3 header too small"));
        }
        3 if header.header_size < MPQ_HEADER_SIZE_V4 => {
            return Err(StormError::Format("v4 header too small"));
        }
        4 if header.header_size < MPQ_HEADER_SIZE_V4 => {
            return Err(StormError::Format("v4 header too small"));
        }
        _ => {}
    }
    if header.format_version > 4 {
        return Err(StormError::UnsupportedFeature(
            "unknown MPQ header format version",
        ));
    }
    if header.hash_table_entries == 0 || !header.hash_table_entries.is_power_of_two() {
        return Err(StormError::Format(
            "hash table entry count must be non-zero power of two",
        ));
    }
    if header.block_table_entries == 0 {
        return Err(StormError::Format(
            "block table entry count must be non-zero",
        ));
    }

    let hash_end = header
        .hash_table_pos
        .checked_add(header.hash_table_entries as u64 * 16)
        .ok_or(StormError::Bounds("hash table range overflow"))?;
    let block_end = header
        .block_table_pos
        .checked_add(header.block_table_entries as u64 * 16)
        .ok_or(StormError::Bounds("block table range overflow"))?;
    if hash_end > file_len || block_end > file_len {
        return Err(StormError::Format("table range exceeds file length"));
    }
    if header.format_version >= 3 {
        for (pos, size) in [
            (header.het_table_pos_64, header.het_table_size_64),
            (header.bet_table_pos_64, header.bet_table_size_64),
        ] {
            if let (Some(pos), Some(size)) = (pos, size) {
                if pos == 0 || size == 0 {
                    continue;
                }
                let end = pos
                    .checked_add(size)
                    .ok_or(StormError::Bounds("extended table range overflow"))?;
                if end > file_len {
                    return Err(StormError::Format(
                        "extended table range exceeds file length",
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::error::StormError;
    use crate::stream::FileStream;

    use super::{read_header_at, validate_header_basic};

    fn sample_header_bytes() -> [u8; 32] {
        let mut raw = [0u8; 32];
        raw[0..4].copy_from_slice(&0x1A51_504Du32.to_le_bytes());
        raw[4..8].copy_from_slice(&32u32.to_le_bytes());
        raw[8..12].copy_from_slice(&1024u32.to_le_bytes());
        raw[12..14].copy_from_slice(&0u16.to_le_bytes());
        raw[14..16].copy_from_slice(&3u16.to_le_bytes());
        raw[16..20].copy_from_slice(&64u32.to_le_bytes());
        raw[20..24].copy_from_slice(&128u32.to_le_bytes());
        raw[24..28].copy_from_slice(&4u32.to_le_bytes());
        raw[28..32].copy_from_slice(&4u32.to_le_bytes());
        raw
    }

    fn build_header_bytes(header_size: u32, format_version: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 4096];
        bytes[0..4].copy_from_slice(&0x1A51_504Du32.to_le_bytes());
        bytes[4..8].copy_from_slice(&header_size.to_le_bytes());
        bytes[8..12].copy_from_slice(&4096u32.to_le_bytes());
        bytes[12..14].copy_from_slice(&format_version.to_le_bytes());
        bytes[14..16].copy_from_slice(&3u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&64u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&128u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&4u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&4u32.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_and_validates_basic_v1_header() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hdr.mpq");
        let mut fs = FileStream::create(&path).unwrap();
        let mut bytes = vec![0u8; 512];
        bytes[..32].copy_from_slice(&sample_header_bytes());
        fs.write_all(&bytes).unwrap();
        let h = read_header_at(&mut fs, 0).unwrap();
        validate_header_basic(&h, fs.len()).unwrap();
        assert_eq!(h.hash_table_entries, 4);
    }

    #[test]
    fn parses_v4_extended_header_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hdr-v4.mpq");
        let mut fs = FileStream::create(&path).unwrap();
        let mut bytes = vec![0u8; 1024];

        bytes[0..4].copy_from_slice(&0x1A51_504Du32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0xD0u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&1024u32.to_le_bytes());
        bytes[12..14].copy_from_slice(&3u16.to_le_bytes());
        bytes[14..16].copy_from_slice(&3u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&64u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&128u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&4u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&4u32.to_le_bytes());

        bytes[32..40].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        bytes[40..42].copy_from_slice(&0x0001u16.to_le_bytes());
        bytes[42..44].copy_from_slice(&0x0002u16.to_le_bytes());
        bytes[44..52].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[52..60].copy_from_slice(&0x2000u64.to_le_bytes());
        bytes[60..68].copy_from_slice(&0x3000u64.to_le_bytes());
        bytes[68..76].copy_from_slice(&0x400u64.to_le_bytes());
        bytes[76..84].copy_from_slice(&0x500u64.to_le_bytes());
        bytes[84..92].copy_from_slice(&0x600u64.to_le_bytes());
        bytes[92..100].copy_from_slice(&0x700u64.to_le_bytes());
        bytes[100..108].copy_from_slice(&0x800u64.to_le_bytes());
        bytes[108..112].copy_from_slice(&0x10000u32.to_le_bytes());

        fs.write_all(&bytes).unwrap();
        let h = read_header_at(&mut fs, 0).unwrap();

        assert_eq!(h.format_version, 3);
        assert_eq!(h.hash_table_pos_hi, Some(0x0001));
        assert_eq!(h.block_table_pos_hi, Some(0x0002));
        assert_eq!(h.hash_table_pos, (1u64 << 32) | 64);
        assert_eq!(h.block_table_pos, (2u64 << 32) | 128);
        assert_eq!(h.archive_size_64, Some(0x1000));
        assert_eq!(h.bet_table_pos_64, Some(0x2000));
        assert_eq!(h.het_table_pos_64, Some(0x3000));
        assert_eq!(h.hash_table_size_64, Some(0x400));
        assert_eq!(h.block_table_size_64, Some(0x500));
        assert_eq!(h.hi_block_table_size_64, Some(0x600));
        assert_eq!(h.het_table_size_64, Some(0x700));
        assert_eq!(h.bet_table_size_64, Some(0x800));
        assert_eq!(h.raw_chunk_size, Some(0x10000));
    }

    #[test]
    fn header_format_version_matrix_has_explicit_pass_fail_expectations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hdr-matrix.mpq");
        let mut fs = FileStream::create(&path).unwrap();

        for (fmt, size, should_pass) in [
            (0u16, 0x20u32, true), // v1
            (1u16, 0x2Cu32, true), // v2
            (2u16, 0x44u32, true), // v3
            (3u16, 0xD0u32, true), // v4
            (4u16, 0xD0u32, true), // v4+ header acceptance
        ] {
            let bytes = build_header_bytes(size, fmt);
            fs.seek(std::io::SeekFrom::Start(0)).unwrap();
            fs.write_all(&bytes).unwrap();
            fs.flush().unwrap();

            let h = read_header_at(&mut fs, 0).unwrap();
            let res = validate_header_basic(&h, fs.len());
            if should_pass {
                assert!(res.is_ok(), "fmt={fmt} size={size} res={res:?}");
            } else {
                assert!(matches!(
                    res,
                    Err(StormError::UnsupportedFeature(
                        "unknown MPQ header format version"
                    ))
                ));
            }
        }
    }

    #[test]
    fn v2_large_high_offset_fails_range_validation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hdr-v2-large.mpq");
        let mut fs = FileStream::create(&path).unwrap();
        let mut bytes = build_header_bytes(0x2C, 1);
        bytes[40..42].copy_from_slice(&0x0001u16.to_le_bytes());
        fs.write_all(&bytes).unwrap();

        let h = read_header_at(&mut fs, 0).unwrap();
        let err = validate_header_basic(&h, fs.len()).unwrap_err();
        assert!(matches!(
            err,
            StormError::Format("table range exceeds file length")
        ));
    }

    #[test]
    fn v4_extended_table_range_exceeding_file_len_fails_validation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hdr-v4-ext-range.mpq");
        let mut fs = FileStream::create(&path).unwrap();
        let mut bytes = build_header_bytes(0xD0, 3);

        bytes[52..60].copy_from_slice(&0x0F00u64.to_le_bytes());
        bytes[100..108].copy_from_slice(&0x0200u64.to_le_bytes());

        fs.write_all(&bytes).unwrap();
        let h = read_header_at(&mut fs, 0).unwrap();
        let err = validate_header_basic(&h, fs.len()).unwrap_err();
        assert!(matches!(
            err,
            StormError::Format("extended table range exceeds file length")
        ));
    }
}
