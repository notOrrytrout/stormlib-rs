use crate::crypto::md5_digest;
use crate::error::{Result, StormError};
use crate::types::{AddFileOptions, ManifestEntry, MpqArchive, MpqFileFlags};

const ATTR_VERSION_V1: u32 = 100;
const MPQ_ATTRIBUTE_CRC32: u32 = 0x0000_0001;
const MPQ_ATTRIBUTE_FILETIME: u32 = 0x0000_0002;
const MPQ_ATTRIBUTE_MD5: u32 = 0x0000_0004;
const MPQ_ATTRIBUTE_PATCH_BIT: u32 = 0x0000_0008;
const MPQ_ATTRIBUTE_ALL: u32 =
    MPQ_ATTRIBUTE_CRC32 | MPQ_ATTRIBUTE_FILETIME | MPQ_ATTRIBUTE_MD5 | MPQ_ATTRIBUTE_PATCH_BIT;

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let mut x = (crc ^ b as u32) & 0xFF;
        for _ in 0..8 {
            x = if (x & 1) != 0 {
                (x >> 1) ^ 0xEDB8_8320
            } else {
                x >> 1
            };
        }
        crc = (crc >> 8) ^ x;
    }
    !crc
}

pub(crate) fn build_default_attributes_stub(
    entries_without_attributes: &[ManifestEntry],
) -> Result<Vec<u8>> {
    let entry_count = entries_without_attributes.len().saturating_add(1);
    let mut crc32 = Vec::with_capacity(entry_count);
    let mut md5 = Vec::with_capacity(entry_count);
    for entry in entries_without_attributes {
        crc32.push(crc32_ieee(&entry.data));
        md5.push(md5_digest(&entry.data));
    }
    crc32.push(0);
    md5.push([0u8; 16]);
    serialize_attributes_file(&AttributesFile {
        version: ATTR_VERSION_V1,
        flags: MPQ_ATTRIBUTE_CRC32 | MPQ_ATTRIBUTE_FILETIME | MPQ_ATTRIBUTE_MD5,
        entry_count,
        crc32,
        md5,
        ..AttributesFile::default()
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttributesFile {
    pub version: u32,
    pub flags: u32,
    pub entry_count: usize,
    pub crc32: Vec<u32>,
    pub file_time_low: Vec<u32>,
    pub file_time_high: Vec<u32>,
    pub md5: Vec<[u8; 16]>,
    pub patch_bits: Vec<bool>,
}

impl MpqArchive {
    pub fn read_attributes(&mut self) -> Result<Option<AttributesFile>> {
        if !self.has_file("(attributes)") {
            return Ok(None);
        }
        let data = self.read_file("(attributes)")?;
        let expected = Some(self.tables.block_table.len());
        match parse_attributes_file_with_expected_entries(&data, expected) {
            Ok(parsed) => Ok(Some(parsed)),
            Err(StormError::Format(_)) => match parse_attributes_file(&data) {
                Ok(parsed) => Ok(Some(parsed)),
                Err(StormError::Format(_)) => self
                    .build_attributes_from_archive(MPQ_ATTRIBUTE_ALL)
                    .map(Some),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        }
    }

    pub fn write_attributes_stub(&mut self, attrs: &AttributesFile) -> Result<()> {
        let data =
            serialize_attributes_file_with_entry_count(attrs, Some(self.tables.block_table.len()))?;
        self.add_file_from_bytes(
            "(attributes)",
            &data,
            AddFileOptions {
                compression: Some(crate::compression::CompressionMethod::Zlib),
                encrypted: true,
                fix_key: true,
                locale: 0,
                platform: 0,
                single_unit: true,
                sector_crc: false,
            },
        )
    }

    pub fn build_attributes_from_archive(&mut self, flags: u32) -> Result<AttributesFile> {
        if flags & !MPQ_ATTRIBUTE_ALL != 0 {
            return Err(StormError::InvalidInput(
                "attributes flags contain unsupported bits",
            ));
        }

        let entry_count = self.tables.block_table.len();
        let mut crc32 = vec![0u32; entry_count];
        let file_time_low = vec![0u32; entry_count];
        let file_time_high = vec![0u32; entry_count];
        let mut md5 = vec![[0u8; 16]; entry_count];
        let mut patch_bits = vec![false; entry_count];

        let items = self.list()?;
        for item in items {
            if item.block_index >= entry_count {
                continue;
            }
            let idx = item.block_index;
            patch_bits[idx] = item.flags.contains(MpqFileFlags::PATCH_FILE);

            if let Some(name) = item.name {
                let bytes = self.read_file(&name)?;
                crc32[idx] = crc32_ieee(&bytes);
                md5[idx] = md5_digest(&bytes);
            }
        }

        Ok(AttributesFile {
            version: ATTR_VERSION_V1,
            flags,
            entry_count,
            crc32,
            file_time_low,
            file_time_high,
            md5,
            patch_bits,
        })
    }

    pub fn sync_attributes(&mut self, flags: u32) -> Result<()> {
        let attrs = self.build_attributes_from_archive(flags)?;
        self.write_attributes_stub(&attrs)
    }
}

pub fn parse_attributes_file(data: &[u8]) -> Result<AttributesFile> {
    parse_attributes_file_with_expected_entries(data, None)
}

pub fn parse_attributes_file_with_expected_entries(
    data: &[u8],
    expected_entries: Option<usize>,
) -> Result<AttributesFile> {
    if data.len() < 8 {
        return Err(StormError::Format("(attributes) file too small"));
    }
    let version = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| StormError::Format("attributes version"))?,
    );
    let flags = u32::from_le_bytes(
        data[4..8]
            .try_into()
            .map_err(|_| StormError::Format("attributes flags"))?,
    );
    if version != ATTR_VERSION_V1 {
        return Err(StormError::Format("unsupported (attributes) version"));
    }
    if flags & !MPQ_ATTRIBUTE_ALL != 0 {
        return Err(StormError::Format("unsupported (attributes) flags"));
    }

    let entry_count = match expected_entries {
        Some(entries) => check_size_of_attributes_file(data.len(), flags, entries).ok_or(
            StormError::Format("invalid (attributes) size for block table"),
        )?,
        None => infer_entry_count(data.len(), flags).ok_or(StormError::Format(
            "unable to infer (attributes) entry count",
        ))?,
    };

    let mut off = 8usize;

    let mut crc32 = Vec::new();
    if flags & MPQ_ATTRIBUTE_CRC32 != 0 {
        let bytes_len = entry_count
            .checked_mul(4)
            .ok_or(StormError::Bounds("attributes CRC size overflow"))?;
        let bytes = data
            .get(off..off + bytes_len)
            .ok_or(StormError::Format("attributes CRC truncated"))?;
        crc32.reserve(entry_count);
        for chunk in bytes.chunks_exact(4) {
            crc32.push(u32::from_le_bytes(
                chunk
                    .try_into()
                    .map_err(|_| StormError::Format("attributes CRC value"))?,
            ));
        }
        off += bytes_len;
    }

    let mut file_time_low = Vec::new();
    let mut file_time_high = Vec::new();
    if flags & MPQ_ATTRIBUTE_FILETIME != 0 {
        let bytes_len = entry_count
            .checked_mul(8)
            .ok_or(StormError::Bounds("attributes FILETIME size overflow"))?;
        let bytes = data
            .get(off..off + bytes_len)
            .ok_or(StormError::Format("attributes FILETIME truncated"))?;
        file_time_low.reserve(entry_count);
        file_time_high.reserve(entry_count);
        for chunk in bytes.chunks_exact(8) {
            let value = u64::from_le_bytes(
                chunk
                    .try_into()
                    .map_err(|_| StormError::Format("attributes FILETIME value"))?,
            );
            file_time_low.push(value as u32);
            file_time_high.push((value >> 32) as u32);
        }
        off += bytes_len;
    }

    let mut md5 = Vec::new();
    if flags & MPQ_ATTRIBUTE_MD5 != 0 {
        let bytes_len = entry_count
            .checked_mul(16)
            .ok_or(StormError::Bounds("attributes MD5 size overflow"))?;
        let bytes = data
            .get(off..off + bytes_len)
            .ok_or(StormError::Format("attributes MD5 truncated"))?;
        md5.reserve(entry_count);
        for chunk in bytes.chunks_exact(16) {
            let mut digest = [0u8; 16];
            digest.copy_from_slice(chunk);
            md5.push(digest);
        }
        off += bytes_len;
    }

    let mut patch_bits = Vec::new();
    if flags & MPQ_ATTRIBUTE_PATCH_BIT != 0 {
        let bit_array_len = entry_count.div_ceil(8);
        let dword_array_len = entry_count
            .checked_mul(4)
            .ok_or(StormError::Bounds("attributes patch bit size overflow"))?;
        if data.len().saturating_sub(off) == bit_array_len {
            let bits = &data[off..off + bit_array_len];
            patch_bits.reserve(entry_count);
            for i in 0..entry_count {
                let byte_index = i / 8;
                let bit_mask = 0x80u8 >> (i % 8);
                patch_bits.push((bits[byte_index] & bit_mask) != 0);
            }
            off += bit_array_len;
        } else if data.len().saturating_sub(off) == dword_array_len {
            let bytes = &data[off..off + dword_array_len];
            patch_bits.reserve(entry_count);
            for chunk in bytes.chunks_exact(4) {
                let v = u32::from_le_bytes(
                    chunk
                        .try_into()
                        .map_err(|_| StormError::Format("attributes patch dword value"))?,
                );
                patch_bits.push(v != 0);
            }
            off += dword_array_len;
        }
    }

    if off > data.len() {
        return Err(StormError::Format("attributes parser overflow"));
    }

    Ok(AttributesFile {
        version,
        flags,
        entry_count,
        crc32,
        file_time_low,
        file_time_high,
        md5,
        patch_bits,
    })
}

pub fn serialize_attributes_file(attrs: &AttributesFile) -> Result<Vec<u8>> {
    if attrs.version != ATTR_VERSION_V1 {
        return Err(StormError::InvalidInput("attributes version must be 100"));
    }
    if attrs.flags & !MPQ_ATTRIBUTE_ALL != 0 {
        return Err(StormError::InvalidInput(
            "attributes flags contain unsupported bits",
        ));
    }

    serialize_attributes_file_with_entry_count(attrs, None)
}

fn serialize_attributes_file_with_entry_count(
    attrs: &AttributesFile,
    forced_entry_count: Option<usize>,
) -> Result<Vec<u8>> {
    let inferred = attrs
        .entry_count
        .max(attrs.crc32.len())
        .max(attrs.file_time_low.len())
        .max(attrs.file_time_high.len())
        .max(attrs.md5.len())
        .max(attrs.patch_bits.len());
    let entry_count = forced_entry_count.unwrap_or(inferred).max(inferred);

    let mut out = Vec::new();
    out.extend_from_slice(&attrs.version.to_le_bytes());
    out.extend_from_slice(&attrs.flags.to_le_bytes());

    if attrs.flags & MPQ_ATTRIBUTE_CRC32 != 0 {
        for i in 0..entry_count {
            let v = attrs.crc32.get(i).copied().unwrap_or(0);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    if attrs.flags & MPQ_ATTRIBUTE_FILETIME != 0 {
        for i in 0..entry_count {
            let lo = attrs.file_time_low.get(i).copied().unwrap_or(0);
            let hi = attrs.file_time_high.get(i).copied().unwrap_or(0);
            let v = ((hi as u64) << 32) | (lo as u64);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    if attrs.flags & MPQ_ATTRIBUTE_MD5 != 0 {
        for i in 0..entry_count {
            let digest = attrs.md5.get(i).copied().unwrap_or([0u8; 16]);
            out.extend_from_slice(&digest);
        }
    }
    if attrs.flags & MPQ_ATTRIBUTE_PATCH_BIT != 0 {
        let bit_len = (entry_count + 6) / 8;
        let mut bit_array = vec![0u8; bit_len.saturating_add(1)];
        for i in 0..entry_count {
            if attrs.patch_bits.get(i).copied().unwrap_or(false) {
                let byte_index = i / 8;
                let bit_mask = 0x80u8 >> (i % 8);
                bit_array[byte_index] |= bit_mask;
            }
        }
        out.extend_from_slice(&bit_array[..bit_len]);
    }
    Ok(out)
}

fn check_size_of_attributes_file(
    cb_attr_file: usize,
    flags: u32,
    block_table_size: usize,
) -> Option<usize> {
    let header_size = 8usize;
    let checksum1 = if flags & MPQ_ATTRIBUTE_CRC32 != 0 {
        block_table_size.checked_mul(4)?
    } else {
        0
    };
    let checksum2 = checksum1.saturating_sub(4);

    let file_time1 = if flags & MPQ_ATTRIBUTE_FILETIME != 0 {
        block_table_size.checked_mul(8)?
    } else {
        0
    };
    let file_time2 = file_time1.saturating_sub(8);

    let md51 = if flags & MPQ_ATTRIBUTE_MD5 != 0 {
        block_table_size.checked_mul(16)?
    } else {
        0
    };
    let md52 = md51.saturating_sub(16);

    let patch_bit1 = if flags & MPQ_ATTRIBUTE_PATCH_BIT != 0 {
        (block_table_size + 6) / 8
    } else {
        0
    };
    let patch_bit2 = patch_bit1;
    let patch_bit3 = if flags & MPQ_ATTRIBUTE_PATCH_BIT != 0 {
        block_table_size.checked_mul(4)?
    } else {
        0
    };

    if cb_attr_file == header_size + checksum1 + file_time1 + md51 + patch_bit1 {
        return Some(block_table_size);
    }
    if block_table_size > 0
        && cb_attr_file == header_size + checksum2 + file_time2 + md52 + patch_bit2
    {
        return Some(block_table_size - 1);
    }
    if cb_attr_file == header_size + checksum1 + file_time1 + md51 {
        return Some(block_table_size);
    }
    if cb_attr_file == header_size + checksum1 + file_time1 + md51 + patch_bit3 {
        return Some(block_table_size);
    }
    None
}

fn infer_entry_count(cb_attr_file: usize, flags: u32) -> Option<usize> {
    if cb_attr_file < 8 {
        return None;
    }
    for mid in 0..=cb_attr_file {
        if let Some(entries) = check_size_of_attributes_file(cb_attr_file, flags, mid) {
            return Some(entries);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        parse_attributes_file, parse_attributes_file_with_expected_entries,
        serialize_attributes_file, AttributesFile,
    };
    use crate::types::{AddFileOptions, CreateOptions, MpqArchive, MpqFileFlags};

    #[test]
    fn attributes_roundtrip() {
        let a = AttributesFile {
            version: 100,
            flags: 0x0F,
            entry_count: 2,
            crc32: vec![1, 2],
            file_time_low: vec![3, 5],
            file_time_high: vec![4, 6],
            md5: vec![[0xAA; 16], [0xBB; 16]],
            patch_bits: vec![true, false],
        };
        let bytes = serialize_attributes_file(&a).unwrap();
        let b = parse_attributes_file(&bytes).unwrap();
        assert_eq!(b.version, 100);
        assert_eq!(b.entry_count, 2);
        assert_eq!(b.crc32, vec![1, 2]);
        assert_eq!(b.file_time_low, vec![3, 5]);
        assert_eq!(b.file_time_high, vec![4, 6]);
        assert_eq!(b.md5.len(), 2);
        assert_eq!(b.patch_bits, vec![true, false]);
    }

    #[test]
    fn write_attributes_stub_pads_to_block_table_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attrs.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive
            .add_file_from_bytes("a.txt", b"abc", AddFileOptions::default())
            .unwrap();

        let attrs = AttributesFile {
            version: 100,
            flags: 0x01,
            entry_count: 0,
            crc32: vec![0xDEAD_BEEF],
            file_time_low: Vec::new(),
            file_time_high: Vec::new(),
            md5: Vec::new(),
            patch_bits: Vec::new(),
        };
        archive.write_attributes_stub(&attrs).unwrap();

        let parsed = archive.read_attributes().unwrap().unwrap();
        assert_eq!(parsed.entry_count, archive.tables.block_table.len());
    }

    #[test]
    fn serialize_patch_bits_matches_stormlib_short_bitarray_quirk() {
        let attrs = AttributesFile {
            version: 100,
            flags: 0x08,
            entry_count: 9,
            crc32: Vec::new(),
            file_time_low: Vec::new(),
            file_time_high: Vec::new(),
            md5: Vec::new(),
            patch_bits: vec![true; 9],
        };

        let bytes = serialize_attributes_file(&attrs).unwrap();
        assert_eq!(bytes.len(), 8 + ((9 + 6) / 8));

        let parsed = parse_attributes_file_with_expected_entries(&bytes, Some(9)).unwrap();
        assert_eq!(parsed.entry_count, 9);
    }

    #[test]
    fn sync_attributes_builds_crc_and_md5_from_named_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync_attrs.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive
            .add_file_from_bytes("alpha.txt", b"alpha", AddFileOptions::default())
            .unwrap();

        archive.sync_attributes(0x07).unwrap();
        let attrs = archive.read_attributes().unwrap().unwrap();

        let alpha_item = archive
            .list()
            .unwrap()
            .into_iter()
            .find(|it| it.name.as_deref() == Some("alpha.txt"))
            .unwrap();
        assert_eq!(
            attrs.crc32[alpha_item.block_index],
            super::crc32_ieee(b"alpha")
        );
        assert_eq!(
            attrs.md5[alpha_item.block_index],
            crate::crypto::md5_digest(b"alpha")
        );
    }

    #[test]
    fn write_attributes_stub_uses_internal_special_file_flags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attrs_flags.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive
            .add_file_from_bytes("f.bin", b"1234", AddFileOptions::default())
            .unwrap();
        archive.sync_attributes(0x07).unwrap();

        let attrs_item = archive
            .list()
            .unwrap()
            .into_iter()
            .find(|it| it.name.as_deref() == Some("(attributes)"))
            .unwrap();
        assert!(attrs_item.flags.contains(MpqFileFlags::COMPRESS));
        assert!(attrs_item.flags.contains(MpqFileFlags::ENCRYPTED));
        assert!(attrs_item.flags.contains(MpqFileFlags::FIX_KEY));
        assert!(!attrs_item.flags.contains(MpqFileFlags::SINGLE_UNIT));
    }
}
