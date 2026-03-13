use crate::error::{Result, StormError};
use crate::internal::common::{
    hash_string, MPQ_HASH_NAME_A, MPQ_HASH_NAME_B, MPQ_HASH_TABLE_INDEX,
};
use crate::types::{BlockTableEntry, HashTableEntry, MpqFileFlags};

pub fn parse_hash_table(bytes: &[u8]) -> Result<Vec<HashTableEntry>> {
    if !bytes.len().is_multiple_of(HashTableEntry::SERIALIZED_LEN) {
        return Err(StormError::Format(
            "hash table byte length is not a multiple of 16",
        ));
    }

    let mut out = Vec::with_capacity(bytes.len() / HashTableEntry::SERIALIZED_LEN);
    for chunk in bytes.chunks_exact(HashTableEntry::SERIALIZED_LEN) {
        let hash_a = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let hash_b = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let locale = u16::from_le_bytes(chunk[8..10].try_into().unwrap());
        let platform = chunk[10];
        let flags = chunk[11];
        let block_index = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
        out.push(HashTableEntry {
            hash_a,
            hash_b,
            locale,
            platform,
            flags,
            block_index,
        });
    }
    Ok(out)
}

pub fn parse_block_table(bytes: &[u8]) -> Result<Vec<BlockTableEntry>> {
    if !bytes.len().is_multiple_of(BlockTableEntry::SERIALIZED_LEN) {
        return Err(StormError::Format(
            "block table byte length is not a multiple of 16",
        ));
    }

    let mut out = Vec::with_capacity(bytes.len() / BlockTableEntry::SERIALIZED_LEN);
    for chunk in bytes.chunks_exact(BlockTableEntry::SERIALIZED_LEN) {
        out.push(BlockTableEntry {
            file_pos: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
            compressed_size: u32::from_le_bytes(chunk[4..8].try_into().unwrap()),
            file_size: u32::from_le_bytes(chunk[8..12].try_into().unwrap()),
            flags: MpqFileFlags::from_bits_retain(u32::from_le_bytes(
                chunk[12..16].try_into().unwrap(),
            )),
        });
    }
    Ok(out)
}

pub fn serialize_hash_table(entries: &[HashTableEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * HashTableEntry::SERIALIZED_LEN);
    for e in entries {
        out.extend_from_slice(&e.hash_a.to_le_bytes());
        out.extend_from_slice(&e.hash_b.to_le_bytes());
        out.extend_from_slice(&e.locale.to_le_bytes());
        out.push(e.platform);
        out.push(e.flags);
        out.extend_from_slice(&e.block_index.to_le_bytes());
    }
    out
}

pub fn serialize_block_table(entries: &[BlockTableEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * BlockTableEntry::SERIALIZED_LEN);
    for e in entries {
        out.extend_from_slice(&e.file_pos.to_le_bytes());
        out.extend_from_slice(&e.compressed_size.to_le_bytes());
        out.extend_from_slice(&e.file_size.to_le_bytes());
        out.extend_from_slice(&e.flags.bits().to_le_bytes());
    }
    out
}

pub fn empty_hash_table(len: usize) -> Vec<HashTableEntry> {
    vec![
        HashTableEntry {
            hash_a: u32::MAX,
            hash_b: u32::MAX,
            locale: u16::MAX,
            platform: u8::MAX,
            flags: u8::MAX,
            block_index: HashTableEntry::BLOCK_INDEX_FREE,
        };
        len
    ]
}

pub fn empty_block_table(len: usize) -> Vec<BlockTableEntry> {
    vec![
        BlockTableEntry {
            file_pos: 0,
            compressed_size: 0,
            file_size: 0,
            flags: MpqFileFlags::empty()
        };
        len
    ]
}

pub fn insert_hash_entry(
    entries: &mut [HashTableEntry],
    block_table_len: usize,
    name: &str,
    block_index: u32,
    locale: u16,
    platform: u8,
) -> Result<usize> {
    if entries.is_empty() || !entries.len().is_power_of_two() {
        return Err(StormError::Format(
            "hash table must be non-empty and power-of-two sized",
        ));
    }
    if (block_index as usize) >= block_table_len {
        return Err(StormError::Bounds(
            "block index out of range for hash table insert",
        ));
    }

    let start_hash = hash_string(name, MPQ_HASH_TABLE_INDEX);
    let hash_a = hash_string(name, MPQ_HASH_NAME_A);
    let hash_b = hash_string(name, MPQ_HASH_NAME_B);
    let start = (start_hash as usize) & (entries.len() - 1);
    let mut idx = start;
    loop {
        let cur = entries[idx];
        if cur.is_free() || cur.is_deleted() {
            entries[idx] = HashTableEntry {
                hash_a,
                hash_b,
                locale,
                platform,
                flags: 0,
                block_index,
            };
            return Ok(idx);
        }
        if cur.hash_a == hash_a && cur.hash_b == hash_b && cur.locale == locale {
            entries[idx].block_index = block_index;
            entries[idx].platform = platform;
            return Ok(idx);
        }
        idx = (idx + 1) & (entries.len() - 1);
        if idx == start {
            return Err(StormError::Format("hash table is full"));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupMatch {
    pub hash_index: usize,
    pub block_index: usize,
}

pub fn lookup_file_name(
    entries: &[HashTableEntry],
    block_table_len: usize,
    name: &str,
) -> Option<LookupMatch> {
    lookup_hash_entry(
        entries,
        block_table_len,
        hash_string(name, MPQ_HASH_TABLE_INDEX),
        hash_string(name, MPQ_HASH_NAME_A),
        hash_string(name, MPQ_HASH_NAME_B),
    )
}

pub fn lookup_file_name_with_locale(
    entries: &[HashTableEntry],
    block_table_len: usize,
    name: &str,
    locale: u16,
) -> Option<LookupMatch> {
    lookup_hash_entry_with_locale(
        entries,
        block_table_len,
        hash_string(name, MPQ_HASH_TABLE_INDEX),
        hash_string(name, MPQ_HASH_NAME_A),
        hash_string(name, MPQ_HASH_NAME_B),
        locale,
    )
}

pub fn lookup_hash_entry(
    entries: &[HashTableEntry],
    block_table_len: usize,
    start_hash: u32,
    hash_a: u32,
    hash_b: u32,
) -> Option<LookupMatch> {
    if entries.is_empty() || !entries.len().is_power_of_two() {
        return None;
    }

    let mask = entries.len() - 1;
    let start = (start_hash as usize) & mask;
    let mut idx = start;
    loop {
        let e = entries[idx];

        if e.hash_a == hash_a && e.hash_b == hash_b && (e.block_index as usize) < block_table_len {
            return Some(LookupMatch {
                hash_index: idx,
                block_index: e.block_index as usize,
            });
        }

        if e.is_free() {
            return None;
        }

        idx = (idx + 1) & mask;
        if idx == start {
            return None;
        }
    }
}

pub fn lookup_hash_entry_with_locale(
    entries: &[HashTableEntry],
    block_table_len: usize,
    start_hash: u32,
    hash_a: u32,
    hash_b: u32,
    locale: u16,
) -> Option<LookupMatch> {
    if entries.is_empty() || !entries.len().is_power_of_two() {
        return None;
    }

    let mask = entries.len() - 1;
    let start = (start_hash as usize) & mask;
    let mut idx = start;
    let mut neutral: Option<LookupMatch> = None;
    let mut first_any: Option<LookupMatch> = None;

    loop {
        let e = entries[idx];

        if e.hash_a == hash_a && e.hash_b == hash_b && (e.block_index as usize) < block_table_len {
            let m = LookupMatch {
                hash_index: idx,
                block_index: e.block_index as usize,
            };
            if first_any.is_none() {
                first_any = Some(m);
            }
            if e.locale == locale {
                return Some(m);
            }
            if e.locale == 0 && neutral.is_none() {
                neutral = Some(m);
            }
        }

        if e.is_free() {
            return neutral.or(first_any);
        }

        idx = (idx + 1) & mask;
        if idx == start {
            return neutral.or(first_any);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::common::{MPQ_HASH_NAME_A, MPQ_HASH_NAME_B, MPQ_HASH_TABLE_INDEX};

    fn hash_entry_for(name: &str, block_index: u32) -> HashTableEntry {
        HashTableEntry {
            hash_a: hash_string(name, MPQ_HASH_NAME_A),
            hash_b: hash_string(name, MPQ_HASH_NAME_B),
            locale: 0,
            platform: 0,
            flags: 0,
            block_index,
        }
    }

    #[test]
    fn parse_hash_and_block_tables() {
        let mut hash_bytes = Vec::new();
        hash_bytes.extend_from_slice(&1u32.to_le_bytes());
        hash_bytes.extend_from_slice(&2u32.to_le_bytes());
        hash_bytes.extend_from_slice(&3u16.to_le_bytes());
        hash_bytes.extend_from_slice(&[4, 5]);
        hash_bytes.extend_from_slice(&6u32.to_le_bytes());
        let hashes = parse_hash_table(&hash_bytes).unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].locale, 3);
        assert_eq!(hashes[0].platform, 4);
        assert_eq!(hashes[0].flags, 5);
        assert_eq!(hashes[0].block_index, 6);

        let mut block_bytes = Vec::new();
        block_bytes.extend_from_slice(&10u32.to_le_bytes());
        block_bytes.extend_from_slice(&11u32.to_le_bytes());
        block_bytes.extend_from_slice(&12u32.to_le_bytes());
        block_bytes.extend_from_slice(&MpqFileFlags::EXISTS.bits().to_le_bytes());
        let blocks = parse_block_table(&block_bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].file_pos, 10);
        assert!(blocks[0].flags.contains(MpqFileFlags::EXISTS));
    }

    #[test]
    fn lookup_handles_collision_and_linear_probe() {
        let mut entries = vec![
            HashTableEntry {
                hash_a: 0,
                hash_b: 0,
                locale: 0,
                platform: 0,
                flags: 0,
                block_index: HashTableEntry::BLOCK_INDEX_FREE,
            };
            8
        ];

        let a = "a.txt";
        let b = "b.txt";
        let start_a = (hash_string(a, MPQ_HASH_TABLE_INDEX) as usize) & 7;
        let start_b = (hash_string(b, MPQ_HASH_TABLE_INDEX) as usize) & 7;

        entries[start_a] = hash_entry_for(a, 1);
        let collision_slot = if start_b == start_a {
            (start_b + 1) & 7
        } else {
            start_b
        };
        entries[collision_slot] = hash_entry_for(b, 2);
        if start_b == start_a {
            // occupy initial slot with a non-matching valid entry to force probing
            entries[start_b] = hash_entry_for(a, 1);
        }

        let m1 = lookup_file_name(&entries, 10, a).unwrap();
        assert_eq!(m1.block_index, 1);
        let m2 = lookup_file_name(&entries, 10, b).unwrap();
        assert_eq!(m2.block_index, 2);
    }

    #[test]
    fn lookup_rejects_invalid_block_index_and_stops_on_free() {
        let name = "bad.bin";
        let start = (hash_string(name, MPQ_HASH_TABLE_INDEX) as usize) & 3;
        let mut entries = vec![
            HashTableEntry {
                hash_a: 0,
                hash_b: 0,
                locale: 0,
                platform: 0,
                flags: 0,
                block_index: HashTableEntry::BLOCK_INDEX_FREE,
            };
            4
        ];
        entries[start] = hash_entry_for(name, 99);
        entries[(start + 1) & 3].block_index = HashTableEntry::BLOCK_INDEX_FREE;

        assert!(lookup_file_name(&entries, 10, name).is_none());
        assert!(lookup_hash_entry(&entries, 0, 0, 0, 0).is_none());
    }

    #[test]
    fn lookup_with_locale_prefers_exact_then_neutral_then_any() {
        let name = "loc.txt";
        let mut entries = vec![
            HashTableEntry {
                hash_a: 0,
                hash_b: 0,
                locale: 0,
                platform: 0,
                flags: 0,
                block_index: HashTableEntry::BLOCK_INDEX_FREE,
            };
            8
        ];

        let start = (hash_string(name, MPQ_HASH_TABLE_INDEX) as usize) & 7;
        let hash_a = hash_string(name, MPQ_HASH_NAME_A);
        let hash_b = hash_string(name, MPQ_HASH_NAME_B);

        entries[start] = HashTableEntry {
            hash_a,
            hash_b,
            locale: 0x0409,
            platform: 0,
            flags: 0,
            block_index: 1,
        };
        entries[(start + 1) & 7] = HashTableEntry {
            hash_a,
            hash_b,
            locale: 0,
            platform: 0,
            flags: 0,
            block_index: 2,
        };

        let exact = lookup_file_name_with_locale(&entries, 10, name, 0x0409).unwrap();
        assert_eq!(exact.block_index, 1);
        let neutral = lookup_file_name_with_locale(&entries, 10, name, 0x0419).unwrap();
        assert_eq!(neutral.block_index, 2);
    }
}
