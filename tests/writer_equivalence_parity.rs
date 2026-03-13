use std::collections::BTreeMap;

#[cfg(feature = "compression-zlib")]
use stormlib_rs::CompressionMethod;
#[cfg(feature = "compression-zlib-native")]
use stormlib_rs::{decrypt_mpq_block, derive_file_key};
use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive, MpqFileFlags};

fn fill_beta(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x = 0x9E37_79B9u32;
    for b in &mut out {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    out
}

#[allow(dead_code)]
fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

#[allow(dead_code)]
fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[allow(dead_code)]
fn first_diff(left: &[u8], right: &[u8]) -> Option<usize> {
    let n = left.len().min(right.len());
    for i in 0..n {
        if left[i] != right[i] {
            return Some(i);
        }
    }
    if left.len() != right.len() {
        return Some(n);
    }
    None
}

fn canonical_subset(path: &std::path::Path) -> BTreeMap<String, (MpqFileFlags, Vec<u8>)> {
    let mut archive = MpqArchive::open(path).expect("open archive");
    let items = archive.list().expect("list archive");
    let mut out = BTreeMap::new();
    let mask = MpqFileFlags::EXISTS
        | MpqFileFlags::COMPRESS
        | MpqFileFlags::SINGLE_UNIT
        | MpqFileFlags::ENCRYPTED
        | MpqFileFlags::FIX_KEY;

    for name in ["alpha.txt", "beta.bin"] {
        let item = items
            .iter()
            .find(|it| it.name.as_deref() == Some(name))
            .expect("find listed file");
        let data = archive.read_file(name).expect("read file");
        out.insert(name.to_string(), (item.flags & mask, data));
    }
    out
}

#[cfg(feature = "compression-zlib")]
#[test]
fn rust_writer_matches_stormlib_reference_canonical_subset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storm_path = dir.path().join("stormlib_writer_reference.mpq");
    let rust_path = dir.path().join("rust_writer_reference.mpq");

    let storm_bytes = include_bytes!("../fixtures/parity/stormlib_writer_reference.mpq");
    std::fs::write(&storm_path, storm_bytes).expect("write storm fixture");

    let mut rust_archive =
        MpqArchive::create(&rust_path, CreateOptions::default()).expect("create rust archive");
    rust_archive
        .add_file_from_bytes(
            "alpha.txt",
            b"stormlib-writer-alpha",
            AddFileOptions {
                compression: Some(CompressionMethod::Zlib),
                single_unit: true,
                ..AddFileOptions::default()
            },
        )
        .expect("add alpha");
    rust_archive
        .add_file_from_bytes(
            "beta.bin",
            &fill_beta(9000),
            AddFileOptions {
                compression: Some(CompressionMethod::Zlib),
                single_unit: false,
                ..AddFileOptions::default()
            },
        )
        .expect("add beta");

    let storm = canonical_subset(&storm_path);
    let rust = canonical_subset(&rust_path);

    assert_eq!(rust["alpha.txt"].1, storm["alpha.txt"].1);
    assert_eq!(rust["beta.bin"].1, storm["beta.bin"].1);

    let beta_mask = MpqFileFlags::EXISTS | MpqFileFlags::COMPRESS | MpqFileFlags::SINGLE_UNIT;
    assert_eq!(
        rust["beta.bin"].0 & beta_mask,
        storm["beta.bin"].0 & beta_mask
    );
    assert!(rust["beta.bin"].0.contains(MpqFileFlags::COMPRESS));
    assert!(!rust["beta.bin"].0.contains(MpqFileFlags::SINGLE_UNIT));

    #[cfg(feature = "compression-zlib-native")]
    {
        // Stronger writer parity gate: archive bytes must match StormLib fixture exactly.
        let storm_raw = std::fs::read(&storm_path).expect("read storm bytes");
        let rust_raw = std::fs::read(&rust_path).expect("read rust bytes");
        if rust_raw != storm_raw {
            let diff = first_diff(&rust_raw, &storm_raw).expect("first diff index");
            let mut storm_archive = MpqArchive::open(&storm_path).expect("open storm for diag");
            let mut rust_archive = MpqArchive::open(&rust_path).expect("open rust for diag");
            let storm_items = storm_archive.list().expect("storm list");
            let rust_items = rust_archive.list().expect("rust list");
            let storm_attrs = storm_archive.read_attributes().ok().flatten().map(|a| {
                (
                    a.entry_count,
                    a.flags,
                    a.crc32.clone(),
                    a.file_time_low.clone(),
                    a.file_time_high.clone(),
                    a.md5.clone(),
                )
            });
            let rust_attrs = rust_archive.read_attributes().ok().flatten().map(|a| {
                (
                    a.entry_count,
                    a.flags,
                    a.crc32.clone(),
                    a.file_time_low.clone(),
                    a.file_time_high.clone(),
                    a.md5.clone(),
                )
            });
            let storm_named: Vec<(Option<String>, usize, u32)> = storm_items
                .iter()
                .map(|it| (it.name.clone(), it.block_index, it.flags.bits()))
                .collect();
            let rust_named: Vec<(Option<String>, usize, u32)> = rust_items
                .iter()
                .map(|it| (it.name.clone(), it.block_index, it.flags.bits()))
                .collect();
            let storm_blocks: Vec<(u32, u32, u32, u32)> = storm_archive
                .tables
                .block_table
                .iter()
                .take(4)
                .map(|b| (b.file_pos, b.compressed_size, b.file_size, b.flags.bits()))
                .collect();
            let hash_diff = rust_archive
                .tables
                .hash_table
                .iter()
                .zip(storm_archive.tables.hash_table.iter())
                .enumerate()
                .find(|(_, (r, s))| *r != *s)
                .map(|(i, (r, s))| (i, *r, *s));

            let storm_attr_block = storm_archive.tables.block_table[3];
            let rust_attr_block = rust_archive.tables.block_table[3];
            let mut storm_attr_raw = std::fs::read(&storm_path).expect("storm raw");
            let mut rust_attr_raw = std::fs::read(&rust_path).expect("rust raw");
            let storm_slice = &mut storm_attr_raw[storm_attr_block.file_pos as usize
                ..(storm_attr_block.file_pos + storm_attr_block.compressed_size) as usize];
            let rust_slice = &mut rust_attr_raw[rust_attr_block.file_pos as usize
                ..(rust_attr_block.file_pos + rust_attr_block.compressed_size) as usize];
            let storm_key = derive_file_key(
                "(attributes)",
                storm_attr_block.file_pos as u64,
                storm_attr_block.file_size,
                true,
            );
            let rust_key = derive_file_key(
                "(attributes)",
                rust_attr_block.file_pos as u64,
                rust_attr_block.file_size,
                true,
            );
            let mut storm_table = storm_slice[..8].to_vec();
            let mut rust_table = rust_slice[..8].to_vec();
            decrypt_mpq_block(&mut storm_table, storm_key.wrapping_sub(1));
            decrypt_mpq_block(&mut rust_table, rust_key.wrapping_sub(1));
            let mut storm_blob = storm_slice[8..].to_vec();
            let mut rust_blob = rust_slice[8..].to_vec();
            decrypt_mpq_block(&mut storm_blob, storm_key);
            decrypt_mpq_block(&mut rust_blob, rust_key);
            let attr_blob_diff = first_diff(&rust_blob, &storm_blob);
            let rust_blocks: Vec<(u32, u32, u32, u32)> = rust_archive
                .tables
                .block_table
                .iter()
                .take(4)
                .map(|b| (b.file_pos, b.compressed_size, b.file_size, b.flags.bits()))
                .collect();
            let storm_list = storm_archive.read_file("(listfile)").ok().map(|v| v.len());
            let rust_list = rust_archive.read_file("(listfile)").ok().map(|v| v.len());
            let storm_attr = storm_archive
                .read_file("(attributes)")
                .ok()
                .map(|v| v.len());
            let rust_attr = rust_archive.read_file("(attributes)").ok().map(|v| v.len());
            let storm_list_flags = storm_items
                .iter()
                .find(|it| it.name.as_deref() == Some("(listfile)"))
                .map(|it| it.flags.bits());
            let storm_attr_flags = storm_items
                .iter()
                .find(|it| it.name.as_deref() == Some("(attributes)"))
                .map(|it| it.flags.bits());
            let rust_list_flags = rust_items
                .iter()
                .find(|it| it.name.as_deref() == Some("(listfile)"))
                .map(|it| it.flags.bits());
            let rust_attr_flags = rust_items
                .iter()
                .find(|it| it.name.as_deref() == Some("(attributes)"))
                .map(|it| it.flags.bits());
            let rust_header = (
                le_u32(&rust_raw, 4),
                le_u16(&rust_raw, 12),
                le_u16(&rust_raw, 14),
                le_u32(&rust_raw, 24),
                le_u32(&rust_raw, 28),
            );
            let storm_header = (
                le_u32(&storm_raw, 4),
                le_u16(&storm_raw, 12),
                le_u16(&storm_raw, 14),
                le_u32(&storm_raw, 24),
                le_u32(&storm_raw, 28),
            );
            panic!(
                "archive bytes differ: first_diff={} rust_len={} storm_len={} rust_header={:?} storm_header={:?} rust_listfile={:?} storm_listfile={:?} rust_attributes={:?} storm_attributes={:?} rust_list_flags={:?} storm_list_flags={:?} rust_attr_flags={:?} storm_attr_flags={:?} rust_blocks={:?} storm_blocks={:?} rust_named={:?} storm_named={:?} rust_attrs={:?} storm_attrs={:?} hash_diff={:?} attr_table_rust={:?} attr_table_storm={:?} attr_blob_diff={:?} attr_blob_rust_prefix={:?} attr_blob_storm_prefix={:?}",
                diff,
                rust_raw.len(),
                storm_raw.len(),
                rust_header,
                storm_header,
                rust_list,
                storm_list,
                rust_attr,
                storm_attr,
                rust_list_flags,
                storm_list_flags,
                rust_attr_flags,
                storm_attr_flags,
                rust_blocks,
                storm_blocks,
                rust_named,
                storm_named,
                rust_attrs,
                storm_attrs,
                hash_diff,
                rust_table,
                storm_table,
                attr_blob_diff,
                &rust_blob[..rust_blob.len().min(24)],
                &storm_blob[..storm_blob.len().min(24)]
            );
        }
    }
}
