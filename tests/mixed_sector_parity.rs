use stormlib_rs::lookup_file_name;
use stormlib_rs::MpqArchive;
use stormlib_rs::MpqFileFlags;

#[cfg(feature = "compression-zlib")]
#[test]
fn stormlib_generated_mixed_sector_archive_reads_with_mixed_raw_sector_sizes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mpq_path = dir.path().join("stormlib_mixed_sectors.mpq");
    let payload = include_bytes!("../fixtures/parity/stormlib_mixed_payload.bin");
    let mpq = include_bytes!("../fixtures/parity/stormlib_mixed_sectors.mpq");
    std::fs::write(&mpq_path, mpq).expect("write fixture mpq");

    let mut archive = MpqArchive::open(&mpq_path).expect("open fixture");
    let data = archive.read_file("mixed.bin").expect("read mixed.bin");
    assert_eq!(data, payload);

    let m = lookup_file_name(
        &archive.tables.hash_table,
        archive.tables.block_table.len(),
        "mixed.bin",
    )
    .expect("mixed.bin lookup");
    let block = archive.tables.block_table[m.block_index];
    assert!(block.flags.contains(MpqFileFlags::COMPRESS));
    assert!(!block.flags.contains(MpqFileFlags::SINGLE_UNIT));

    let sector_size = archive.header.sector_size() as usize;
    let sector_count = (block.file_size as usize).div_ceil(sector_size);
    let base = archive.header.archive_offset + block.file_pos as u64;
    let offset_words =
        sector_count + 1 + usize::from(block.flags.contains(MpqFileFlags::SECTOR_CRC));
    let offset_raw = archive
        .stream
        .read_at(base, offset_words * 4)
        .expect("read sector offset table");

    let mut offsets = Vec::with_capacity(sector_count + 1);
    for chunk in offset_raw.chunks_exact(4).take(sector_count + 1) {
        offsets.push(u32::from_le_bytes(chunk.try_into().expect("dword")) as usize);
    }

    let mut raw_lens = Vec::new();
    for w in offsets.windows(2) {
        raw_lens.push(w[1] - w[0]);
    }

    assert!(
        raw_lens.iter().any(|&n| n < sector_size),
        "expected at least one compressed sector, got {raw_lens:?}"
    );
    assert!(
        raw_lens.contains(&sector_size),
        "expected at least one uncompressed sector, got {raw_lens:?}"
    );
}
