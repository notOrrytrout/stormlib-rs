use stormlib_rs::lookup_file_name;
use stormlib_rs::{ErrorKind, MpqArchive, StormError};

fn write_fixture_mpq(path: &std::path::Path) {
    let mpq = include_bytes!("../fixtures/parity/stormlib_mixed_sectors.mpq");
    std::fs::write(path, mpq).expect("write fixture mpq");
}

#[test]
fn corrupted_sector_offsets_return_format_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mpq_path = dir.path().join("corrupt_offsets.mpq");
    write_fixture_mpq(&mpq_path);

    let archive = MpqArchive::open(&mpq_path).expect("open fixture");
    let m = lookup_file_name(
        &archive.tables.hash_table,
        archive.tables.block_table.len(),
        "mixed.bin",
    )
    .expect("mixed.bin lookup");
    let block = archive.tables.block_table[m.block_index];
    let base = archive.header.archive_offset + block.file_pos as u64;
    drop(archive);

    let mut bytes = std::fs::read(&mpq_path).expect("read fixture");
    bytes[(base as usize + 4)..(base as usize + 8)].copy_from_slice(&0u32.to_le_bytes());
    std::fs::write(&mpq_path, bytes).expect("rewrite corrupted fixture");

    let mut archive = MpqArchive::open(&mpq_path).expect("open corrupted fixture");
    let err = archive
        .read_file("mixed.bin")
        .expect_err("expected read failure");
    assert_eq!(err.kind(), ErrorKind::Format);
    assert!(matches!(
        err,
        StormError::Format("sector offsets not monotonic")
    ));
}

#[test]
fn truncated_block_range_returns_bounds_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mpq_path = dir.path().join("truncated.mpq");
    write_fixture_mpq(&mpq_path);

    let mut archive = MpqArchive::open(&mpq_path).expect("open fixture");
    let m = lookup_file_name(
        &archive.tables.hash_table,
        archive.tables.block_table.len(),
        "mixed.bin",
    )
    .expect("mixed.bin lookup");
    archive.tables.block_table[m.block_index].compressed_size = u32::MAX;
    let err = archive
        .read_file("mixed.bin")
        .expect_err("expected read failure");
    assert_eq!(err.kind(), ErrorKind::Bounds);
    assert!(matches!(err, StormError::Bounds(_)), "{err:?}");
}
