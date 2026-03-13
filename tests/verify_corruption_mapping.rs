use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive};

#[test]
fn verify_archive_reports_invalid_hash_block_index_message() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("verify-corrupt-hash.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create archive");
    archive
        .add_file_from_bytes("a.txt", b"abc", AddFileOptions::default())
        .expect("add file");

    let hash_index = archive
        .tables
        .hash_table
        .iter()
        .position(|h| !(h.is_free() || h.is_deleted()))
        .expect("active hash");
    let invalid_block_index = archive.tables.block_table.len() as u32 + 1;
    archive.tables.hash_table[hash_index].block_index = invalid_block_index;
    let report = archive.verify_archive().expect("verify archive");

    let expected =
        format!("hash[{hash_index}] points to invalid block index {invalid_block_index}");
    assert!(
        report.table_errors.iter().any(|e| e == &expected),
        "{report:?}"
    );
}

#[test]
fn verify_archive_reports_block_range_exceeds_archive_length_message() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("verify-corrupt-range.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create archive");
    archive
        .add_file_from_bytes("a.txt", b"abc", AddFileOptions::default())
        .expect("add file");

    let hash_index = archive
        .tables
        .hash_table
        .iter()
        .position(|h| !(h.is_free() || h.is_deleted()))
        .expect("active hash");
    let block_index = archive.tables.hash_table[hash_index].block_index as usize;
    archive.tables.block_table[block_index].compressed_size = u32::MAX;
    let report = archive.verify_archive().expect("verify archive");

    let expected = format!("block[{block_index}] data range exceeds archive length");
    assert!(
        report.file_errors.iter().any(|e| e == &expected),
        "{report:?}"
    );
}

#[test]
fn verify_archive_reports_duplicate_hash_tuple_message() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("verify-corrupt-dup-hash.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create archive");
    archive
        .add_file_from_bytes("a.txt", b"abc", AddFileOptions::default())
        .expect("add first file");
    archive
        .add_file_from_bytes("b.txt", b"def", AddFileOptions::default())
        .expect("add second file");

    let active: Vec<usize> = archive
        .tables
        .hash_table
        .iter()
        .enumerate()
        .filter_map(|(i, h)| (!(h.is_free() || h.is_deleted())).then_some(i))
        .collect();
    assert!(active.len() >= 2, "need two active hashes: {active:?}");

    let first_idx = active[0];
    let dup_idx = active[1];
    let first = archive.tables.hash_table[first_idx];
    archive.tables.hash_table[dup_idx].hash_a = first.hash_a;
    archive.tables.hash_table[dup_idx].hash_b = first.hash_b;
    archive.tables.hash_table[dup_idx].locale = first.locale;

    let report = archive.verify_archive().expect("verify archive");
    let expected = format!("duplicate hash tuple at hash[{dup_idx}]");
    assert!(
        report.table_errors.iter().any(|e| e == &expected),
        "{report:?}"
    );
}
