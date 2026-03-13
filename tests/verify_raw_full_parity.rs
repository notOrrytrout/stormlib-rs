use stormlib_rs::{AddFileOptions, CreateOptions, ErrorKind, MpqArchive, VerifyRawDataTarget};

#[test]
fn raw_file_verify_zero_sized_block_is_success() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raw-zero-size.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");
    archive
        .add_file_from_bytes("empty.bin", b"", AddFileOptions::default())
        .expect("add empty");

    archive.header.format_version = 3;
    archive.header.header_size = 0xD0;
    archive.header.raw_chunk_size = Some(4096);

    let report = archive
        .verify_raw_data(VerifyRawDataTarget::File, Some("empty.bin"))
        .expect("verify raw zero-sized file");
    assert!(report.is_ok());
}

#[test]
fn raw_file_verify_missing_name_returns_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("raw-missing.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");

    archive.header.format_version = 3;
    archive.header.header_size = 0xD0;
    archive.header.raw_chunk_size = Some(4096);

    let err = archive
        .verify_raw_data(VerifyRawDataTarget::File, Some("missing.bin"))
        .expect_err("missing file should fail");
    assert_eq!(err.kind(), ErrorKind::NotFound);
}
