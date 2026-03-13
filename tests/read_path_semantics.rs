use stormlib_rs::{AddFileOptions, CreateOptions, ErrorKind, MpqArchive};

#[test]
fn reading_missing_file_returns_not_found_kind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("read-missing.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");

    let err = archive
        .read_file("missing.bin")
        .expect_err("missing should error");
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

#[test]
fn encrypted_named_file_reads_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("enc-roundtrip.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");

    archive
        .add_file_from_bytes(
            "enc.bin",
            b"secret payload",
            AddFileOptions {
                encrypted: true,
                fix_key: true,
                single_unit: true,
                ..AddFileOptions::default()
            },
        )
        .expect("add enc");

    let out = archive.read_file("enc.bin").expect("read enc");
    assert_eq!(out, b"secret payload");
}
