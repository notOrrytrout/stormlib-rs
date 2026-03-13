use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive};

#[test]
fn checksums_and_attributes_and_locales_api_work() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("info.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");

    archive
        .add_file_from_bytes("alpha.txt", b"alpha", AddFileOptions::default())
        .expect("add");

    let (crc, md5) = archive.get_file_checksums("alpha.txt").expect("checksums");
    assert_ne!(crc, 0);
    assert_ne!(md5, [0u8; 16]);

    archive.sync_attributes(0x07).expect("sync attrs");
    let flags = archive
        .get_archive_attributes_flags()
        .expect("get attrs")
        .expect("has attrs");
    assert_eq!(flags, 0x07);

    let locales = archive.enum_locales("alpha.txt").expect("enum locales");
    assert!(locales.contains(&0));

    archive
        .update_file_attributes("alpha.txt")
        .expect("update attrs");
}
