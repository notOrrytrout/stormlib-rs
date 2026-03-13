mod common;

use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive, StormError};

#[test]
fn remove_rename_locale_and_max_count_roundtrip() {
    let (_dir, path) = common::temp_archive_path("mutation-api.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");
    archive
        .add_file_from_bytes("a.txt", b"aaa", AddFileOptions::default())
        .expect("add a");
    archive
        .add_file_from_bytes("b.txt", b"bbb", AddFileOptions::default())
        .expect("add b");

    archive.rename_file("a.txt", "renamed.txt").expect("rename");
    archive
        .set_file_locale("renamed.txt", 0x0409, 1)
        .expect("set locale");
    archive.set_locale(0x0409);
    archive.remove_file("b.txt").expect("remove");
    archive.set_max_file_count(64, 64).expect("set max count");

    assert!(archive.has_file("renamed.txt"));
    assert!(archive.has_file_with_locale("renamed.txt", 0x0409));
    assert_eq!(archive.locale(), 0x0409);
    assert!(!archive.has_file("a.txt"));
    assert!(!archive.has_file("b.txt"));
    assert_eq!(
        archive.read_file("renamed.txt").expect("read renamed"),
        b"aaa"
    );
    assert_eq!(
        archive
            .read_file_with_locale("renamed.txt", 0x0409)
            .expect("read renamed with locale"),
        b"aaa"
    );

    let listed = archive
        .list()
        .expect("list")
        .into_iter()
        .find(|i| i.name.as_deref() == Some("renamed.txt"))
        .expect("find renamed");
    assert_eq!(listed.locale, 0x0409);
    assert_eq!(listed.platform, 1);

    assert_eq!(archive.header.hash_table_entries, 64);
    assert_eq!(archive.header.block_table_entries, 64);
}

#[test]
fn remove_missing_file_returns_not_found() {
    let (_dir, path) = common::temp_archive_path("mutation-remove-missing.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");
    let err = archive
        .remove_file("missing.txt")
        .expect_err("missing remove should fail");
    assert!(matches!(err, StormError::NotFound(name) if name == "missing.txt"));
}
