use stormlib_rs::MpqArchive;

#[test]
fn reads_stormlib_fixture_attributes_exact_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("storm_writer.mpq");
    std::fs::write(
        &path,
        include_bytes!("../fixtures/parity/stormlib_writer_reference.mpq"),
    )
    .expect("write fixture");

    let mut archive = MpqArchive::open(&path).expect("open");
    let attrs = archive
        .read_attributes()
        .expect("read attributes result")
        .expect("attributes present");

    assert_eq!(attrs.version, 100);
    assert_eq!(attrs.flags, 0x07);
    assert_eq!(attrs.entry_count, 4);
    assert_eq!(attrs.crc32, vec![502_230_861, 898_569_122, 272_706_041, 0]);
    assert_eq!(
        attrs.md5[0],
        [234, 54, 202, 161, 110, 65, 134, 57, 96, 37, 209, 18, 153, 42, 97, 215]
    );
    assert_eq!(
        attrs.md5[1],
        [241, 20, 118, 220, 194, 224, 30, 9, 221, 144, 8, 64, 221, 79, 239, 150]
    );
}

#[test]
fn sync_attributes_is_stable_on_stormlib_fixture() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sync.mpq");

    let mut archive =
        MpqArchive::create(&path, stormlib_rs::CreateOptions::default()).expect("create");
    archive
        .add_file_from_bytes(
            "alpha.txt",
            b"alpha",
            stormlib_rs::AddFileOptions::default(),
        )
        .expect("add alpha");
    archive.sync_attributes(0x07).expect("sync");
    let before = archive
        .read_attributes()
        .expect("read before")
        .expect("before attrs");
    let alpha_idx = archive
        .list()
        .expect("list")
        .into_iter()
        .find(|it| it.name.as_deref() == Some("alpha.txt"))
        .expect("alpha item")
        .block_index;
    archive.sync_attributes(0x07).expect("sync second");
    let after = archive
        .read_attributes()
        .expect("read after")
        .expect("after attrs");

    assert_eq!(after.version, before.version);
    assert_eq!(after.flags, before.flags);
    assert_eq!(after.entry_count, before.entry_count);
    assert_eq!(after.crc32[alpha_idx], before.crc32[alpha_idx]);
    assert_eq!(after.md5[alpha_idx], before.md5[alpha_idx]);
}
