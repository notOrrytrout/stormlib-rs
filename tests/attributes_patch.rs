mod common;

use stormlib_rs::{AttributesFile, CreateOptions, MpqArchive};

#[test]
fn attributes_roundtrip_via_archive_stub_writer() {
    let (_dir, path) = common::temp_archive_path("attrs.mpq");
    let mut a = MpqArchive::create(&path, CreateOptions::default()).unwrap();
    let attrs = AttributesFile {
        version: 100,
        flags: 0x1,
        entry_count: a.tables.block_table.len(),
        crc32: vec![0xDEADBEEF],
        ..Default::default()
    };
    a.write_attributes_stub(&attrs).unwrap();
    let parsed = a.read_attributes().unwrap().unwrap();
    assert_eq!(parsed.entry_count, a.tables.block_table.len());
    assert_eq!(parsed.crc32.first().copied(), Some(0xDEADBEEF));
}

#[test]
fn patch_chain_api_reports_unimplemented_execution() {
    let (_dir, path) = common::temp_archive_path("patch.mpq");
    let mut a = MpqArchive::create(&path, CreateOptions::default()).unwrap();
    let chain = stormlib_rs::PatchChain::default();
    assert!(a.apply_patch_chain(&chain).is_ok());
}
