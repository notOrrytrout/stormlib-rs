mod common;

use stormlib_rs::{CreateOptions, MpqArchive};

#[test]
fn create_and_open_archive_parses_header_and_tables() {
    let (_dir, path) = common::temp_archive_path("open.mpq");
    let a = MpqArchive::create(&path, CreateOptions::default()).unwrap();
    assert!(a.header.hash_table_entries.is_power_of_two());
    let b = MpqArchive::open(&path).unwrap();
    assert_eq!(b.header.header_size, 32);
    assert!(b.has_file("(listfile)"));
}
