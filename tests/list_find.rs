mod common;

use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive, SearchScope};

#[test]
fn list_and_find_merge_names_from_listfile() {
    let (_dir, path) = common::temp_archive_path("list.mpq");
    let mut a = MpqArchive::create(&path, CreateOptions::default()).unwrap();
    a.add_file_from_bytes("foo.txt", b"a", AddFileOptions::default())
        .unwrap();
    a.add_file_from_bytes("bar.bin", b"b", AddFileOptions::default())
        .unwrap();

    let reopened = MpqArchive::open(&path).unwrap();
    let list = reopened.list().unwrap();
    assert!(list.iter().any(|i| i.name.as_deref() == Some("foo.txt")));
    let find = reopened.find("*.txt").unwrap();
    assert_eq!(find.len(), 1);
}

#[test]
fn listfile_sources_and_scope_aware_find_work() {
    let (_dir, path) = common::temp_archive_path("list-scope.mpq");
    let mut a = MpqArchive::create(&path, CreateOptions::default()).unwrap();
    a.add_file_from_bytes("foo.txt", b"a", AddFileOptions::default())
        .unwrap();
    a.add_file_from_bytes("bar.bin", b"b", AddFileOptions::default())
        .unwrap();

    let mut reopened = MpqArchive::open(&path).unwrap();
    reopened.file_names.clear();

    assert!(reopened.find("*.txt").unwrap().is_empty());
    let all_before = reopened.list_with_scope(SearchScope::AllEntries).unwrap();
    let named_before = reopened.list_with_scope(SearchScope::NamedEntries).unwrap();
    assert!(!all_before.is_empty());
    assert!(named_before.is_empty());

    let added = reopened
        .add_listfile_source_bytes(b"foo.txt\r\nbar.bin\r\nmissing.dat\r\n")
        .unwrap();
    assert_eq!(added, 2);

    let named_after = reopened.list_with_scope(SearchScope::NamedEntries).unwrap();
    assert_eq!(named_after.len(), 2);
    let find_txt = reopened
        .find_with_scope("*.txt", SearchScope::NamedEntries)
        .unwrap();
    assert_eq!(find_txt.len(), 1);
}
