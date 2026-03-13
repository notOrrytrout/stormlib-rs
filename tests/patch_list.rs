mod common;

use std::collections::BTreeSet;

use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive};

fn names_from_list(items: &[stormlib_rs::ArchiveListItem]) -> BTreeSet<String> {
    items.iter().filter_map(|i| i.name.clone()).collect()
}

#[test]
fn patch_only_name_discovered() {
    let (_dir, base_path) = common::temp_archive_path("base.mpq");
    let (_dir2, patch_path) = common::temp_archive_path("patch.mpq");

    let mut base = MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
    base.add_file_from_bytes("base.txt", b"a", AddFileOptions::default())
        .unwrap();

    let mut patch = MpqArchive::create(&patch_path, CreateOptions::default()).unwrap();
    patch
        .add_file_from_bytes("patch.txt", b"b", AddFileOptions::default())
        .unwrap();

    let mut reopened = MpqArchive::open(&base_path).unwrap();
    reopened.open_patch_archive(&patch_path, None).unwrap();

    let all = reopened.list_all().unwrap();
    let names = names_from_list(&all);
    assert!(names.contains("base.txt"));
    assert!(names.contains("patch.txt"));
    assert!(reopened.has_file_any("patch.txt"));
}

#[test]
fn patch_wins_merge_by_locale() {
    let (_dir, base_path) = common::temp_archive_path("base-merge.mpq");
    let (_dir2, patch_path) = common::temp_archive_path("patch-merge.mpq");

    let mut base = MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
    base.add_file_from_bytes("shared.txt", b"a", AddFileOptions::default())
        .unwrap();

    let mut patch = MpqArchive::create(&patch_path, CreateOptions::default()).unwrap();
    let opts = AddFileOptions {
        locale: 0x0409,
        ..AddFileOptions::default()
    };
    patch.add_file_from_bytes("shared.txt", b"b", opts).unwrap();

    let mut reopened = MpqArchive::open(&base_path).unwrap();
    reopened.open_patch_archive(&patch_path, None).unwrap();

    let all = reopened.list_all().unwrap();
    let shared = all
        .iter()
        .find(|i| i.name.as_deref() == Some("shared.txt"))
        .unwrap();
    assert_eq!(shared.locale, 0x0409);
}

#[test]
fn prefix_handling_strips_base_prefix() {
    let (_dir, base_path) = common::temp_archive_path("base-prefix.mpq");
    let (_dir2, patch_path) = common::temp_archive_path("patch-prefix.mpq");

    let mut base = MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
    base.add_file_from_bytes("base.txt", b"a", AddFileOptions::default())
        .unwrap();

    let mut patch = MpqArchive::create(&patch_path, CreateOptions::default()).unwrap();
    patch
        .add_file_from_bytes("base\\(patch_metadata)", b"x", AddFileOptions::default())
        .unwrap();
    patch
        .add_file_from_bytes("base\\foo.txt", b"b", AddFileOptions::default())
        .unwrap();

    let mut reopened = MpqArchive::open(&base_path).unwrap();
    reopened.open_patch_archive(&patch_path, None).unwrap();

    let all = reopened.list_all().unwrap();
    let names = names_from_list(&all);
    assert!(names.contains("foo.txt"));
    assert!(reopened.has_file_any("foo.txt"));
}

#[test]
fn list_all_ignores_patch_without_listfile() {
    let (_dir, base_path) = common::temp_archive_path("base-nolist.mpq");
    let (_dir2, patch_path) = common::temp_archive_path("patch-nolist.mpq");

    let mut base = MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
    base.add_file_from_bytes("base.txt", b"a", AddFileOptions::default())
        .unwrap();

    let opts = CreateOptions {
        create_listfile: false,
        ..CreateOptions::default()
    };
    let mut patch = MpqArchive::create(&patch_path, opts).unwrap();
    patch
        .add_file_from_bytes("patch.txt", b"b", AddFileOptions::default())
        .unwrap();

    let mut reopened = MpqArchive::open(&base_path).unwrap();
    reopened.open_patch_archive(&patch_path, None).unwrap();

    let base_list = reopened
        .list_with_scope(stormlib_rs::SearchScope::NamedEntries)
        .unwrap();
    let base_names = names_from_list(&base_list);

    let all = reopened.list_all().unwrap();
    let all_names = names_from_list(&all);

    assert_eq!(base_names, all_names);
    assert!(reopened.has_file_any("patch.txt"));
}
