use stormlib_rs::MpqArchive;
use stormlib_rs::{AddFileOptions, CreateOptions};

#[test]
fn stormlib_generated_patch_chain_preserves_fallback_and_precedence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let base_path = dir.path().join("stormlib_patch_base.mpq");
    let patch_path = dir.path().join("stormlib_patch_overlay.mpq");

    std::fs::write(
        &base_path,
        include_bytes!("../fixtures/parity/stormlib_patch_base.mpq"),
    )
    .expect("write base fixture");
    std::fs::write(
        &patch_path,
        include_bytes!("../fixtures/parity/stormlib_patch_overlay.mpq"),
    )
    .expect("write patch fixture");

    let expected_replace = include_bytes!("../fixtures/parity/stormlib_patch_expected_replace.bin");
    let expected_base_only =
        include_bytes!("../fixtures/parity/stormlib_patch_expected_base_only.bin");

    let mut archive = MpqArchive::open(&base_path).expect("open base archive");
    archive
        .open_patch_archive(&patch_path, None)
        .expect("open patch archive");

    let replace = archive.read_file("replace.txt").expect("read replace.txt");
    assert_eq!(replace, expected_replace);

    let base_only = archive
        .read_file("base_only.txt")
        .expect("read base_only.txt");
    assert_eq!(base_only, expected_base_only);
}

#[test]
fn patch_chain_explicit_base_prefix_applies_overlay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let base_path = dir.path().join("base-auto.mpq");
    let patch_path = dir.path().join("patch-auto.mpq");

    {
        let mut base =
            MpqArchive::create(&base_path, CreateOptions::default()).expect("create base");
        base.add_file_from_bytes("foo.txt", b"base", AddFileOptions::default())
            .expect("add base file");
    }
    {
        let mut patch =
            MpqArchive::create(&patch_path, CreateOptions::default()).expect("create patch");
        patch
            .add_file_from_bytes("base\\(patch_metadata)", b"meta", AddFileOptions::default())
            .expect("add marker");
        patch
            .add_file_from_bytes("base\\foo.txt", b"patched", AddFileOptions::default())
            .expect("add overlay");
    }

    let mut archive = MpqArchive::open(&base_path).expect("open base");
    archive
        .open_patch_archive(&patch_path, Some("base"))
        .expect("open patch");
    assert_eq!(
        archive.read_file("foo.txt").expect("read patched"),
        b"patched"
    );
}

#[test]
fn patch_chain_uses_last_patch_precedence_for_same_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let base_path = dir.path().join("base-precedence.mpq");
    let p1_path = dir.path().join("p1.mpq");
    let p2_path = dir.path().join("p2.mpq");

    {
        let mut base =
            MpqArchive::create(&base_path, CreateOptions::default()).expect("create base");
        base.add_file_from_bytes("replace.txt", b"base", AddFileOptions::default())
            .expect("add base");
    }
    {
        let mut p1 = MpqArchive::create(&p1_path, CreateOptions::default()).expect("create p1");
        p1.add_file_from_bytes("replace.txt", b"patch1", AddFileOptions::default())
            .expect("add p1");
    }
    {
        let mut p2 = MpqArchive::create(&p2_path, CreateOptions::default()).expect("create p2");
        p2.add_file_from_bytes("replace.txt", b"patch2", AddFileOptions::default())
            .expect("add p2");
    }

    let mut archive = MpqArchive::open(&base_path).expect("open base");
    archive.open_patch_archive(&p1_path, None).expect("open p1");
    archive.open_patch_archive(&p2_path, None).expect("open p2");
    assert_eq!(
        archive.read_file("replace.txt").expect("read replace"),
        b"patch2"
    );
}
