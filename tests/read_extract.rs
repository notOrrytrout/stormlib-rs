mod common;

use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive};

#[test]
fn read_and_extract_single_unit_file() {
    let (_dir, path) = common::temp_archive_path("read.mpq");
    let mut a = MpqArchive::create(&path, CreateOptions::default()).unwrap();
    a.add_file_from_bytes("docs/readme.txt", b"hello mpq", AddFileOptions::default())
        .unwrap();

    let data = a.read_file("docs/readme.txt").unwrap();
    assert_eq!(data, b"hello mpq");

    let out_dir = path.with_extension("out");
    a.extract_file("docs/readme.txt", out_dir.join("docs/readme.txt"))
        .unwrap();
    let on_disk = std::fs::read(out_dir.join("docs/readme.txt")).unwrap();
    assert_eq!(on_disk, b"hello mpq");
}

#[cfg(feature = "compression-zlib")]
#[test]
fn read_compressed_single_unit_file() {
    let (_dir, path) = common::temp_archive_path("readz.mpq");
    let mut a = MpqArchive::create(&path, CreateOptions::default()).unwrap();
    let opts = AddFileOptions {
        compression: Some(stormlib_rs::CompressionMethod::Zlib),
        ..Default::default()
    };
    let payload = b"repeated repeated repeated repeated repeated";
    a.add_file_from_bytes("payload.bin", payload, opts).unwrap();
    assert_eq!(a.read_file("payload.bin").unwrap(), payload);
}
