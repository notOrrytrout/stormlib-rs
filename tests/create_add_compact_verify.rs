mod common;

#[cfg(feature = "compression-zlib")]
use stormlib_rs::CompressionMethod;
use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive};

#[test]
fn create_add_verify_and_compact_work_logically() {
    let (_dir, path) = common::temp_archive_path("mutate.mpq");
    let mut a = MpqArchive::create(&path, CreateOptions::default()).unwrap();
    a.add_file_from_bytes("a.txt", b"aaa", AddFileOptions::default())
        .unwrap();
    a.add_file_from_bytes("b.txt", b"bbb", AddFileOptions::default())
        .unwrap();

    let before = std::fs::metadata(&path).unwrap().len();
    let report = a.verify().unwrap();
    assert!(report.is_ok(), "{report:?}");

    a.compact().unwrap();
    let after = std::fs::metadata(&path).unwrap().len();
    assert!(after <= before + 1024);

    let reopened = MpqArchive::open(&path).unwrap();
    assert_eq!(reopened.header.format_version, 0);
}

#[cfg(feature = "compression-zlib")]
#[test]
fn encrypted_sector_file_survives_rewrite_and_compact() {
    let (_dir, path) = common::temp_archive_path("mutate-encrypted.mpq");
    let mut a = MpqArchive::create(&path, CreateOptions::default()).unwrap();
    let payload = vec![0x5Au8; 12_000];

    let opts = AddFileOptions {
        compression: Some(CompressionMethod::Zlib),
        encrypted: true,
        fix_key: true,
        single_unit: false,
        sector_crc: true,
        ..AddFileOptions::default()
    };
    a.add_file_from_bytes("enc.bin", &payload, opts).unwrap();
    assert_eq!(a.read_file("enc.bin").unwrap(), payload);

    a.add_file_from_bytes("other.txt", b"ok", AddFileOptions::default())
        .unwrap();
    assert_eq!(a.read_file("enc.bin").unwrap(), payload);

    let listed = a
        .list()
        .unwrap()
        .into_iter()
        .find(|it| it.name.as_deref() == Some("enc.bin"))
        .unwrap();
    assert!(listed.flags.contains(stormlib_rs::MpqFileFlags::ENCRYPTED));
    assert!(listed.flags.contains(stormlib_rs::MpqFileFlags::FIX_KEY));
    assert!(listed.flags.contains(stormlib_rs::MpqFileFlags::SECTOR_CRC));
    assert!(!listed
        .flags
        .contains(stormlib_rs::MpqFileFlags::SINGLE_UNIT));

    a.compact().unwrap();
    assert_eq!(a.read_file("enc.bin").unwrap(), payload);
}
