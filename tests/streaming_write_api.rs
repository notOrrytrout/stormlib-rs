mod common;

use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive, StormError};

#[test]
fn create_write_finish_streaming_file_roundtrip() {
    let (_dir, path) = common::temp_archive_path("streaming-write.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");

    let mut h = archive
        .create_file("streamed.bin", Some(6), AddFileOptions::default())
        .expect("create_file");
    archive.write_file(&mut h, b"abc").expect("write 1");
    archive.write_file(&mut h, b"def").expect("write 2");
    archive.finish_file(h).expect("finish");

    assert_eq!(archive.read_file("streamed.bin").expect("read"), b"abcdef");
}

#[test]
fn streaming_write_rejects_size_overflow() {
    let (_dir, path) = common::temp_archive_path("streaming-overflow.mpq");
    let archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");
    let mut h = archive
        .create_file("x.bin", Some(3), AddFileOptions::default())
        .expect("create_file");

    let err = archive
        .write_file(&mut h, b"abcd")
        .expect_err("overflow should fail");
    assert!(matches!(
        err,
        StormError::InvalidInput("streaming write exceeds expected file size")
    ));
}

#[test]
fn finish_file_rejects_size_mismatch() {
    let (_dir, path) = common::temp_archive_path("streaming-size-mismatch.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default()).expect("create");
    let mut h = archive
        .create_file("x.bin", Some(4), AddFileOptions::default())
        .expect("create_file");
    archive.write_file(&mut h, b"abc").expect("write");

    let err = archive
        .finish_file(h)
        .expect_err("size mismatch should fail");
    assert!(matches!(
        err,
        StormError::InvalidInput("streaming write final size does not match expected file size")
    ));
}
