use criterion::{criterion_group, criterion_main, Criterion};

use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive};

/// Benchmarks are designed to be self-contained (no committed fixtures required).
///
/// They create a temporary MPQ, add a small in-memory file, then benchmark open/list/read.
///
/// Run locally:
/// ```
/// cargo bench --all-features
/// ```
fn bench_roundtrip(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mpq_path = dir.path().join("bench.mpq");

    // Setup archive
    {
        let mut a = MpqArchive::create(&mpq_path, CreateOptions::default()).expect("create");
        let data = vec![0xABu8; 128 * 1024];
        a.add_file_from_bytes("data.bin", &data, AddFileOptions::default())
            .expect("add");
        a.compact().expect("compact");
    }

    c.bench_function("open", |b| {
        b.iter(|| {
            let _ = MpqArchive::open(&mpq_path).expect("open");
        })
    });

    c.bench_function("list", |b| {
        b.iter(|| {
            let a = MpqArchive::open(&mpq_path).expect("open");
            let _ = a.list().expect("list");
        })
    });

    c.bench_function("read_file", |b| {
        b.iter(|| {
            let mut a = MpqArchive::open(&mpq_path).expect("open");
            let bytes = a.read_file("data.bin").expect("read");
            assert_eq!(bytes.len(), 128 * 1024);
        })
    });
}

criterion_group!(benches, bench_roundtrip);
criterion_main!(benches);
