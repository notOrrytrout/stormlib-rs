use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use stormlib_rs::CompressionMethod;
use stormlib_rs::{AddFileOptions, CreateOptions, MpqArchive, MpqFileFlags, VerifyRawDataTarget};

fn fill_beta(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x = 0x9E37_79B9u32;
    for b in &mut out {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    out
}

fn canonical_subset(path: &Path) -> Result<BTreeMap<String, (MpqFileFlags, Vec<u8>)>, String> {
    let mut archive = MpqArchive::open(path).map_err(|e| format!("open archive: {e}"))?;
    let items = archive.list().map_err(|e| format!("list archive: {e}"))?;
    let mut out = BTreeMap::new();
    let mask = MpqFileFlags::EXISTS
        | MpqFileFlags::COMPRESS
        | MpqFileFlags::SINGLE_UNIT
        | MpqFileFlags::ENCRYPTED
        | MpqFileFlags::FIX_KEY;

    for name in ["alpha.txt", "beta.bin"] {
        let item = items
            .iter()
            .find(|it| it.name.as_deref() == Some(name))
            .ok_or_else(|| format!("missing listed file {name}"))?;
        let data = archive
            .read_file(name)
            .map_err(|e| format!("read {name}: {e}"))?;
        out.insert(name.to_string(), (item.flags & mask, data));
    }
    Ok(out)
}

fn check_mixed_sector(root: &Path) -> Result<(), String> {
    let mpq_path = root.join("mixed.mpq");
    fs::write(
        &mpq_path,
        include_bytes!("../fixtures/parity/stormlib_mixed_sectors.mpq"),
    )
    .map_err(|e| format!("write mixed fixture: {e}"))?;
    let expected = include_bytes!("../fixtures/parity/stormlib_mixed_payload.bin");

    let mut archive =
        MpqArchive::open(&mpq_path).map_err(|e| format!("open mixed fixture: {e}"))?;
    let got = archive
        .read_file("mixed.bin")
        .map_err(|e| format!("read mixed.bin: {e}"))?;
    if got != expected {
        return Err("mixed-sector payload mismatch".to_string());
    }
    Ok(())
}

fn check_writer_equivalence(root: &Path) -> Result<(), String> {
    let storm_path = root.join("storm_writer.mpq");
    let rust_path = root.join("rust_writer.mpq");
    fs::write(
        &storm_path,
        include_bytes!("../fixtures/parity/stormlib_writer_reference.mpq"),
    )
    .map_err(|e| format!("write writer fixture: {e}"))?;

    let mut rust_archive = MpqArchive::create(&rust_path, CreateOptions::default())
        .map_err(|e| format!("create rust archive: {e}"))?;
    rust_archive
        .add_file_from_bytes(
            "alpha.txt",
            b"stormlib-writer-alpha",
            AddFileOptions {
                compression: Some(CompressionMethod::Zlib),
                single_unit: true,
                ..AddFileOptions::default()
            },
        )
        .map_err(|e| format!("add alpha.txt: {e}"))?;
    rust_archive
        .add_file_from_bytes(
            "beta.bin",
            &fill_beta(9000),
            AddFileOptions {
                compression: Some(CompressionMethod::Zlib),
                single_unit: false,
                ..AddFileOptions::default()
            },
        )
        .map_err(|e| format!("add beta.bin: {e}"))?;

    let storm = canonical_subset(&storm_path)?;
    let rust = canonical_subset(&rust_path)?;
    if rust["alpha.txt"].1 != storm["alpha.txt"].1 {
        return Err("writer equivalence mismatch for alpha.txt payload".to_string());
    }
    if rust["beta.bin"].1 != storm["beta.bin"].1 {
        return Err("writer equivalence mismatch for beta.bin payload".to_string());
    }
    let beta_mask = MpqFileFlags::EXISTS | MpqFileFlags::COMPRESS | MpqFileFlags::SINGLE_UNIT;
    if (rust["beta.bin"].0 & beta_mask) != (storm["beta.bin"].0 & beta_mask) {
        return Err("writer equivalence mismatch for beta.bin flags".to_string());
    }
    Ok(())
}

fn check_patch_chain(root: &Path) -> Result<(), String> {
    let base_path = root.join("patch_base.mpq");
    let patch_path = root.join("patch_overlay.mpq");
    fs::write(
        &base_path,
        include_bytes!("../fixtures/parity/stormlib_patch_base.mpq"),
    )
    .map_err(|e| format!("write patch base fixture: {e}"))?;
    fs::write(
        &patch_path,
        include_bytes!("../fixtures/parity/stormlib_patch_overlay.mpq"),
    )
    .map_err(|e| format!("write patch overlay fixture: {e}"))?;

    let expected_replace = include_bytes!("../fixtures/parity/stormlib_patch_expected_replace.bin");
    let expected_base_only =
        include_bytes!("../fixtures/parity/stormlib_patch_expected_base_only.bin");

    let mut archive =
        MpqArchive::open(&base_path).map_err(|e| format!("open base archive: {e}"))?;
    archive
        .open_patch_archive(&patch_path, None)
        .map_err(|e| format!("open patch archive: {e}"))?;

    let replace = archive
        .read_file("replace.txt")
        .map_err(|e| format!("read replace.txt: {e}"))?;
    if replace != expected_replace {
        return Err("patch-chain mismatch for replace.txt".to_string());
    }
    let base_only = archive
        .read_file("base_only.txt")
        .map_err(|e| format!("read base_only.txt: {e}"))?;
    if base_only != expected_base_only {
        return Err("patch-chain mismatch for base_only.txt".to_string());
    }
    Ok(())
}

fn check_implode_read(_root: &Path) -> Result<(), String> {
    let payload = fill_beta(4096);
    let compressed = pklib::implode_bytes(
        &payload,
        pklib::CompressionMode::Binary,
        pklib::DictionarySize::Size4K,
    )
    .map_err(|e| format!("implode payload: {e}"))?;
    let got = stormlib_rs::decompress(
        CompressionMethod::PkwareImplode,
        &compressed,
        Some(payload.len()),
    )
    .map_err(|e| format!("decompress implode payload: {e}"))?;
    if got != payload {
        return Err("implode read payload mismatch".to_string());
    }
    Ok(())
}

fn check_verify_raw_v4(root: &Path) -> Result<(), String> {
    let path = root.join("verify_raw_v4.mpq");
    let mut archive = MpqArchive::create(&path, CreateOptions::default())
        .map_err(|e| format!("create verify-raw-v4 fixture: {e}"))?;
    archive
        .add_file_from_bytes("a.txt", b"abc", AddFileOptions::default())
        .map_err(|e| format!("add a.txt: {e}"))?;
    archive.header.format_version = 3;
    archive.header.header_size = 0xD0;
    archive.header.raw_chunk_size = Some(4096);

    let hash_report = archive
        .verify_raw_data(VerifyRawDataTarget::HashTable, None)
        .map_err(|e| format!("verify raw hash table: {e}"))?;
    if !hash_report.is_ok() {
        return Err("verify-raw-v4 hash-table report was not ok".to_string());
    }
    let file_report = archive
        .verify_raw_data(VerifyRawDataTarget::File, Some("a.txt"))
        .map_err(|e| format!("verify raw file a.txt: {e}"))?;
    if !file_report.is_ok() {
        return Err("verify-raw-v4 file report was not ok".to_string());
    }
    Ok(())
}

fn run_harness(root: &Path) -> Vec<(&'static str, Result<(), String>)> {
    let mut results = vec![
        ("mixed-sector-001", check_mixed_sector(root)),
        ("writer-equiv-001", check_writer_equivalence(root)),
        ("patch-chain-001", check_patch_chain(root)),
        ("implode-read-001", check_implode_read(root)),
        ("verify-raw-v4-001", check_verify_raw_v4(root)),
    ];
    if std::env::var_os("PARITY_FORCE_FAIL").is_some() {
        results.push((
            "synthetic-fail-001",
            Err("forced parity mismatch".to_string()),
        ));
    }
    results
}

fn main() -> Result<(), String> {
    let mut out_dir = std::env::temp_dir();
    let stamp = format!(
        "stormlib-rs-parity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs()
    );
    out_dir.push(stamp);
    fs::create_dir_all(&out_dir).map_err(|e| format!("create temp dir: {e}"))?;

    let results = run_harness(&out_dir);
    let mut failed = false;
    let mut lines = Vec::new();
    lines.push("{".to_string());
    lines.push("  \"runner\": \"parity_harness\",".to_string());
    lines.push("  \"results\": [".to_string());
    for (idx, (id, result)) in results.iter().enumerate() {
        let (status, detail) = match result {
            Ok(()) => ("pass", "ok".to_string()),
            Err(msg) => {
                failed = true;
                ("fail", msg.clone())
            }
        };
        let comma = if idx + 1 == results.len() { "" } else { "," };
        lines.push(format!(
            "    {{\"id\":\"{id}\",\"status\":\"{status}\",\"detail\":\"{}\"}}{comma}",
            detail.replace('"', "'")
        ));
    }
    lines.push("  ]".to_string());
    lines.push("}".to_string());
    let report = lines.join("\n");

    if let Some(path) = std::env::args().nth(1) {
        let report_path = PathBuf::from(path);
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create report parent dir: {e}"))?;
        }
        fs::write(&report_path, report).map_err(|e| format!("write report: {e}"))?;
        println!("wrote parity report: {}", report_path.display());
    } else {
        println!("{report}");
    }

    if failed {
        return Err("parity harness detected mismatches".to_string());
    }
    Ok(())
}
