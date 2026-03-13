use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use stormlib_rs::{AddFileOptions, CompressionMethod, MpqArchive, MpqFileFlags, WriteManifest};

const LISTFILE_NAME: &str = "(listfile)";

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let mpq = flag_value(&args, "--mpq");
    let out = flag_value(&args, "--out").ok_or("missing --out")?;
    let from_dir = flag_value(&args, "--from-dir").map(PathBuf::from);
    let work_dir = flag_value(&args, "--work-dir")
        .map(PathBuf::from)
        .or_else(|| from_dir.clone())
        .unwrap_or_else(|| default_work_dir(mpq.as_deref().map(Path::new), Path::new(&out)));

    fs::create_dir_all(&work_dir)?;

    let mut flags = HashMap::new();
    if let Some(mpq_path) = mpq.as_deref() {
        let archive = MpqArchive::open(mpq_path)?;
        flags = build_flag_map(&archive)?;
    }

    if let Some(source_dir) = from_dir.as_ref() {
        if source_dir != &work_dir {
            return Err("--from-dir and --work-dir must match when both are provided".into());
        }
    } else if let Some(mpq_path) = mpq.as_deref() {
        let mut archive = MpqArchive::open(mpq_path)?;
        let extracted = archive.extract_all(&work_dir)?;
        println!(
            "extracted {} files into {}",
            extracted.len(),
            work_dir.display()
        );
    } else {
        return Err("missing --mpq or --from-dir".into());
    }

    let entries = build_manifest_from_dir(&work_dir, &flags)?;
    let listfile_path = work_dir.join(LISTFILE_NAME);
    write_listfile(&listfile_path, &entries)?;

    let mut out_archive = MpqArchive::create(
        &out,
        stormlib_rs::CreateOptions {
            sector_size_shift: 3,
            hash_table_entries: 1024,
            block_table_entries: 1024,
            create_listfile: true,
            create_attributes: false,
        },
    )?;
    out_archive.rewrite_from_manifest(WriteManifest { entries })?;

    println!("wrote repacked mpq -> {}", out);
    Ok(())
}

fn print_usage() {
    eprintln!(
        "Usage: repack --out <output.mpq> [--mpq <input.mpq>] [--from-dir <dir>] [--work-dir <dir>]"
    );
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|v| v == name)
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}

fn default_work_dir(input: Option<&Path>, output: &Path) -> PathBuf {
    let base = output
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("repacked");
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    if let Some(input) = input {
        let in_base = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("input");
        return parent.join(format!("{in_base}_extract"));
    }
    parent.join(format!("{base}_extract"))
}

fn build_flag_map(
    archive: &MpqArchive,
) -> Result<HashMap<String, MpqFileFlags>, Box<dyn std::error::Error>> {
    let mut out = HashMap::new();
    for item in archive.list()? {
        let Some(name) = item.name else { continue };
        if name.eq_ignore_ascii_case(LISTFILE_NAME) {
            continue;
        }
        out.insert(name, item.flags);
    }
    Ok(out)
}

fn build_manifest_from_dir(
    root: &Path,
    flags: &HashMap<String, MpqFileFlags>,
) -> Result<Vec<stormlib_rs::ManifestEntry>, Box<dyn std::error::Error>> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path.strip_prefix(root)?;
            let name = rel.to_string_lossy().replace('/', "\\");
            if name.eq_ignore_ascii_case(LISTFILE_NAME) {
                continue;
            }
            let data = fs::read(&path)?;
            let flags = flags.get(&name).copied().unwrap_or(MpqFileFlags::empty());
            let compression = if flags.contains(MpqFileFlags::COMPRESS) {
                Some(CompressionMethod::Zlib)
            } else {
                None
            };
            entries.push(stormlib_rs::ManifestEntry {
                name,
                data,
                options: AddFileOptions {
                    compression,
                    encrypted: flags.contains(MpqFileFlags::ENCRYPTED),
                    fix_key: flags.contains(MpqFileFlags::FIX_KEY),
                    locale: 0,
                    platform: 0,
                    single_unit: flags.contains(MpqFileFlags::SINGLE_UNIT),
                    sector_crc: flags.contains(MpqFileFlags::SECTOR_CRC),
                },
            });
        }
    }
    Ok(entries)
}

fn write_listfile(
    path: &Path,
    entries: &[stormlib_rs::ManifestEntry],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable_by_key(|s| s.to_ascii_lowercase());
    let mut content = names.join("\r\n");
    if !content.is_empty() {
        content.push_str("\r\n");
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}
