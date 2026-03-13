use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use stormlib_rs::MpqArchive;

fn usage() {
    eprintln!("Usage: storm_extract <mpq> <listfile> <out_dir>");
}

fn sanitize_extract_name(name: &str) -> PathBuf {
    let normalized = name.replace('\\', "/");
    let mut out = PathBuf::new();
    for part in normalized.split('/') {
        let part = part.trim();
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        out.push(part);
    }
    out
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        usage();
        return Err("missing required arguments".into());
    }

    let mpq = &args[1];
    let listfile = &args[2];
    let out_dir = Path::new(&args[3]);

    fs::create_dir_all(out_dir)?;
    let file = fs::File::open(listfile)?;
    let reader = BufReader::new(file);
    let mut archive = MpqArchive::open(mpq)?;
    let mut extracted: usize = 0;

    for line in reader.lines() {
        let line = line?;
        let entry = line.trim();
        if entry.is_empty() {
            continue;
        }
        let rel = sanitize_extract_name(entry);
        if rel.as_os_str().is_empty() {
            continue;
        }
        let target = out_dir.join(rel);
        if archive.extract_file(entry, &target).is_ok() {
            extracted += 1;
        }
    }

    println!("extracted {extracted} files");
    Ok(())
}
