use std::env;
use std::fs;
use std::path::PathBuf;

use stormlib_rs::MpqArchive;

const LISTFILE_NAME: &str = "(listfile)";

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mpq = flag_value(&args, "--mpq").ok_or("missing --mpq")?;
    let out = flag_value(&args, "--out").ok_or("missing --out")?;

    let mut archive = MpqArchive::open(&mpq)?;
    let bytes = archive.read_file(LISTFILE_NAME)?;

    let out_path = PathBuf::from(out);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&out_path, bytes)?;
    println!("wrote listfile -> {}", out_path.display());
    Ok(())
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|v| v == name)
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}
