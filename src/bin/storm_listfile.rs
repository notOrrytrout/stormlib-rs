use std::fs;

use stormlib_rs::MpqArchive;

fn usage() {
    eprintln!("Usage: storm_listfile <mpq> <out>");
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
        return Err("missing required arguments".into());
    }
    let mpq = &args[1];
    let out = &args[2];

    let mut archive = MpqArchive::open(mpq)?;
    let bytes = archive
        .read_file("(listfile)")
        .map_err(|_| "listfile not found")?;
    fs::write(out, bytes)?;
    println!("wrote listfile -> {out}");
    Ok(())
}
