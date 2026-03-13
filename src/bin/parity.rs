use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stormlib_rs::MpqArchive;
use stormlib_rs::{compress, CompressionMethod};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }
    let cmd = args[1].as_str();
    let rest = &args[2..];
    match cmd {
        "checklist" => cmd_checklist(rest),
        "full-api" => cmd_full_api(rest),
        "patch-z" => cmd_patch_z(rest),
        "codec-vectors" => cmd_codec_vectors(rest),
        _ => {
            print_usage();
            Ok(())
        }
    }
}

fn print_usage() {
    eprintln!("Usage: parity <command> [args]");
    eprintln!("Commands:");
    eprintln!("  checklist --matrix <path>");
    eprintln!("  full-api <extract-stormlib|extract-rust|compare> ...");
    eprintln!("  patch-z <extract|manifest|compare|run> ...");
    eprintln!("  codec-vectors --input <path> --out-dir <dir>");
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|v| v == name)
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}

fn require_flag(args: &[String], name: &str) -> Result<String, Box<dyn Error>> {
    flag_value(args, name).ok_or_else(|| format!("missing required flag: {name}").into())
}

#[derive(Deserialize)]
struct FeatureMatrix {
    features: Vec<FeatureRow>,
}

#[derive(Deserialize)]
struct FeatureRow {
    id: String,
    description: String,
    status: String,
    evidence: String,
}

fn cmd_checklist(args: &[String]) -> Result<(), Box<dyn Error>> {
    let matrix_path = flag_value(args, "--matrix")
        .unwrap_or_else(|| "tools/parity/api_parity/feature_matrix.json".to_string());
    let raw = fs::read_to_string(&matrix_path)?;
    let matrix: FeatureMatrix = serde_json::from_str(&raw)?;

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in &matrix.features {
        *counts.entry(row.status.clone()).or_insert(0) += 1;
    }

    let valid = ["implemented", "partial", "missing", "out_of_scope"];
    let invalid: Vec<_> = counts
        .keys()
        .filter(|k| !valid.contains(&k.as_str()))
        .cloned()
        .collect();
    if !invalid.is_empty() {
        eprintln!("Invalid statuses: {invalid:?}");
        std::process::exit(1);
    }

    let total = matrix.features.len();
    let implemented = *counts.get("implemented").unwrap_or(&0);
    let partial = *counts.get("partial").unwrap_or(&0);
    let missing = *counts.get("missing").unwrap_or(&0);
    let out_of_scope = *counts.get("out_of_scope").unwrap_or(&0);

    println!("Parity Checklist Summary");
    println!(
        "total={total} implemented={implemented} partial={partial} missing={missing} out_of_scope={out_of_scope}"
    );

    for status in ["missing", "partial"] {
        let items: Vec<_> = matrix
            .features
            .iter()
            .filter(|row| row.status == status)
            .collect();
        if items.is_empty() {
            continue;
        }
        println!("\n{} ({})", status.to_uppercase(), items.len());
        for item in items {
            println!("- {}: {} [{}]", item.id, item.description, item.evidence);
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct StormlibApiList {
    count: usize,
    apis: Vec<StormlibApi>,
}

#[derive(Serialize, Deserialize)]
struct StormlibApi {
    name: String,
    #[serde(rename = "return")]
    return_type: String,
    args: String,
}

#[derive(Serialize, Deserialize)]
struct RustApiList {
    count: usize,
    apis: Vec<String>,
}

fn cmd_full_api(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.is_empty() {
        return Err("missing full-api subcommand".into());
    }
    match args[0].as_str() {
        "extract-stormlib" => full_api_extract_stormlib(&args[1..]),
        "extract-rust" => full_api_extract_rust(&args[1..]),
        "compare" => full_api_compare(&args[1..]),
        _ => Err("unknown full-api subcommand".into()),
    }
}

fn full_api_extract_stormlib(args: &[String]) -> Result<(), Box<dyn Error>> {
    let header = require_flag(args, "--header")?;
    let out = require_flag(args, "--out")?;
    let text = fs::read_to_string(&header)?;
    let re = Regex::new(
        r"^\s*(?P<ret>[A-Za-z_][\w\s\*]+?)\s+(?:WINAPI\s+)?(?P<name>S(?:File|Comp)[A-Za-z0-9_]+)\s*\((?P<args>[^)]*)\)\s*;",
    )?;

    let mut apis = Vec::new();
    for line in text.lines() {
        if let Some(caps) = re.captures(line) {
            let name = caps.name("name").unwrap().as_str().trim().to_string();
            let ret = caps
                .name("ret")
                .unwrap()
                .as_str()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let args = caps
                .name("args")
                .unwrap()
                .as_str()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            apis.push(StormlibApi {
                name,
                return_type: ret,
                args,
            });
        }
    }

    let payload = StormlibApiList {
        count: apis.len(),
        apis,
    };
    write_json(Path::new(&out), &payload)?;
    println!("wrote {} APIs -> {}", payload.count, out);
    Ok(())
}

fn full_api_extract_rust(args: &[String]) -> Result<(), Box<dyn Error>> {
    let src = require_flag(args, "--src")?;
    let out = require_flag(args, "--out")?;

    let pub_fn = Regex::new(r"^\s*pub\s+fn\s+([A-Za-z0-9_]+)\s*\(")?;
    let impl_mpq = Regex::new(r"^\s*impl\s+MpqArchive\s*\{")?;

    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![PathBuf::from(src)];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let text = fs::read_to_string(&p)?;
            let mut in_impl = false;
            for line in text.lines() {
                if impl_mpq.is_match(line) {
                    in_impl = true;
                    continue;
                }
                if in_impl && line.trim() == "}" {
                    in_impl = false;
                }
                if let Some(caps) = pub_fn.captures(line) {
                    let name = caps.get(1).unwrap().as_str();
                    if in_impl {
                        names.insert(format!("MpqArchive::{name}"));
                    } else {
                        names.insert(name.to_string());
                    }
                }
            }
        }
    }

    let apis: Vec<String> = names.into_iter().collect();
    let payload = RustApiList {
        count: apis.len(),
        apis,
    };
    write_json(Path::new(&out), &payload)?;
    println!("wrote {} APIs -> {}", payload.count, out);
    Ok(())
}

#[derive(Serialize)]
struct ApiCompareReport {
    stormlib_count: usize,
    rust_count: usize,
    abi_present: Vec<String>,
    abi_missing: Vec<String>,
}

fn full_api_compare(args: &[String]) -> Result<(), Box<dyn Error>> {
    let stormlib_path = require_flag(args, "--stormlib")?;
    let rust_path = require_flag(args, "--rust")?;
    let out_json = require_flag(args, "--out-json")?;
    let out_md = require_flag(args, "--out-md")?;

    let storm: StormlibApiList = read_json(Path::new(&stormlib_path))?;
    let rust: RustApiList = read_json(Path::new(&rust_path))?;

    let storm_names: BTreeSet<String> = storm.apis.iter().map(|a| a.name.clone()).collect();
    let rust_names: BTreeSet<String> = rust.apis.iter().cloned().collect();

    let abi_present: Vec<String> = storm_names.intersection(&rust_names).cloned().collect();
    let abi_missing: Vec<String> = storm_names.difference(&rust_names).cloned().collect();

    let report = ApiCompareReport {
        stormlib_count: storm_names.len(),
        rust_count: rust_names.len(),
        abi_present,
        abi_missing,
    };

    write_json(Path::new(&out_json), &report)?;

    let mut lines = Vec::new();
    lines.push("# Full API Parity Report".to_string());
    lines.push(String::new());
    lines.push(format!(
        "- StormLib exported APIs: {}",
        report.stormlib_count
    ));
    lines.push(format!(
        "- Rust detected public APIs: {}",
        report.rust_count
    ));
    lines.push(format!(
        "- C-ABI compatible names present: {}",
        report.abi_present.len()
    ));
    lines.push(format!(
        "- C-ABI compatible names missing: {}",
        report.abi_missing.len()
    ));
    lines.push(String::new());
    lines.push("## Missing C-ABI Surface".to_string());
    lines.push(String::new());
    for name in &report.abi_missing {
        lines.push(format!("- `{name}`"));
    }

    fs::write(&out_md, lines.join("\n") + "\n")?;
    println!("wrote report: {out_md}");
    Ok(())
}

fn cmd_patch_z(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.is_empty() {
        return Err("missing patch-z subcommand".into());
    }
    match args[0].as_str() {
        "extract" => patch_z_extract(&args[1..]),
        "manifest" => patch_z_manifest(&args[1..]),
        "compare" => patch_z_compare(&args[1..]),
        "run" => patch_z_run(&args[1..]),
        _ => Err("unknown patch-z subcommand".into()),
    }
}

fn patch_z_extract(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mpq = require_flag(args, "--mpq")?;
    let out = require_flag(args, "--out")?;
    fs::create_dir_all(&out)?;
    let mut archive = MpqArchive::open(mpq)?;
    let extracted = archive.extract_all(&out)?;
    println!("extracted {} files", extracted.len());
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
struct ManifestEntry {
    path: String,
    size: usize,
    sha256: String,
}

fn patch_z_manifest(args: &[String]) -> Result<(), Box<dyn Error>> {
    let root = require_flag(args, "--root")?;
    let out = require_flag(args, "--out")?;
    let manifest = build_manifest(Path::new(&root))?;
    write_json(Path::new(&out), &manifest)?;
    println!("wrote manifest: {out}");
    Ok(())
}

#[derive(Serialize)]
struct ManifestCompare {
    actual_missing_in_expected: Vec<String>,
    actual_hash_mismatch: Vec<String>,
    expected_only_unexpected: Vec<String>,
    expected_only_allowed: Vec<String>,
}

fn patch_z_compare(args: &[String]) -> Result<(), Box<dyn Error>> {
    let expected_path = require_flag(args, "--expected")?;
    let actual_path = require_flag(args, "--actual")?;
    let out = require_flag(args, "--out")?;

    let expected: Vec<ManifestEntry> = read_json(Path::new(&expected_path))?;
    let actual: Vec<ManifestEntry> = read_json(Path::new(&actual_path))?;

    let allow: BTreeSet<&str> = ["(listfile)", "(attributes)"].into_iter().collect();

    let expected_map: BTreeMap<&str, &ManifestEntry> =
        expected.iter().map(|e| (e.path.as_str(), e)).collect();
    let actual_map: BTreeMap<&str, &ManifestEntry> =
        actual.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut actual_missing_in_expected = Vec::new();
    let mut actual_hash_mismatch = Vec::new();
    for (path, actual_entry) in &actual_map {
        match expected_map.get(path) {
            None => actual_missing_in_expected.push((*path).to_string()),
            Some(expected_entry) => {
                if expected_entry.size != actual_entry.size
                    || expected_entry.sha256 != actual_entry.sha256
                {
                    actual_hash_mismatch.push((*path).to_string());
                }
            }
        }
    }

    let mut expected_only_unexpected = Vec::new();
    let mut expected_only_allowed = Vec::new();
    for path in expected_map.keys() {
        if actual_map.contains_key(path) {
            continue;
        }
        if allow.contains(path) {
            expected_only_allowed.push((*path).to_string());
        } else {
            expected_only_unexpected.push((*path).to_string());
        }
    }

    let compare = ManifestCompare {
        actual_missing_in_expected: sort_vec(actual_missing_in_expected),
        actual_hash_mismatch: sort_vec(actual_hash_mismatch),
        expected_only_unexpected: sort_vec(expected_only_unexpected),
        expected_only_allowed: sort_vec(expected_only_allowed),
    };

    write_json(Path::new(&out), &compare)?;
    println!("wrote compare: {out}");
    Ok(())
}

fn patch_z_run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mpq = require_flag(args, "--mpq")?;
    let golden = require_flag(args, "--golden")?;
    let out = require_flag(args, "--out")?;

    let rust_dir = Path::new(&out).join("rust");
    let rust_manifest = Path::new(&out).join("rust_manifest.json");
    let compare_out = Path::new(&out).join("compare.json");

    patch_z_extract(&[
        "--mpq".to_string(),
        mpq,
        "--out".to_string(),
        rust_dir.to_string_lossy().into_owned(),
    ])?;
    patch_z_manifest(&[
        "--root".to_string(),
        rust_dir.to_string_lossy().into_owned(),
        "--out".to_string(),
        rust_manifest.to_string_lossy().into_owned(),
    ])?;
    patch_z_compare(&[
        "--expected".to_string(),
        golden,
        "--actual".to_string(),
        rust_manifest.to_string_lossy().into_owned(),
        "--out".to_string(),
        compare_out.to_string_lossy().into_owned(),
    ])?;
    Ok(())
}

fn cmd_codec_vectors(args: &[String]) -> Result<(), Box<dyn Error>> {
    let input = require_flag(args, "--input")?;
    let out_dir = require_flag(args, "--out-dir")?;
    let input_bytes = fs::read(&input)?;
    let out = Path::new(&out_dir);
    fs::create_dir_all(out)?;

    let input_path = out.join("input.bin");
    fs::write(&input_path, &input_bytes)?;

    #[cfg(feature = "compression-pkware")]
    let mut outputs: Vec<(&str, CompressionMethod)> = vec![
        ("huffman", CompressionMethod::Huffman),
        ("adpcm_mono", CompressionMethod::AdpcmMono),
        ("adpcm_stereo", CompressionMethod::AdpcmStereo),
        ("sparse", CompressionMethod::Sparse),
    ];
    #[cfg(not(feature = "compression-pkware"))]
    let outputs: Vec<(&str, CompressionMethod)> = vec![
        ("huffman", CompressionMethod::Huffman),
        ("adpcm_mono", CompressionMethod::AdpcmMono),
        ("adpcm_stereo", CompressionMethod::AdpcmStereo),
        ("sparse", CompressionMethod::Sparse),
    ];

    #[cfg(feature = "compression-pkware")]
    {
        outputs.push(("pkware", CompressionMethod::PkwareImplode));
    }

    for (name, method) in outputs {
        let encoded = compress(method, &input_bytes)?;
        let path = out.join(format!("{name}.bin"));
        fs::write(&path, encoded)?;
    }

    println!("wrote codec vectors to {}", out.display());
    Ok(())
}

fn build_manifest(root: &Path) -> Result<Vec<ManifestEntry>, Box<dyn Error>> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let data = fs::read(&p)?;
            let rel = p.strip_prefix(root)?.to_string_lossy().replace('\\', "/");
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let sha256 = format!("{:x}", hasher.finalize());
            entries.push(ManifestEntry {
                path: rel,
                size: data.len(),
                sha256,
            });
        }
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

fn write_json<T: Serialize>(path: &Path, payload: &T) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(payload)?;
    fs::write(path, json + "\n")?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Box<dyn Error>> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn sort_vec(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}
