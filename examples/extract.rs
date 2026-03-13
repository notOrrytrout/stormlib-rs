use std::env;
use std::path::PathBuf;

use stormlib_rs::MpqArchive;

fn main() {
    let mut args = env::args().skip(1);
    let mpq = args.next().expect("mpq path");
    let out = args.next().expect("output dir");

    let mpq_path = PathBuf::from(mpq);
    let out_dir = PathBuf::from(out);

    let mut a = MpqArchive::open(&mpq_path).expect("open mpq");
    a.extract_all(&out_dir).expect("extract all");
}
