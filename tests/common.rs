use std::path::PathBuf;

use tempfile::tempdir;

pub fn temp_archive_path(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join(name);
    (dir, path)
}
