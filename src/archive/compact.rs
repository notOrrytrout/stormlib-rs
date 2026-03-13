use std::path::PathBuf;

use crate::error::Result;
use crate::file::callbacks::invoke_compact_callback;
use crate::stream::FileStream;
use crate::types::MpqArchive;

impl MpqArchive {
    pub fn compact(&mut self) -> Result<()> {
        invoke_compact_callback(0, 1);
        let manifest = self.capture_or_init_manifest()?;
        let tmp_path = compact_temp_path(&self.path);
        let rewrite = crate::file::add::rewrite_archive_from_manifest(
            &tmp_path,
            &manifest,
            Some(&self.header),
        )?;
        std::fs::rename(&tmp_path, &self.path)?;
        self.stream = FileStream::open(&self.path)?;
        self.header = rewrite.header;
        self.tables = rewrite.tables;
        self.file_names = rewrite.file_names;
        self.write_manifest = Some(manifest);
        invoke_compact_callback(1, 1);
        Ok(())
    }
}

fn compact_temp_path(path: &std::path::Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let file_name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive.mpq".to_string());
    p.set_file_name(format!("{}.compact.tmp", file_name));
    p
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::types::{AddFileOptions, CreateOptions, MpqArchive};

    use super::compact_temp_path;

    static COMPACT_HITS: AtomicUsize = AtomicUsize::new(0);

    fn bump_compact_callback(_: usize, _: usize) {
        COMPACT_HITS.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn compact_temp_path_is_adjacent() {
        let p = compact_temp_path(std::path::Path::new("test.mpq"));
        assert!(p.ends_with("test.mpq.compact.tmp"));
    }

    #[test]
    fn compact_invokes_callback() {
        COMPACT_HITS.store(0, Ordering::Relaxed);
        MpqArchive::set_compact_callback(Some(bump_compact_callback));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compact-callback.mpq");
        let mut archive = MpqArchive::create(&path, CreateOptions::default()).unwrap();
        archive
            .add_file_from_bytes("a.txt", b"abc", AddFileOptions::default())
            .unwrap();
        archive.compact().unwrap();

        assert!(COMPACT_HITS.load(Ordering::Relaxed) >= 2);
        MpqArchive::set_compact_callback(None);
    }
}
