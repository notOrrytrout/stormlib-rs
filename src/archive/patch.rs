use std::path::Path;

use crate::error::{Result, StormError};
use crate::types::MpqArchive;

fn detect_patch_prefix(patch: &MpqArchive) -> Option<String> {
    // StormLib performs WoW/SC2-specific prefix heuristics. Keep a bounded equivalent
    // for the common WoW prefix marker.
    if patch.has_file("base\\(patch_metadata)") {
        return Some("base\\".to_string());
    }
    if patch.has_file("(patch_metadata)") {
        return Some(String::new());
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct PatchChain {
    pub patches: Vec<std::path::PathBuf>,
}

impl PatchChain {
    pub fn push(&mut self, path: impl Into<std::path::PathBuf>) {
        self.patches.push(path.into());
    }

    pub fn push_with_prefix(&mut self, path: impl Into<std::path::PathBuf>, _prefix: &str) {
        // Prefix-aware chain specs are represented in MpqArchive::patch_chain entries.
        // This helper keeps API compatibility for callers that already track prefixes.
        self.patches.push(path.into());
    }
}

impl MpqArchive {
    pub fn open_patch_archive(
        &mut self,
        patch_path: impl AsRef<Path>,
        patch_prefix: Option<&str>,
    ) -> Result<()> {
        let patch_path = patch_path.as_ref();
        if patch_path.as_os_str().is_empty() {
            return Err(StormError::Format("patch archive path cannot be empty"));
        }
        if !patch_path.exists() {
            return Err(StormError::NotFound(
                patch_path.to_string_lossy().into_owned(),
            ));
        }

        let opened_patch = MpqArchive::open(patch_path)?;
        let patch_path_buf = patch_path.to_path_buf();
        if self.patch_chain.iter().any(|p| p.path == patch_path_buf) {
            return Ok(());
        }

        let normalized_prefix = patch_prefix
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                let mut v = s.replace('/', "\\");
                while v.ends_with('\\') {
                    v.pop();
                }
                if !v.is_empty() {
                    v.push('\\');
                }
                v
            })
            .filter(|s| !s.is_empty());
        let inferred_prefix = if normalized_prefix.is_none() {
            detect_patch_prefix(&opened_patch)
        } else {
            None
        };

        self.patch_chain.push(crate::types::PatchArchiveEntry {
            path: patch_path_buf,
            prefix: normalized_prefix.or(inferred_prefix),
        });
        Ok(())
    }

    pub fn is_patched_archive(&self) -> bool {
        !self.patch_chain.is_empty()
    }

    pub fn apply_patch_chain(&mut self, chain: &PatchChain) -> Result<()> {
        if chain.patches.is_empty() {
            return Ok(());
        }

        for p in &chain.patches {
            self.open_patch_archive(p, None)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::types::CreateOptions;

    use super::PatchChain;

    #[test]
    fn patch_chain_pushes_paths() {
        let mut c = PatchChain::default();
        c.push("a.mpq");
        assert_eq!(c.patches.len(), 1);
        c.push_with_prefix("b.mpq", "base");
        assert_eq!(c.patches.len(), 2);
    }

    #[test]
    fn open_patch_archive_appends_chain_for_read_only_base() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("base.mpq");
        let p1 = dir.path().join("p1.mpq");
        let p2 = dir.path().join("p2.mpq");

        let _ = crate::types::MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
        let _ = crate::types::MpqArchive::create(&p1, CreateOptions::default()).unwrap();
        let _ = crate::types::MpqArchive::create(&p2, CreateOptions::default()).unwrap();

        let mut base = crate::types::MpqArchive::open(&base_path).unwrap();
        base.open_patch_archive(&p1, Some("Base")).unwrap();
        base.open_patch_archive(&p2, None).unwrap();

        assert!(base.is_patched_archive());
        assert_eq!(base.patch_chain.len(), 2);
        assert_eq!(base.patch_chain[0].prefix.as_deref(), Some("Base\\"));
    }

    #[test]
    fn open_patch_archive_allows_write_mode_base() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("base.mpq");
        let p1 = dir.path().join("p1.mpq");
        let mut base =
            crate::types::MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
        let _ = crate::types::MpqArchive::create(&p1, CreateOptions::default()).unwrap();

        base.open_patch_archive(&p1, None).unwrap();
        assert!(base.is_patched_archive());
    }

    #[test]
    fn open_patch_archive_normalizes_empty_prefix_to_none() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("base.mpq");
        let p1 = dir.path().join("p1.mpq");

        let _ = crate::types::MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
        let _ = crate::types::MpqArchive::create(&p1, CreateOptions::default()).unwrap();

        let mut base = crate::types::MpqArchive::open(&base_path).unwrap();
        base.open_patch_archive(&p1, Some(" /// ")).unwrap();
        assert_eq!(base.patch_chain[0].prefix, None);
    }

    #[test]
    fn open_patch_archive_detects_base_prefix_from_patch_metadata() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("base.mpq");
        let p1 = dir.path().join("p1.mpq");

        let _ = crate::types::MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
        let mut patch = crate::types::MpqArchive::create(&p1, CreateOptions::default()).unwrap();
        patch
            .add_file_from_bytes(
                "base\\(patch_metadata)",
                b"x",
                crate::types::AddFileOptions::default(),
            )
            .unwrap();

        let mut base = crate::types::MpqArchive::open(&base_path).unwrap();
        base.open_patch_archive(&p1, None).unwrap();
        assert_eq!(base.patch_chain[0].prefix.as_deref(), Some("base\\"));
    }
}
