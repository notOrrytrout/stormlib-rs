use std::fs;
use std::path::Path;

use crate::error::Result;
use crate::types::MpqArchive;

impl MpqArchive {
    pub fn extract_file(&mut self, name: &str, dest: impl AsRef<Path>) -> Result<()> {
        let bytes = self.read_file(name)?;
        let dest = dest.as_ref();
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(dest, bytes)?;
        Ok(())
    }

    pub fn extract_all(&mut self, root: impl AsRef<Path>) -> Result<Vec<String>> {
        let root = root.as_ref();
        fs::create_dir_all(root)?;
        let items = self.list()?;
        let mut extracted = Vec::new();
        let mut push_once = |rel: &std::path::Path| {
            let rel_s = rel.to_string_lossy().into_owned();
            if !extracted.iter().any(|v| v == &rel_s) {
                extracted.push(rel_s);
            }
        };
        for item in items {
            let Some(name) = item.name else { continue };
            let rel = sanitize_extract_name(&name);
            let target = root.join(&rel);
            if self.extract_file(&name, &target).is_ok() {
                push_once(&rel);
            }
        }

        // StormLib extraction workflows commonly include these internal files.
        for special in ["(listfile)", "(attributes)"] {
            let rel = sanitize_extract_name(special);
            let target = root.join(&rel);
            if self.extract_file(special, &target).is_ok() {
                push_once(&rel);
            }
        }
        Ok(extracted)
    }
}

pub(crate) fn sanitize_extract_name(name: &str) -> std::path::PathBuf {
    let normalized = name.replace('\\', "/");
    let mut out = std::path::PathBuf::new();
    for part in normalized.split('/') {
        let part = part.trim();
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        out.push(part);
    }
    if out.as_os_str().is_empty() {
        out.push("unnamed.bin");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sanitize_extract_name;

    #[test]
    fn sanitize_extract_name_removes_parent_segments() {
        let p = sanitize_extract_name("../foo\\bar//baz.txt");
        assert_eq!(p.to_string_lossy(), "foo/bar/baz.txt");
    }

    #[test]
    fn sanitize_extract_name_keeps_special_file_tokens() {
        let p = sanitize_extract_name("(listfile)");
        assert_eq!(p.to_string_lossy(), "(listfile)");
    }
}
