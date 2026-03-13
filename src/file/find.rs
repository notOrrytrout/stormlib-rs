use crate::error::Result;
use crate::types::{ArchiveListItem, MpqArchive, SearchScope};

impl MpqArchive {
    pub fn find(&self, pattern: &str) -> Result<Vec<ArchiveListItem>> {
        self.find_with_scope(pattern, SearchScope::NamedEntries)
    }

    pub fn find_with_scope(
        &self,
        pattern: &str,
        scope: SearchScope,
    ) -> Result<Vec<ArchiveListItem>> {
        let items = self.list_with_scope(scope)?;
        Ok(items
            .into_iter()
            .filter(|i| match &i.name {
                Some(name) => wildcard_match(pattern, name),
                None => matches!(scope, SearchScope::AllEntries) && pattern == "*",
            })
            .collect())
    }
}

pub(crate) fn wildcard_match(pattern: &str, text: &str) -> bool {
    wildcard_match_bytes(pattern.as_bytes(), text.as_bytes())
}

fn wildcard_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut star_match) = (None::<usize>, 0usize);

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || eq_fold_ascii(pattern[p], text[t])) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_match = t;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            star_match += 1;
            t = star_match;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

fn eq_fold_ascii(a: u8, b: u8) -> bool {
    a.eq_ignore_ascii_case(&b)
}

#[cfg(test)]
mod tests {
    use super::wildcard_match;

    #[test]
    fn wildcard_matching_handles_star_and_question() {
        assert!(wildcard_match("*.txt", "Readme.TXT"));
        assert!(wildcard_match("foo?.bin", "foo1.bin"));
        assert!(!wildcard_match("foo?.bin", "foo12.bin"));
    }
}
