use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::{OnceLock, RwLock};

use crate::error::{Result, StormError};
use crate::internal::file_table::lookup_file_name;
use crate::types::{
    ArchiveListItem, HashTableEntry, ListCallback, MpqArchive, MpqFileFlags, SearchScope,
};

static LIST_CALLBACK: OnceLock<RwLock<Option<ListCallback>>> = OnceLock::new();
static PATCH_NAME_CACHE: OnceLock<RwLock<HashMap<PatchCacheKey, PatchNameIndex>>> = OnceLock::new();

fn list_callback_cell() -> &'static RwLock<Option<ListCallback>> {
    LIST_CALLBACK.get_or_init(|| RwLock::new(None))
}

fn patch_cache_cell() -> &'static RwLock<HashMap<PatchCacheKey, PatchNameIndex>> {
    PATCH_NAME_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn invoke_list_callback(item: &ArchiveListItem) {
    if let Ok(guard) = list_callback_cell().read() {
        if let Some(cb) = *guard {
            cb(item);
        }
    }
}

impl MpqArchive {
    pub fn list(&self) -> Result<Vec<ArchiveListItem>> {
        self.list_with_scope(SearchScope::AllEntries)
    }

    pub fn list_with_scope(&self, scope: SearchScope) -> Result<Vec<ArchiveListItem>> {
        let mut out = Vec::new();
        for (hash_index, h) in self.tables.hash_table.iter().copied().enumerate() {
            if h.is_free() || h.is_deleted() {
                continue;
            }
            let block_index = h.block_index as usize;
            let name = self.file_names.get(&block_index).cloned();
            if matches!(scope, SearchScope::NamedEntries) && name.is_none() {
                continue;
            }
            let flags = block_flags_for_hash(self, h)?;
            out.push(ArchiveListItem {
                hash_index,
                block_index,
                name,
                locale: h.locale,
                platform: h.platform,
                flags,
            });
            if let Some(item) = out.last() {
                invoke_list_callback(item);
            }
        }
        Ok(out)
    }

    pub fn set_list_callback(callback: Option<ListCallback>) {
        if let Ok(mut guard) = list_callback_cell().write() {
            *guard = callback;
        }
    }

    pub fn add_listfile_source_bytes(&mut self, bytes: &[u8]) -> Result<usize> {
        merge_listfile_names(self, bytes)
    }

    pub fn add_listfile_source_path(&mut self, path: impl AsRef<Path>) -> Result<usize> {
        let bytes = std::fs::read(path)?;
        merge_listfile_names(self, &bytes)
    }

    pub fn has_file(&self, name: &str) -> bool {
        lookup_file_name(&self.tables.hash_table, self.tables.block_table.len(), name).is_some()
    }

    pub fn has_file_any(&self, name: &str) -> bool {
        if self.has_file(name) {
            return true;
        }
        if self.patch_chain.is_empty() {
            return false;
        }

        let normalized = normalize_name_slash(name);
        for patch_entry in &self.patch_chain {
            let Ok(patch) = MpqArchive::open(&patch_entry.path) else {
                continue;
            };
            let mut candidates = Vec::with_capacity(4);
            if let Some(prefix) = patch_entry.prefix.as_deref().filter(|s| !s.is_empty()) {
                candidates.push(format!("{prefix}{normalized}"));
                candidates.push(format!("{prefix}{name}"));
            }
            candidates.push(name.to_string());
            if normalized != name {
                candidates.push(normalized.clone());
            }

            for candidate in candidates {
                if patch.has_file(&candidate) {
                    return true;
                }
            }
        }

        false
    }

    pub fn list_all(&self) -> Result<Vec<ArchiveListItem>> {
        let base = self.list_with_scope(SearchScope::NamedEntries)?;
        let mut merged: BTreeMap<String, ArchiveListItem> = BTreeMap::new();
        for item in base {
            if let Some(name) = item.name.clone() {
                merged.insert(name, item);
            }
        }

        let patch_names = patch_name_index(self);
        for (name, item) in patch_names {
            merged.insert(name, item);
        }

        Ok(merged.into_values().collect())
    }
}

pub(crate) fn populate_names_from_listfile(archive: &mut MpqArchive) -> Result<()> {
    if !archive.has_file("(listfile)") {
        return Ok(());
    }

    let bytes = archive.read_file("(listfile)")?;
    let _ = merge_listfile_names(archive, &bytes)?;
    Ok(())
}

fn merge_listfile_names(archive: &mut MpqArchive, bytes: &[u8]) -> Result<usize> {
    let mut added = 0usize;
    let text = String::from_utf8_lossy(bytes);
    for raw_line in text.lines() {
        let name = raw_line.trim();
        if name.is_empty() {
            continue;
        }
        if let Some(m) = lookup_file_name(
            &archive.tables.hash_table,
            archive.tables.block_table.len(),
            name,
        ) {
            if let std::collections::btree_map::Entry::Vacant(v) =
                archive.file_names.entry(m.block_index)
            {
                v.insert(name.to_string());
                added += 1;
            }
        }
    }
    Ok(added)
}

#[derive(Debug, Clone)]
struct PatchNameIndex {
    entries: BTreeMap<String, ArchiveListItem>,
}

#[derive(Clone, Eq)]
struct PatchCacheKey {
    base: String,
    patches: Vec<PatchCacheEntryKey>,
}

#[derive(Clone, Eq)]
struct PatchCacheEntryKey {
    path: String,
    prefix: Option<String>,
}

impl PartialEq for PatchCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.base == other.base && self.patches == other.patches
    }
}

impl Hash for PatchCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.base.hash(state);
        self.patches.hash(state);
    }
}

impl PartialEq for PatchCacheEntryKey {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.prefix == other.prefix
    }
}

impl Hash for PatchCacheEntryKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
        self.prefix.hash(state);
    }
}

fn patch_name_index(archive: &MpqArchive) -> BTreeMap<String, ArchiveListItem> {
    if archive.patch_chain.is_empty() {
        return BTreeMap::new();
    }

    let key = PatchCacheKey {
        base: archive.path.to_string_lossy().into_owned(),
        patches: archive
            .patch_chain
            .iter()
            .map(|p| PatchCacheEntryKey {
                path: p.path.to_string_lossy().into_owned(),
                prefix: p.prefix.clone(),
            })
            .collect(),
    };

    if let Ok(guard) = patch_cache_cell().read() {
        if let Some(cached) = guard.get(&key) {
            return cached.entries.clone();
        }
    }

    let built = build_patch_name_index(archive);
    if let Ok(mut guard) = patch_cache_cell().write() {
        guard.insert(
            key,
            PatchNameIndex {
                entries: built.clone(),
            },
        );
    }
    built
}

fn build_patch_name_index(archive: &MpqArchive) -> BTreeMap<String, ArchiveListItem> {
    let mut out = BTreeMap::new();
    for patch_entry in &archive.patch_chain {
        let Ok(mut patch) = MpqArchive::open(&patch_entry.path) else {
            continue;
        };
        if !patch.has_file("(listfile)") {
            continue;
        }
        let Ok(bytes) = patch.read_file("(listfile)") else {
            continue;
        };

        let prefix = patch_entry.prefix.as_deref().filter(|s| !s.is_empty());
        let text = String::from_utf8_lossy(&bytes);
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }

            let normalized = normalize_name_slash(line);
            let logical = if let Some(prefix) = prefix {
                if let Some(stripped) = normalized.strip_prefix(prefix) {
                    stripped.to_string()
                } else {
                    normalized.clone()
                }
            } else {
                normalized.clone()
            };

            if logical.is_empty() {
                continue;
            }

            let Some(m) = lookup_file_name(
                &patch.tables.hash_table,
                patch.tables.block_table.len(),
                &normalized,
            ) else {
                continue;
            };
            let hash_entry = patch.tables.hash_table[m.hash_index];
            let Ok(flags) = block_flags_for_hash(&patch, hash_entry) else {
                continue;
            };
            let item = ArchiveListItem {
                hash_index: m.hash_index,
                block_index: m.block_index,
                name: Some(logical.clone()),
                locale: hash_entry.locale,
                platform: hash_entry.platform,
                flags,
            };
            out.insert(logical, item);
        }
    }
    out
}

fn normalize_name_slash(name: &str) -> String {
    name.replace('/', "\\")
}

pub(crate) fn block_flags_for_hash(
    archive: &MpqArchive,
    hash: HashTableEntry,
) -> Result<MpqFileFlags> {
    let idx = hash.block_index as usize;
    let b = archive
        .tables
        .block_table
        .get(idx)
        .copied()
        .ok_or(StormError::Bounds("hash entry block index out of range"))?;
    Ok(b.flags)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::types::{BlockTableEntry, HashTableEntry, Header, MpqArchive, MpqFileFlags, Tables};

    #[test]
    fn list_skips_free_and_deleted_hash_entries() {
        let archive = MpqArchive {
            stream: crate::stream::FileStream::create(
                tempfile::tempdir().unwrap().path().join("x"),
            )
            .unwrap(),
            path: "dummy".into(),
            header: Header {
                archive_offset: 0,
                header_size: 32,
                archive_size_32: 0,
                format_version: 0,
                sector_size_shift: 3,
                hash_table_pos: 0,
                block_table_pos: 0,
                hash_table_entries: 2,
                block_table_entries: 1,
                hi_block_table_pos_64: None,
                hash_table_pos_hi: None,
                block_table_pos_hi: None,
                archive_size_64: None,
                bet_table_pos_64: None,
                het_table_pos_64: None,
                hash_table_size_64: None,
                block_table_size_64: None,
                hi_block_table_size_64: None,
                het_table_size_64: None,
                bet_table_size_64: None,
                raw_chunk_size: None,
            },
            tables: Tables {
                hash_table: vec![
                    HashTableEntry {
                        hash_a: 1,
                        hash_b: 2,
                        locale: 0,
                        platform: 0,
                        flags: 0,
                        block_index: 0,
                    },
                    HashTableEntry {
                        hash_a: 0,
                        hash_b: 0,
                        locale: 0,
                        platform: 0,
                        flags: 0,
                        block_index: HashTableEntry::BLOCK_INDEX_FREE,
                    },
                ],
                block_table: vec![BlockTableEntry {
                    file_pos: 0,
                    compressed_size: 1,
                    file_size: 1,
                    flags: MpqFileFlags::EXISTS,
                }],
            },
            file_names: Default::default(),
            write_manifest: None,
            patch_chain: Vec::new(),
            create_listfile: false,
            create_attributes: false,
        };
        let list = archive.list().unwrap();
        assert_eq!(list.len(), 1);
    }

    static CALLBACK_HITS: AtomicUsize = AtomicUsize::new(0);

    fn bump_callback(_: &crate::types::ArchiveListItem) {
        CALLBACK_HITS.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn list_invokes_registered_callback() {
        CALLBACK_HITS.store(0, Ordering::Relaxed);
        crate::types::MpqArchive::set_list_callback(Some(bump_callback));

        let archive = MpqArchive {
            stream: crate::stream::FileStream::create(
                tempfile::tempdir().unwrap().path().join("x"),
            )
            .unwrap(),
            path: "dummy".into(),
            header: Header {
                archive_offset: 0,
                header_size: 32,
                archive_size_32: 0,
                format_version: 0,
                sector_size_shift: 3,
                hash_table_pos: 0,
                block_table_pos: 0,
                hash_table_entries: 2,
                block_table_entries: 1,
                hi_block_table_pos_64: None,
                hash_table_pos_hi: None,
                block_table_pos_hi: None,
                archive_size_64: None,
                bet_table_pos_64: None,
                het_table_pos_64: None,
                hash_table_size_64: None,
                block_table_size_64: None,
                hi_block_table_size_64: None,
                het_table_size_64: None,
                bet_table_size_64: None,
                raw_chunk_size: None,
            },
            tables: Tables {
                hash_table: vec![
                    HashTableEntry {
                        hash_a: 1,
                        hash_b: 2,
                        locale: 0,
                        platform: 0,
                        flags: 0,
                        block_index: 0,
                    },
                    HashTableEntry {
                        hash_a: 0,
                        hash_b: 0,
                        locale: 0,
                        platform: 0,
                        flags: 0,
                        block_index: HashTableEntry::BLOCK_INDEX_FREE,
                    },
                ],
                block_table: vec![BlockTableEntry {
                    file_pos: 0,
                    compressed_size: 1,
                    file_size: 1,
                    flags: MpqFileFlags::EXISTS,
                }],
            },
            file_names: Default::default(),
            write_manifest: None,
            patch_chain: Vec::new(),
            create_listfile: false,
            create_attributes: false,
        };
        let list = archive.list().unwrap();
        assert!(CALLBACK_HITS.load(Ordering::Relaxed) >= list.len());
        crate::types::MpqArchive::set_list_callback(None);
    }
}
