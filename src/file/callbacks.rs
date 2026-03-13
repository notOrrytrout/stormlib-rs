use std::sync::{OnceLock, RwLock};

use crate::types::{AddFileCallback, CompactCallback, MpqArchive};

static ADD_FILE_CALLBACK: OnceLock<RwLock<Option<AddFileCallback>>> = OnceLock::new();
static COMPACT_CALLBACK: OnceLock<RwLock<Option<CompactCallback>>> = OnceLock::new();

fn add_file_callback_cell() -> &'static RwLock<Option<AddFileCallback>> {
    ADD_FILE_CALLBACK.get_or_init(|| RwLock::new(None))
}

fn compact_callback_cell() -> &'static RwLock<Option<CompactCallback>> {
    COMPACT_CALLBACK.get_or_init(|| RwLock::new(None))
}

pub(crate) fn invoke_add_file_callback(done: usize, total: usize) {
    if let Ok(guard) = add_file_callback_cell().read() {
        if let Some(cb) = *guard {
            cb(done, total);
        }
    }
}

pub(crate) fn invoke_compact_callback(done: usize, total: usize) {
    if let Ok(guard) = compact_callback_cell().read() {
        if let Some(cb) = *guard {
            cb(done, total);
        }
    }
}

impl MpqArchive {
    pub fn set_add_file_callback(callback: Option<AddFileCallback>) {
        if let Ok(mut guard) = add_file_callback_cell().write() {
            *guard = callback;
        }
    }

    pub fn set_compact_callback(callback: Option<CompactCallback>) {
        if let Ok(mut guard) = compact_callback_cell().write() {
            *guard = callback;
        }
    }
}
