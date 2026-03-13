use crate::archive::attributes::parse_attributes_file_with_expected_entries;
use crate::crypto::md5_digest;
use crate::error::{Result, StormError};
use crate::internal::file_table::lookup_file_name_with_locale;
use crate::types::MpqArchive;

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let mut x = (crc ^ b as u32) & 0xFF;
        for _ in 0..8 {
            x = if (x & 1) != 0 {
                (x >> 1) ^ 0xEDB8_8320
            } else {
                x >> 1
            };
        }
        crc = (crc >> 8) ^ x;
    }
    !crc
}

impl MpqArchive {
    pub fn get_file_checksums(&mut self, name: &str) -> Result<(u32, [u8; 16])> {
        let data = self.read_file(name)?;
        Ok((crc32_ieee(&data), md5_digest(&data)))
    }

    pub fn enum_locales(&self, name: &str) -> Result<Vec<u16>> {
        let mut locales = Vec::new();
        for h in self.tables.hash_table.iter().copied() {
            if h.is_free() || h.is_deleted() {
                continue;
            }
            if lookup_file_name_with_locale(
                &self.tables.hash_table,
                self.tables.block_table.len(),
                name,
                h.locale,
            )
            .is_some()
                && !locales.contains(&h.locale)
            {
                locales.push(h.locale);
            }
        }
        locales.sort_unstable();
        Ok(locales)
    }

    pub fn get_archive_attributes_flags(&mut self) -> Result<Option<u32>> {
        if !self.has_file("(attributes)") {
            return Ok(None);
        }
        let data = self.read_file("(attributes)")?;
        let parsed = parse_attributes_file_with_expected_entries(
            &data,
            Some(self.tables.block_table.len()),
        )?;
        Ok(Some(parsed.flags))
    }

    pub fn update_file_attributes(&mut self, name: &str) -> Result<()> {
        if !self.has_file("(attributes)") {
            return Err(StormError::NotFound("(attributes)".to_string()));
        }
        let Some(flags) = self.get_archive_attributes_flags()? else {
            return Err(StormError::NotFound("(attributes)".to_string()));
        };
        if !self.has_file(name) {
            return Err(StormError::NotFound(name.to_string()));
        }
        self.sync_attributes(flags)
    }
}
