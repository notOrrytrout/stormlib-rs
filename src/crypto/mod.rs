use md5::Md5;
use sha1::Digest as _;

use crate::internal::common::{
    decrypt_mpq_block_in_place, encrypt_mpq_block_in_place, hash_string, MPQ_HASH_FILE_KEY,
};

pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

pub fn encrypt_mpq_block(data: &mut [u8], key: u32) {
    encrypt_mpq_block_in_place(data, key)
}

pub fn decrypt_mpq_block(data: &mut [u8], key: u32) {
    decrypt_mpq_block_in_place(data, key)
}

pub fn plain_file_name(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

pub fn derive_file_key(name: &str, mpq_pos: u64, file_size: u32, fix_key: bool) -> u32 {
    let mut key = hash_string(plain_file_name(name), MPQ_HASH_FILE_KEY);
    if fix_key {
        key = key.wrapping_add(mpq_pos as u32) ^ file_size;
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_have_expected_hex() {
        assert_eq!(
            hex::encode(md5_digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn file_key_uses_plain_name_and_optional_fixup() {
        let a = derive_file_key("dir/sub/file.txt", 0x1234, 0x80, false);
        let b = derive_file_key("file.txt", 0x9999, 0x80, false);
        assert_eq!(a, b);

        let fixed = derive_file_key("file.txt", 0x1234, 0x80, true);
        assert_ne!(fixed, b);
        assert_eq!(fixed, b.wrapping_add(0x1234) ^ 0x80);
    }

    #[test]
    fn encryption_vector_regression() {
        // Regression vector generated from StormLib-compatible algorithm in SBaseCommon.cpp.
        let key = derive_file_key("fixtures\\models\\footman.mdx", 0, 12, false);
        let mut data = vec![
            0x11, 0x22, 0x33, 0x44, 0xCA, 0xFE, 0xBA, 0xBE, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        encrypt_mpq_block(&mut data, key);
        assert_eq!(hex::encode(&data), "cceec7070e38b6b2800230fa");
        decrypt_mpq_block(&mut data, key);
        assert_eq!(
            data,
            vec![0x11, 0x22, 0x33, 0x44, 0xCA, 0xFE, 0xBA, 0xBE, 0xAA, 0xBB, 0xCC, 0xDD]
        );
    }
}
