use std::sync::OnceLock;

pub const MPQ_HASH_TABLE_INDEX: u32 = 0x000;
pub const MPQ_HASH_NAME_A: u32 = 0x100;
pub const MPQ_HASH_NAME_B: u32 = 0x200;
pub const MPQ_HASH_FILE_KEY: u32 = 0x300;
pub const MPQ_HASH_KEY2_MIX: u32 = 0x400;

static STORM_BUFFER: OnceLock<[u32; 0x500]> = OnceLock::new();

fn ascii_upper(byte: u8, convert_slash: bool) -> u8 {
    match byte {
        b'/' if convert_slash => b'\\',
        b'a'..=b'z' => byte - 32,
        _ => byte,
    }
}

pub fn storm_buffer() -> &'static [u32; 0x500] {
    STORM_BUFFER.get_or_init(|| {
        let mut table = [0u32; 0x500];
        let mut seed: u32 = 0x0010_0001;
        for index1 in 0..0x100usize {
            let mut index2 = index1;
            for _ in 0..5 {
                seed = (seed.wrapping_mul(125).wrapping_add(3)) % 0x2AAAAB;
                let temp1 = (seed & 0xFFFF) << 16;
                seed = (seed.wrapping_mul(125).wrapping_add(3)) % 0x2AAAAB;
                let temp2 = seed & 0xFFFF;
                table[index2] = temp1 | temp2;
                index2 += 0x100;
            }
        }
        table
    })
}

pub fn hash_string(name: &str, hash_type: u32) -> u32 {
    hash_bytes(name.as_bytes(), hash_type, true)
}

fn hash_bytes(bytes: &[u8], hash_type: u32, convert_slash: bool) -> u32 {
    let mut seed1 = 0x7FED_7FEDu32;
    let mut seed2 = 0xEEEE_EEEEu32;
    let t = storm_buffer();
    for &b in bytes {
        let ch = ascii_upper(b, convert_slash) as u32;
        seed1 = t[(hash_type + ch) as usize] ^ seed1.wrapping_add(seed2);
        seed2 = ch
            .wrapping_add(seed1)
            .wrapping_add(seed2)
            .wrapping_add(seed2 << 5)
            .wrapping_add(3);
    }
    seed1
}

#[inline]
fn mpq_key1_step(key1: u32) -> u32 {
    ((!key1) << 21).wrapping_add(0x1111_1111) | (key1 >> 11)
}

pub fn encrypt_mpq_block_in_place(data: &mut [u8], mut key1: u32) {
    let words = data.len() / 4;
    let t = storm_buffer();
    let mut key2 = 0xEEEE_EEEEu32;

    for i in 0..words {
        key2 = key2.wrapping_add(t[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);
        let start = i * 4;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&data[start..start + 4]);
        let value32 = u32::from_le_bytes(raw);
        let enc = value32 ^ key1.wrapping_add(key2);
        data[start..start + 4].copy_from_slice(&enc.to_le_bytes());
        key1 = mpq_key1_step(key1);
        key2 = value32
            .wrapping_add(key2)
            .wrapping_add(key2 << 5)
            .wrapping_add(3);
    }
}

pub fn decrypt_mpq_block_in_place(data: &mut [u8], mut key1: u32) {
    let words = data.len() / 4;
    let t = storm_buffer();
    let mut key2 = 0xEEEE_EEEEu32;

    for i in 0..words {
        key2 = key2.wrapping_add(t[(MPQ_HASH_KEY2_MIX + (key1 & 0xFF)) as usize]);
        let start = i * 4;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&data[start..start + 4]);
        let encrypted = u32::from_le_bytes(raw);
        let value32 = encrypted ^ key1.wrapping_add(key2);
        data[start..start + 4].copy_from_slice(&value32.to_le_bytes());
        key1 = mpq_key1_step(key1);
        key2 = value32
            .wrapping_add(key2)
            .wrapping_add(key2 << 5)
            .wrapping_add(3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hash_vectors_match_stormlib_constants() {
        // Constants documented in StormLib.h
        assert_eq!(hash_string("(hash table)", MPQ_HASH_FILE_KEY), 0xC3AF_3770);
        assert_eq!(hash_string("(block table)", MPQ_HASH_FILE_KEY), 0xEC83_B3A3);
    }

    #[test]
    fn encryption_decryption_roundtrip() {
        let key = hash_string("fixtures\\models\\footman.mdx", MPQ_HASH_FILE_KEY);
        let mut data = vec![
            0x11, 0x22, 0x33, 0x44, 0xCA, 0xFE, 0xBA, 0xBE, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        let original = data.clone();
        encrypt_mpq_block_in_place(&mut data, key);
        assert_ne!(data, original);
        decrypt_mpq_block_in_place(&mut data, key);
        assert_eq!(data, original);
    }
}
