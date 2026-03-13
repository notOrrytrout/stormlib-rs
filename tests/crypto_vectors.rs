use stormlib_rs::{decrypt_mpq_block, derive_file_key, encrypt_mpq_block};

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn crypto_vectors() {
    let text = include_str!("../fixtures/crypto_vectors.txt");
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        assert!(parts.len() == 6, "bad vector line {}: {}", lineno + 1, line);
        let name = parts[0];
        let mpq_pos = u32::from_str_radix(parts[1], 16).expect("mpq_pos");
        let file_size = u32::from_str_radix(parts[2], 16).expect("file_size");
        let fix_key = parts[3] == "1";
        let plain = hex_decode(parts[4]);
        let encrypted = hex_decode(parts[5]);
        assert_eq!(plain.len(), encrypted.len());
        assert!(
            plain.len().is_multiple_of(4),
            "vector plaintext must be multiple of 4 bytes"
        );

        let key = derive_file_key(name, mpq_pos as u64, file_size, fix_key);

        let mut buf = plain.clone();
        encrypt_mpq_block(&mut buf, key);
        assert_eq!(buf, encrypted, "encrypt mismatch for {}", name);

        decrypt_mpq_block(&mut buf, key);
        assert_eq!(buf, plain, "decrypt mismatch for {}", name);
    }
}
