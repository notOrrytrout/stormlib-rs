//! MPQ "sparse" compression (StormLib compatible).
//!
//! This codec is used in some MPQ sectors to encode runs of zeros.
//!
//! ## Format (as implemented by StormLib)
//! * Output begins with a 4-byte big-endian original length.
//! * Then a sequence of chunks:
//!   * If marker byte has high bit set (0x80): copy (marker&0x7F)+1 bytes
//!   * Else: write (marker&0x7F)+3 zero bytes
//!
//! Note: The encoder keeps a historical quirk for exact byte compatibility
//! (see comments in StormLib `CompressSparse`).

use crate::error::{Result, StormError};

pub fn compress_sparse(input: &[u8]) -> Result<Vec<u8>> {
    if input.len() < 4 {
        // StormLib early-outs (writes nothing) when input < 4; for our API,
        // just return a minimal encoded stream.
        return Err(StormError::Compression(
            "sparse compression requires >= 4 bytes",
        ));
    }

    let mut out: Vec<u8> = Vec::with_capacity(input.len() + 16);
    let len = input.len() as u32;
    // StormLib writes length as big-endian bytes.
    out.extend_from_slice(&len.to_be_bytes());

    let mut in_pos: usize = 0;
    let end = input.len();

    // main loop processes while at least 3 bytes remain (StormLib uses end-3)
    while in_pos < end.saturating_sub(3) {
        let mut last_nonzero = in_pos;
        let mut ptr = in_pos;
        let mut zeros: usize = 0;

        while ptr < end {
            if input[ptr] == 0 {
                zeros += 1;
            } else {
                if zeros >= 3 {
                    break;
                }
                last_nonzero = ptr + 1;
                zeros = 0;
            }
            ptr += 1;
        }

        let mut nonzeros = last_nonzero - in_pos;
        if nonzeros != 0 {
            // blocks longer than 0x81 nonzero bytes
            while nonzeros > 0x81 {
                out.push(0xFF); // marker for 0x80 nonzeros
                out.extend_from_slice(&input[in_pos..in_pos + 0x80]);
                nonzeros -= 0x80;
                in_pos += 0x80;
            }

            // StormLib quirk: if nonzeros == 0x81, it emits marker 0x80 and copies 1 byte
            if nonzeros > 0x80 {
                out.push(0x80);
                out.push(input[in_pos]);
                nonzeros -= 1;
                in_pos += 1;
            }

            if nonzeros >= 0x01 {
                out.push(0x80 | ((nonzeros - 1) as u8));
                out.extend_from_slice(&input[in_pos..in_pos + nonzeros]);
                in_pos += nonzeros;
            }
        }

        // flush zeros
        while zeros > 0x85 {
            out.push(0x7F); // 0x82 zeros
            zeros -= 0x82;
            in_pos += 0x82;
        }

        if zeros > 0x82 {
            out.push(0x00); // 0x03 zeros
            zeros -= 0x03;
            in_pos += 0x03;
        }

        if zeros >= 3 {
            out.push((zeros - 3) as u8);
            in_pos += zeros;
        }
    }

    // flush last bytes
    if in_pos < end {
        let mut ptr = in_pos;
        loop {
            if input[ptr] != 0 {
                let remaining = end - in_pos;
                out.push(0xFF);
                out.extend_from_slice(&input[in_pos..]);
                let _ = remaining;
                break;
            } else {
                ptr += 1;
                if ptr < end {
                    continue;
                }
                out.push(0x7F);
                break;
            }
        }
    }

    Ok(out)
}

#[allow(dead_code)]
pub fn decompress_sparse(input: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    decompress_sparse_len(input, Some(expected_len))
}

/// Decompresses a sparse stream, optionally enforcing the expected output length.
pub fn decompress_sparse_len(input: &[u8], expected_len: Option<usize>) -> Result<Vec<u8>> {
    if input.len() < 5 {
        return Err(StormError::Compression("sparse stream too short"));
    }
    let declared = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
    if let Some(expected) = expected_len {
        if declared != expected {
            // keep strict; caller expected size is authoritative.
            return Err(StormError::CompressionOwned {
                message: format!("sparse declared size {}, expected {}", declared, expected),
            });
        }
    }

    let mut out = vec![0u8; declared];
    let mut out_pos: usize = 0;
    let mut in_pos: usize = 4;

    while in_pos < input.len() {
        let marker = input[in_pos];
        in_pos += 1;

        if marker & 0x80 != 0 {
            let mut chunk = ((marker & 0x7F) as usize) + 1;
            if in_pos + chunk > input.len() {
                return Err(StormError::Compression("sparse copy chunk overruns input"));
            }
            chunk = chunk.min(declared - out_pos);
            out[out_pos..out_pos + chunk].copy_from_slice(&input[in_pos..in_pos + chunk]);
            in_pos += chunk;
            out_pos += chunk;
        } else {
            let mut chunk = ((marker & 0x7F) as usize) + 3;
            chunk = chunk.min(declared - out_pos);
            // already zero-initialized, just advance
            out_pos += chunk;
        }
        if out_pos >= declared {
            break;
        }
    }

    Ok(out)
}
