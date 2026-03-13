//! Pure-Rust implementation of the MPQ ADPCM codec (mono/stereo).
//!
//! Matches StormLib's `CompressADPCM` / `DecompressADPCM` (see
//! `StormLib-master/src/adpcm/adpcm.cpp`).
//!
//! Notes
//! - Input and output PCM are 16-bit little-endian.
//! - Encoded stream begins with two bytes: 0x00, then `bit_shift = level - 1`.
//! - Marker bytes 0x80 and 0x81 are emitted/handled exactly as StormLib.

use crate::error::{Result, StormError};

const INITIAL_ADPCM_STEP_INDEX: i32 = 0x2C;

const NEXT_STEP_TABLE: [i32; 32] = [
    -1, 0, -1, 4, -1, 2, -1, 6, -1, 1, -1, 5, -1, 3, -1, 7, -1, 1, -1, 5, -1, 3, -1, 7, -1, 2, -1,
    4, -1, 6, -1, 8,
];

const STEP_SIZE_TABLE: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

#[inline]
fn get_next_step_index(step_index: i32, encoded: u8) -> i32 {
    let idx = step_index + NEXT_STEP_TABLE[(encoded & 0x1F) as usize];
    idx.clamp(0, 88)
}

#[inline]
fn update_predicted_sample(predicted: i32, encoded: u8, diff: i32, bitmask: u8) -> i32 {
    if (encoded & bitmask) != 0 {
        let mut v = predicted - diff;
        if v <= -32768 {
            v = -32768;
        }
        v
    } else {
        let mut v = predicted + diff;
        if v >= 32767 {
            v = 32767;
        }
        v
    }
}

#[inline]
fn decode_sample(predicted: i32, encoded: u8, step_size: i32, mut diff: i32) -> i32 {
    if (encoded & 0x01) != 0 {
        diff += step_size;
    }
    if (encoded & 0x02) != 0 {
        diff += step_size >> 1;
    }
    if (encoded & 0x04) != 0 {
        diff += step_size >> 2;
    }
    if (encoded & 0x08) != 0 {
        diff += step_size >> 3;
    }
    if (encoded & 0x10) != 0 {
        diff += step_size >> 4;
    }
    if (encoded & 0x20) != 0 {
        diff += step_size >> 5;
    }
    update_predicted_sample(predicted, encoded, diff, 0x40)
}

#[inline]
fn read_i16_le(input: &[u8], pos: &mut usize) -> Option<i16> {
    if *pos + 2 > input.len() {
        return None;
    }
    let v = i16::from_le_bytes([input[*pos], input[*pos + 1]]);
    *pos += 2;
    Some(v)
}

#[inline]
fn write_i16_le(out: &mut Vec<u8>, v: i16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn compress_adpcm(input_pcm: &[u8], channels: usize, compression_level: u8) -> Result<Vec<u8>> {
    if channels == 0 || channels > 2 {
        return Err(StormError::Compression("ADPCM supports 1 or 2 channels"));
    }
    if compression_level < 1 {
        return Err(StormError::Compression("invalid ADPCM compression level"));
    }
    if input_pcm.len() % 2 != 0 {
        return Err(StormError::Compression("ADPCM input must be 16-bit PCM"));
    }

    let bit_shift = compression_level - 1;
    let mut out = Vec::with_capacity(input_pcm.len());
    out.push(0);
    out.push(bit_shift);

    let mut predicted: [i32; 2] = [0, 0];
    let mut step_idx: [i32; 2] = [INITIAL_ADPCM_STEP_INDEX, INITIAL_ADPCM_STEP_INDEX];

    let mut pos = 0usize;
    for item in predicted.iter_mut().take(channels) {
        let s = read_i16_le(input_pcm, &mut pos).ok_or(StormError::Compression(
            "missing initial PCM sample for ADPCM",
        ))?;
        *item = s as i32;
        write_i16_le(&mut out, s);
    }

    let mut channel_index = channels - 1;
    while let Some(sample) = read_i16_le(input_pcm, &mut pos) {
        channel_index = (channel_index + 1) % channels;

        let mut encoded: u8 = 0;
        let mut abs_diff = (sample as i32) - predicted[channel_index];
        if abs_diff < 0 {
            abs_diff = -abs_diff;
            encoded |= 0x40;
        }

        let mut step_size = STEP_SIZE_TABLE[step_idx[channel_index] as usize];
        if abs_diff < (step_size >> (compression_level as i32)) {
            if step_idx[channel_index] != 0 {
                step_idx[channel_index] -= 1;
            }
            out.push(0x80);
            continue;
        }

        while abs_diff > (step_size << 1) {
            if step_idx[channel_index] >= 0x58 {
                break;
            }
            step_idx[channel_index] += 8;
            if step_idx[channel_index] > 0x58 {
                step_idx[channel_index] = 0x58;
            }
            step_size = STEP_SIZE_TABLE[step_idx[channel_index] as usize];
            out.push(0x81);
        }

        let mut max_bitmask: i32 = 1 << ((bit_shift as i32) - 1);
        if max_bitmask > 0x20 {
            max_bitmask = 0x20;
        }
        let difference: i32 = step_size >> (bit_shift as i32);
        let mut total_step: i32 = 0;

        let mut ss = step_size;
        let mut bit_val: i32 = 0x01;
        while bit_val <= max_bitmask {
            if (total_step + ss) <= abs_diff {
                total_step += ss;
                encoded |= bit_val as u8;
            }
            ss >>= 1;
            bit_val <<= 1;
        }

        predicted[channel_index] = update_predicted_sample(
            predicted[channel_index],
            encoded,
            difference + total_step,
            0x40,
        );
        out.push(encoded);
        step_idx[channel_index] = get_next_step_index(step_idx[channel_index], encoded);
    }

    Ok(out)
}

pub fn decompress_adpcm(input: &[u8], channels: usize, expected_out_len: usize) -> Result<Vec<u8>> {
    if channels == 0 || channels > 2 {
        return Err(StormError::Compression("ADPCM supports 1 or 2 channels"));
    }
    if input.len() < 2 {
        return Err(StormError::Compression("ADPCM input too short"));
    }

    let mut out = Vec::with_capacity(expected_out_len);
    let mut predicted: [i32; 2] = [0, 0];
    let mut step_idx: [i32; 2] = [INITIAL_ADPCM_STEP_INDEX, INITIAL_ADPCM_STEP_INDEX];

    let mut pos = 0usize;
    // skip first byte (always 0)
    pos += 1;
    let bit_shift = input[pos];
    pos += 1;

    for item in predicted.iter_mut().take(channels) {
        let s = read_i16_le(input, &mut pos)
            .ok_or(StormError::Compression("missing initial ADPCM sample"))?;
        *item = s as i32;
        write_i16_le(&mut out, s);
    }

    let mut channel_index = channels - 1;
    while pos < input.len() {
        let encoded = input[pos];
        pos += 1;
        channel_index = (channel_index + 1) % channels;

        if encoded == 0x80 {
            if step_idx[channel_index] != 0 {
                step_idx[channel_index] -= 1;
            }
            write_i16_le(&mut out, predicted[channel_index] as i16);
        } else if encoded == 0x81 {
            step_idx[channel_index] += 8;
            if step_idx[channel_index] > 0x58 {
                step_idx[channel_index] = 0x58;
            }
            // Next pass should continue on the same channel
            channel_index = (channel_index + 1) % channels;
        } else {
            let step_index = step_idx[channel_index];
            let step_size = STEP_SIZE_TABLE[step_index as usize];
            let predicted_new = decode_sample(
                predicted[channel_index],
                encoded,
                step_size,
                step_size >> (bit_shift as i32),
            );
            predicted[channel_index] = predicted_new;
            write_i16_le(&mut out, predicted_new as i16);
            step_idx[channel_index] = get_next_step_index(step_index, encoded);
        }

        if out.len() >= expected_out_len {
            break;
        }
    }

    if out.len() != expected_out_len {
        return Err(StormError::CompressionOwned {
            message: format!(
                "ADPCM decompressed size mismatch: got {}, expected {}",
                out.len(),
                expected_out_len
            ),
        });
    }
    Ok(out)
}
