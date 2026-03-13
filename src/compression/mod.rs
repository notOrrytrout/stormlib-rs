#[cfg(any(feature = "compression-zlib", feature = "compression-bzip2"))]
use std::io::{Read, Write};

mod adpcm;
mod huffman;
mod huffman_tables;
mod sparse;

use crate::error::{Result, StormError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    None,
    Zlib,
    Bzip2,
    Lzma,
    Huffman,
    AdpcmMono,
    AdpcmStereo,
    PkwareImplode,
    Sparse,
}

pub const MPQ_COMPRESSION_HUFFMANN: u8 = 0x01;
pub const MPQ_COMPRESSION_ZLIB: u8 = 0x02;
pub const MPQ_COMPRESSION_PKWARE: u8 = 0x08;
pub const MPQ_COMPRESSION_BZIP2: u8 = 0x10;
pub const MPQ_COMPRESSION_SPARSE: u8 = 0x20;
pub const MPQ_COMPRESSION_ADPCM_MONO: u8 = 0x40;
pub const MPQ_COMPRESSION_ADPCM_STEREO: u8 = 0x80;
pub const MPQ_COMPRESSION_LZMA: u8 = 0x12;

impl CompressionMethod {
    pub fn from_mpq_mask(mask: u8) -> Result<Self> {
        match mask {
            0 => Ok(Self::None),
            MPQ_COMPRESSION_ZLIB => Ok(Self::Zlib),
            MPQ_COMPRESSION_BZIP2 => Ok(Self::Bzip2),
            MPQ_COMPRESSION_LZMA => Ok(Self::Lzma),
            MPQ_COMPRESSION_HUFFMANN => Ok(Self::Huffman),
            MPQ_COMPRESSION_ADPCM_MONO => Ok(Self::AdpcmMono),
            MPQ_COMPRESSION_ADPCM_STEREO => Ok(Self::AdpcmStereo),
            MPQ_COMPRESSION_PKWARE => Ok(Self::PkwareImplode),
            MPQ_COMPRESSION_SPARSE => Ok(Self::Sparse),
            _ => Err(StormError::UnsupportedFeature(
                "unsupported MPQ compression mask combination",
            )),
        }
    }

    pub fn to_mpq_mask(self) -> Option<u8> {
        match self {
            Self::None => Some(0),
            Self::Zlib => Some(MPQ_COMPRESSION_ZLIB),
            Self::Bzip2 => Some(MPQ_COMPRESSION_BZIP2),
            Self::Lzma => Some(MPQ_COMPRESSION_LZMA),
            Self::Huffman => Some(MPQ_COMPRESSION_HUFFMANN),
            Self::AdpcmMono => Some(MPQ_COMPRESSION_ADPCM_MONO),
            Self::AdpcmStereo => Some(MPQ_COMPRESSION_ADPCM_STEREO),
            Self::PkwareImplode => Some(MPQ_COMPRESSION_PKWARE),
            Self::Sparse => Some(MPQ_COMPRESSION_SPARSE),
        }
    }
}

pub fn decompress(
    method: CompressionMethod,
    input: &[u8],
    expected_len: Option<usize>,
) -> Result<Vec<u8>> {
    let out = match method {
        CompressionMethod::None => input.to_vec(),
        CompressionMethod::Zlib => decompress_zlib(input)?,
        CompressionMethod::Bzip2 => decompress_bzip2(input)?,
        CompressionMethod::Lzma => decompress_lzma(input)?,
        CompressionMethod::PkwareImplode => decompress_pkware(input)?,
        CompressionMethod::Sparse => {
            // Pure-Rust implementation (byte-identical to StormLib sparse codec).
            sparse::decompress_sparse_len(input, expected_len)?
        }

        CompressionMethod::AdpcmMono => {
            let expected = expected_len.unwrap_or(0);
            return adpcm::decompress_adpcm(input, 1, expected);
        }

        CompressionMethod::AdpcmStereo => {
            let expected = expected_len.unwrap_or(0);
            return adpcm::decompress_adpcm(input, 2, expected);
        }

        CompressionMethod::Huffman => {
            return huffman::decompress_huffman_len(input, expected_len);
        }
    };

    if let Some(expected) = expected_len {
        if out.len() != expected {
            return Err(StormError::CompressionOwned {
                message: format!(
                    "decompressed size mismatch: got {}, expected {}",
                    out.len(),
                    expected
                ),
            });
        }
    }
    Ok(out)
}

pub fn compress(method: CompressionMethod, input: &[u8]) -> Result<Vec<u8>> {
    match method {
        CompressionMethod::None => Ok(input.to_vec()),
        CompressionMethod::Zlib => compress_zlib(input),
        CompressionMethod::Bzip2 => compress_bzip2(input),
        CompressionMethod::Lzma => compress_lzma(input),
        CompressionMethod::Sparse => sparse::compress_sparse(input),

        CompressionMethod::AdpcmMono => {
            // Equivalent to StormLib's default mapping (SCompression.cpp) when
            // nCmpLevel is not specified: internal CompressionLevel=5.
            adpcm::compress_adpcm(input, 1, 5)
        }

        CompressionMethod::AdpcmStereo => adpcm::compress_adpcm(input, 2, 5),

        CompressionMethod::Huffman => {
            // StormLib's SCompCompress uses nCmpType as the Huffman "CompressionType".
            // For plain Huffman compression, callers typically use nCmpType=0.
            // (See StormLib-master/src/SCompression.cpp -> Compress_huff)
            huffman::compress_huffman(input, 0)
        }
        CompressionMethod::PkwareImplode => compress_pkware(input),
    }
}

#[cfg(feature = "compression-pkware")]
fn compress_pkware(input: &[u8]) -> Result<Vec<u8>> {
    // StormLib reference (oracle): StormLib-master/src/SCompression.cpp -> Compress_PKLIB
    // MPQ uses PKWARE 'implode' with:
    //   - ctype = CMP_BINARY
    //   - dict size: 1024 if <0x600, 2048 if <0xC00, else 4096
    // We mirror that selection to match StormLib's byte stream.
    let dict = if input.len() < 0x600 {
        pklib::DictionarySize::Size1K
    } else if input.len() < 0xC00 {
        pklib::DictionarySize::Size2K
    } else {
        pklib::DictionarySize::Size4K
    };

    pklib::implode_bytes(input, pklib::CompressionMode::Binary, dict).map_err(|e| {
        StormError::CompressionOwned {
            message: e.to_string(),
        }
    })
}

#[cfg(not(feature = "compression-pkware"))]
fn compress_pkware(_input: &[u8]) -> Result<Vec<u8>> {
    Err(StormError::UnsupportedFeature(
        "pkware support disabled (feature: compression-pkware)",
    ))
}

pub fn decompress_masked(input: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Err(StormError::Compression("missing MPQ compression mask"));
    }
    // Fast path: single-bit masks.
    if let Ok(method) = CompressionMethod::from_mpq_mask(input[0]) {
        return decompress(method, &input[1..], Some(expected_len));
    }

    // Multi-mask chaining (StormLib order). Pure Rust implementation.
    decompress_masked_stormlib_order(input[0], &input[1..], expected_len)
}

/// Decompresses MPQ "multi compression" streams (mask combinations) in the exact
/// transform order StormLib uses for `SCompDecompressInternal`.
///
/// Reference (oracle-only, not runtime dependency):
/// `/mnt/data/workspace/workspace/StormLib-master/src/SCompression.cpp` (`dcmp_table`).
///
/// Limitations (tracked):
/// - Intermediate stages that do not embed output lengths rely on terminators or
///   format-specific length headers to delimit output.
pub fn decompress_masked_stormlib_order(
    mask: u8,
    payload: &[u8],
    expected_len: usize,
) -> Result<Vec<u8>> {
    // StormLib doesn't support LZMA inside the multi-mask path.
    if mask == MPQ_COMPRESSION_LZMA {
        return decompress(CompressionMethod::Lzma, payload, Some(expected_len));
    }

    // Determine the active stages in StormLib's decompression table order.
    // StormLib dcmp_table order:
    //   BZIP2, PKWARE, ZLIB, HUFFMAN, ADPCM_STEREO, ADPCM_MONO, SPARSE
    let mut stages: Vec<CompressionMethod> = Vec::new();
    if (mask & MPQ_COMPRESSION_BZIP2) != 0 {
        stages.push(CompressionMethod::Bzip2);
    }
    if (mask & MPQ_COMPRESSION_PKWARE) != 0 {
        stages.push(CompressionMethod::PkwareImplode);
    }
    if (mask & MPQ_COMPRESSION_ZLIB) != 0 {
        stages.push(CompressionMethod::Zlib);
    }
    if (mask & MPQ_COMPRESSION_HUFFMANN) != 0 {
        stages.push(CompressionMethod::Huffman);
    }
    if (mask & MPQ_COMPRESSION_ADPCM_STEREO) != 0 {
        stages.push(CompressionMethod::AdpcmStereo);
    }
    if (mask & MPQ_COMPRESSION_ADPCM_MONO) != 0 {
        stages.push(CompressionMethod::AdpcmMono);
    }
    if (mask & MPQ_COMPRESSION_SPARSE) != 0 {
        stages.push(CompressionMethod::Sparse);
    }

    if stages.is_empty() {
        return Err(StormError::UnsupportedFeature(
            "unsupported MPQ compression mask combination",
        ));
    }

    #[cfg(feature = "strict-multi-mask")]
    {
        // Guard intermediate-length requirements for strict StormLib safety.
        if let Some(huff_pos) = stages.iter().position(|s| *s == CompressionMethod::Huffman) {
            if huff_pos + 1 != stages.len() {
                return Err(StormError::UnsupportedFeature(
                    "Huffman-in-the-middle combos not supported yet (strict-multi-mask)",
                ));
            }
        }

        if stages.len() > 1 && stages.contains(&CompressionMethod::Sparse) {
            return Err(StormError::UnsupportedFeature(
                "Sparse combos not supported yet (strict-multi-mask)",
            ));
        }
    }

    // Apply in order.
    let mut cur = payload.to_vec();
    for (idx, stage) in stages.iter().enumerate() {
        let is_last = idx + 1 == stages.len();
        let expected = if is_last { Some(expected_len) } else { None };
        cur = decompress(*stage, &cur, expected)?;
    }
    Ok(cur)
}

pub fn compress_masked_best_effort(
    method: CompressionMethod,
    input: &[u8],
) -> Result<(Vec<u8>, bool)> {
    if method == CompressionMethod::None {
        return Ok((input.to_vec(), false));
    }

    let compressed = compress(method, input)?;
    if compressed.len() + 1 >= input.len() {
        return Ok((input.to_vec(), false));
    }

    let mask = method.to_mpq_mask().ok_or(StormError::UnsupportedFeature(
        "compression method has no MPQ mask",
    ))?;
    let mut out = Vec::with_capacity(compressed.len() + 1);
    out.push(mask);
    out.extend_from_slice(&compressed);
    Ok((out, true))
}

#[cfg(feature = "compression-zlib")]
fn decompress_zlib(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(input);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| StormError::CompressionOwned {
            message: e.to_string(),
        })?;
    Ok(out)
}

#[cfg(not(feature = "compression-zlib"))]
fn decompress_zlib(_input: &[u8]) -> Result<Vec<u8>> {
    Err(StormError::UnsupportedFeature(
        "zlib support disabled (feature: compression-zlib)",
    ))
}

#[cfg(feature = "compression-zlib")]
fn compress_zlib(input: &[u8]) -> Result<Vec<u8>> {
    let compress = zlib_compress_engine(input);
    let mut enc = flate2::write::ZlibEncoder::new_with_compress(Vec::new(), compress);
    enc.write_all(input)
        .map_err(|e| StormError::CompressionOwned {
            message: e.to_string(),
        })?;
    enc.finish().map_err(|e| StormError::CompressionOwned {
        message: e.to_string(),
    })
}

#[cfg(not(feature = "compression-zlib"))]
fn compress_zlib(_input: &[u8]) -> Result<Vec<u8>> {
    Err(StormError::UnsupportedFeature(
        "zlib support disabled (feature: compression-zlib)",
    ))
}

#[cfg(feature = "compression-zlib-native")]
fn zlib_compress_engine(input: &[u8]) -> flate2::Compress {
    let mut window_bits = if input.len() <= 0x100 {
        8
    } else if input.len() <= 0x200 {
        9
    } else if input.len() <= 0x400 {
        10
    } else if input.len() <= 0x800 {
        11
    } else if input.len() <= 0x1000 {
        12
    } else if input.len() <= 0x2000 {
        13
    } else if input.len() <= 0x4000 {
        14
    } else {
        15
    };
    if window_bits < 9 {
        window_bits = 9;
    }
    flate2::Compress::new_with_window_bits(flate2::Compression::new(6), true, window_bits)
}

#[cfg(not(feature = "compression-zlib-native"))]
fn zlib_compress_engine(_input: &[u8]) -> flate2::Compress {
    flate2::Compress::new(flate2::Compression::new(6), true)
}

#[cfg(feature = "compression-bzip2")]
fn decompress_bzip2(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = bzip2::read::BzDecoder::new(input);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| StormError::CompressionOwned {
            message: e.to_string(),
        })?;
    Ok(out)
}

#[cfg(not(feature = "compression-bzip2"))]
fn decompress_bzip2(_input: &[u8]) -> Result<Vec<u8>> {
    Err(StormError::UnsupportedFeature(
        "bzip2 support disabled (feature: compression-bzip2)",
    ))
}

#[cfg(feature = "compression-bzip2")]
fn compress_bzip2(input: &[u8]) -> Result<Vec<u8>> {
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    enc.write_all(input)
        .map_err(|e| StormError::CompressionOwned {
            message: e.to_string(),
        })?;
    enc.finish().map_err(|e| StormError::CompressionOwned {
        message: e.to_string(),
    })
}

#[cfg(not(feature = "compression-bzip2"))]
fn compress_bzip2(_input: &[u8]) -> Result<Vec<u8>> {
    Err(StormError::UnsupportedFeature(
        "bzip2 support disabled (feature: compression-bzip2)",
    ))
}

#[cfg(feature = "compression-lzma")]
fn decompress_lzma(input: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(input);
    let mut out = Vec::new();
    lzma_rs::xz_decompress(&mut cursor, &mut out).map_err(|e| StormError::CompressionOwned {
        message: e.to_string(),
    })?;
    Ok(out)
}

#[cfg(not(feature = "compression-lzma"))]
fn decompress_lzma(_input: &[u8]) -> Result<Vec<u8>> {
    Err(StormError::UnsupportedFeature(
        "lzma support disabled (feature: compression-lzma)",
    ))
}

#[cfg(feature = "compression-lzma")]
fn compress_lzma(input: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(input);
    let mut out = Vec::new();
    lzma_rs::xz_compress(&mut cursor, &mut out).map_err(|e| StormError::CompressionOwned {
        message: e.to_string(),
    })?;
    Ok(out)
}

#[cfg(not(feature = "compression-lzma"))]
fn compress_lzma(_input: &[u8]) -> Result<Vec<u8>> {
    Err(StormError::UnsupportedFeature(
        "lzma support disabled (feature: compression-lzma)",
    ))
}

#[cfg(feature = "compression-pkware")]
fn decompress_pkware(input: &[u8]) -> Result<Vec<u8>> {
    pklib::explode_mpq_bytes(input).map_err(|e| StormError::CompressionOwned {
        message: e.to_string(),
    })
}

#[cfg(not(feature = "compression-pkware"))]
fn decompress_pkware(_input: &[u8]) -> Result<Vec<u8>> {
    Err(StormError::UnsupportedFeature(
        "pkware support disabled (feature: compression-pkware)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_roundtrip() {
        let data = b"abc123";
        let c = compress(CompressionMethod::None, data).unwrap();
        let d = decompress(CompressionMethod::None, &c, Some(data.len())).unwrap();
        assert_eq!(d, data);
    }

    #[test]
    fn unsupported_codec_returns_error() {
        let err = decompress(CompressionMethod::Huffman, b"", None).unwrap_err();
        assert!(matches!(
            err,
            StormError::UnsupportedFeature(_) | StormError::Compression(_)
        ));
    }

    #[test]
    fn masked_roundtrip_none_passthrough_is_not_prefixed() {
        let data = b"plain";
        let (out, compressed) = compress_masked_best_effort(CompressionMethod::None, data).unwrap();
        assert!(!compressed);
        assert_eq!(out, data);
    }

    #[test]
    fn mpq_mask_mapping_matches_known_values() {
        assert_eq!(
            CompressionMethod::from_mpq_mask(MPQ_COMPRESSION_ZLIB).unwrap(),
            CompressionMethod::Zlib
        );
        assert_eq!(
            CompressionMethod::Lzma.to_mpq_mask(),
            Some(MPQ_COMPRESSION_LZMA)
        );
    }

    #[cfg(feature = "compression-zlib")]
    #[test]
    fn zlib_roundtrip() {
        let data = b"zlib zlib zlib zlib zlib";
        let c = compress(CompressionMethod::Zlib, data).unwrap();
        let d = decompress(CompressionMethod::Zlib, &c, Some(data.len())).unwrap();
        assert_eq!(d, data);
    }

    #[cfg(feature = "compression-bzip2")]
    #[test]
    fn bzip2_roundtrip() {
        let data = b"bzip2 bzip2 bzip2 bzip2 bzip2";
        let c = compress(CompressionMethod::Bzip2, data).unwrap();
        let d = decompress(CompressionMethod::Bzip2, &c, Some(data.len())).unwrap();
        assert_eq!(d, data);
    }

    #[cfg(feature = "compression-pkware")]
    #[test]
    fn pkware_roundtrip() {
        let data = b"pkware pkware pkware pkware";
        let c = compress(CompressionMethod::PkwareImplode, data).unwrap();
        let d = decompress(CompressionMethod::PkwareImplode, &c, Some(data.len())).unwrap();
        assert_eq!(d, data);
    }

    #[cfg(feature = "compression-lzma")]
    #[test]
    fn lzma_roundtrip() {
        let data = b"lzma lzma lzma lzma lzma";
        let c = compress(CompressionMethod::Lzma, data).unwrap();
        let d = decompress(CompressionMethod::Lzma, &c, Some(data.len())).unwrap();
        assert_eq!(d, data);
    }
}
