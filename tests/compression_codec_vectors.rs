use stormlib_rs::{compress, decompress, CompressionMethod};

const INPUT: &[u8] = include_bytes!("../fixtures/parity/codec/input.bin");
const HUFFMAN: &[u8] = include_bytes!("../fixtures/parity/codec/huffman.bin");
const ADPCM_MONO: &[u8] = include_bytes!("../fixtures/parity/codec/adpcm_mono.bin");
const ADPCM_STEREO: &[u8] = include_bytes!("../fixtures/parity/codec/adpcm_stereo.bin");
const ADPCM_MONO_DECODED: &[u8] = include_bytes!("../fixtures/parity/codec/adpcm_mono_decoded.bin");
const ADPCM_STEREO_DECODED: &[u8] =
    include_bytes!("../fixtures/parity/codec/adpcm_stereo_decoded.bin");
const SPARSE: &[u8] = include_bytes!("../fixtures/parity/codec/sparse.bin");
#[cfg(feature = "compression-pkware")]
const PKWARE_DECODED: &[u8] = include_bytes!("../fixtures/parity/codec/pkware_decoded.bin");

#[test]
fn huffman_vectors_match() {
    let encoded = compress(CompressionMethod::Huffman, INPUT).expect("compress");
    assert_eq!(encoded, HUFFMAN);
    let decoded =
        decompress(CompressionMethod::Huffman, HUFFMAN, Some(INPUT.len())).expect("decompress");
    assert_eq!(decoded, INPUT);
}

#[test]
fn adpcm_mono_vectors_match() {
    let encoded = compress(CompressionMethod::AdpcmMono, INPUT).expect("compress");
    assert_eq!(encoded, ADPCM_MONO);
    let decoded = decompress(CompressionMethod::AdpcmMono, ADPCM_MONO, Some(INPUT.len()))
        .expect("decompress");
    assert_eq!(decoded, ADPCM_MONO_DECODED);
}

#[test]
fn adpcm_stereo_vectors_match() {
    let encoded = compress(CompressionMethod::AdpcmStereo, INPUT).expect("compress");
    assert_eq!(encoded, ADPCM_STEREO);
    let decoded = decompress(
        CompressionMethod::AdpcmStereo,
        ADPCM_STEREO,
        Some(INPUT.len()),
    )
    .expect("decompress");
    assert_eq!(decoded, ADPCM_STEREO_DECODED);
}

#[test]
fn sparse_vectors_match() {
    let encoded = compress(CompressionMethod::Sparse, INPUT).expect("compress");
    assert_eq!(encoded, SPARSE);
    let decoded =
        decompress(CompressionMethod::Sparse, SPARSE, Some(INPUT.len())).expect("decompress");
    assert_eq!(decoded, INPUT);
}

#[cfg(feature = "compression-pkware")]
#[test]
fn pkware_vectors_match() {
    const PKWARE: &[u8] = include_bytes!("../fixtures/parity/codec/pkware.bin");
    let encoded = compress(CompressionMethod::PkwareImplode, INPUT).expect("compress");
    assert_eq!(encoded, PKWARE);
    let decoded = decompress(
        CompressionMethod::PkwareImplode,
        PKWARE,
        Some(PKWARE_DECODED.len()),
    )
    .expect("decompress");
    assert_eq!(decoded, PKWARE_DECODED);
}
