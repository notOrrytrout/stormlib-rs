use crate::crypto::md5_digest;
use crate::error::{Result, StormError};
use crate::internal::file_table::lookup_file_name;
use crate::types::MpqArchive;
#[cfg(feature = "compression-bzip2")]
use std::io::Cursor;
#[cfg(feature = "compression-bzip2")]
use std::io::Read;

const PATCH_SIGNATURE_HEADER: u32 = 0x4843_5450; // PTCH
const PATCH_SIGNATURE_MD5: u32 = 0x5F35_444D; // MD5_
const PATCH_SIGNATURE_XFRM: u32 = 0x4D52_4658; // XFRM
const PATCH_TYPE_COPY: u32 = 0x5950_4F43; // COPY
const PATCH_TYPE_BSD0: u32 = 0x3044_5342; // BSD0
const PATCH_HEADER_LEN: usize = 68;
const XFRM_HEADER_LEN: usize = 12;

#[derive(Debug, Clone)]
struct PatchHeader {
    size_of_patch_data: usize,
    size_before_patch: usize,
    size_after_patch: usize,
    md5_before_patch: [u8; 16],
    md5_after_patch: [u8; 16],
    xfrm_block_size: usize,
    patch_type: u32,
}

fn parse_patch_header(payload: &[u8]) -> Result<Option<PatchHeader>> {
    if payload.len() < PATCH_HEADER_LEN {
        return Ok(None);
    }

    let rd = |off: usize| -> Result<u32> {
        let end = off
            .checked_add(4)
            .ok_or(StormError::Bounds("patch header offset overflow"))?;
        let bytes = payload
            .get(off..end)
            .ok_or(StormError::Format("patch header truncated"))?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
            StormError::Format("patch header dword width")
        })?))
    };

    let signature = rd(0)?;
    if signature != PATCH_SIGNATURE_HEADER {
        return Ok(None);
    }

    let size_of_patch_data = rd(4)? as usize;
    let size_before_patch = rd(8)? as usize;
    let size_after_patch = rd(12)? as usize;
    let md5_signature = rd(16)?;
    let md5_block_size = rd(20)? as usize;
    let xfrm_signature = rd(56)?;
    let xfrm_block_size = rd(60)? as usize;
    let patch_type = rd(64)?;

    if md5_signature != PATCH_SIGNATURE_MD5 || xfrm_signature != PATCH_SIGNATURE_XFRM {
        return Err(StormError::Format("invalid patch metadata signatures"));
    }
    if size_of_patch_data < PATCH_HEADER_LEN || size_of_patch_data > payload.len() {
        return Err(StormError::Format("invalid patch size_of_patch_data"));
    }
    if md5_block_size < 8 + 16 + 16 {
        return Err(StormError::Format("invalid patch md5 block size"));
    }
    if xfrm_block_size < XFRM_HEADER_LEN {
        return Err(StormError::Format("invalid patch xfrm block size"));
    }

    let mut md5_before_patch = [0u8; 16];
    let mut md5_after_patch = [0u8; 16];
    md5_before_patch.copy_from_slice(
        payload
            .get(24..40)
            .ok_or(StormError::Format("patch md5_before slice"))?,
    );
    md5_after_patch.copy_from_slice(
        payload
            .get(40..56)
            .ok_or(StormError::Format("patch md5_after slice"))?,
    );

    Ok(Some(PatchHeader {
        size_of_patch_data,
        size_before_patch,
        size_after_patch,
        md5_before_patch,
        md5_after_patch,
        xfrm_block_size,
        patch_type,
    }))
}

fn apply_copy_patch(base: &[u8], header: &PatchHeader) -> Result<Vec<u8>> {
    if base.len() != header.size_before_patch {
        return Err(StormError::Format("patch size_before mismatch"));
    }
    if md5_digest(base) != header.md5_before_patch {
        return Err(StormError::Format("patch md5_before mismatch"));
    }

    let out = base.to_vec();
    if out.len() != header.size_after_patch {
        return Err(StormError::Format("patch size_after mismatch"));
    }
    if md5_digest(&out) != header.md5_after_patch {
        return Err(StormError::Format("patch md5_after mismatch"));
    }
    Ok(out)
}

fn apply_bsd0_patch(base: &[u8], patch_data: &[u8], header: &PatchHeader) -> Result<Vec<u8>> {
    if base.len() != header.size_before_patch {
        return Err(StormError::Format("patch size_before mismatch"));
    }
    if md5_digest(base) != header.md5_before_patch {
        return Err(StormError::Format("patch md5_before mismatch"));
    }

    let out = apply_bsdiff40_patch(base, patch_data, header.size_after_patch)?;

    if out.len() != header.size_after_patch {
        return Err(StormError::Format("patch size_after mismatch"));
    }
    if md5_digest(&out) != header.md5_after_patch {
        return Err(StormError::Format("patch md5_after mismatch"));
    }

    Ok(out)
}

#[cfg(feature = "compression-bzip2")]
fn decode_offt(buf: &[u8]) -> Result<i64> {
    if buf.len() != 8 {
        return Err(StormError::Format("invalid BSDIFF integer width"));
    }
    let mut y: i64 = (buf[7] & 0x7F) as i64;
    for i in (0..7).rev() {
        y = y.saturating_mul(256).saturating_add(buf[i] as i64);
    }
    if (buf[7] & 0x80) != 0 {
        Ok(-y)
    } else {
        Ok(y)
    }
}

#[cfg(feature = "compression-bzip2")]
fn read_bsdiff_i64_le(reader: &mut Cursor<&[u8]>) -> Result<i64> {
    let mut buf = [0u8; 8];
    reader
        .read_exact(&mut buf)
        .map_err(|_| StormError::Format("invalid BSDIFF control block"))?;
    decode_offt(&buf)
}

#[cfg(feature = "compression-bzip2")]
fn apply_bsdiff40_patch(old: &[u8], patch_data: &[u8], new_size: usize) -> Result<Vec<u8>> {
    if patch_data.len() < 32 || &patch_data[0..8] != b"BSDIFF40" {
        return Err(StormError::Format("invalid BSD0 patch payload"));
    }

    let ctrl_len = decode_offt(&patch_data[8..16])?;
    let diff_len = decode_offt(&patch_data[16..24])?;
    let expected_new_size = decode_offt(&patch_data[24..32])?;
    if ctrl_len < 0 || diff_len < 0 || expected_new_size < 0 {
        return Err(StormError::Format("invalid BSDIFF section sizes"));
    }
    if expected_new_size as usize != new_size {
        return Err(StormError::Format("patch size_after mismatch"));
    }

    let ctrl_len = ctrl_len as usize;
    let diff_len = diff_len as usize;
    let ctrl_start = 32usize;
    let diff_start = ctrl_start
        .checked_add(ctrl_len)
        .ok_or(StormError::Bounds("BSDIFF control section overflow"))?;
    let extra_start = diff_start
        .checked_add(diff_len)
        .ok_or(StormError::Bounds("BSDIFF diff section overflow"))?;
    if extra_start > patch_data.len() {
        return Err(StormError::Format("BSDIFF sections exceed patch payload"));
    }

    let mut ctrl_raw = Vec::new();
    bzip2::read::BzDecoder::new(&patch_data[ctrl_start..diff_start])
        .read_to_end(&mut ctrl_raw)
        .map_err(|_| StormError::Format("invalid BSDIFF control stream"))?;
    let mut diff_raw = Vec::new();
    bzip2::read::BzDecoder::new(&patch_data[diff_start..extra_start])
        .read_to_end(&mut diff_raw)
        .map_err(|_| StormError::Format("invalid BSDIFF diff stream"))?;
    let mut extra_raw = Vec::new();
    bzip2::read::BzDecoder::new(&patch_data[extra_start..])
        .read_to_end(&mut extra_raw)
        .map_err(|_| StormError::Format("invalid BSDIFF extra stream"))?;

    let mut new_buf = vec![0u8; new_size];
    let mut old_pos: i64 = 0;
    let mut new_pos: usize = 0;
    let mut diff_pos: usize = 0;
    let mut extra_pos: usize = 0;
    let mut ctrl = Cursor::new(ctrl_raw.as_slice());

    while new_pos < new_size {
        let add_len = read_bsdiff_i64_le(&mut ctrl)?;
        let copy_len = read_bsdiff_i64_le(&mut ctrl)?;
        let seek_old = read_bsdiff_i64_le(&mut ctrl)?;
        if add_len < 0 || copy_len < 0 {
            return Err(StormError::Format("invalid BSDIFF control tuple"));
        }
        let add_len = add_len as usize;
        let copy_len = copy_len as usize;
        if new_pos
            .checked_add(add_len)
            .ok_or(StormError::Bounds("BSDIFF add overflow"))?
            > new_size
        {
            return Err(StormError::Format("BSDIFF add segment exceeds output"));
        }
        if diff_pos
            .checked_add(add_len)
            .ok_or(StormError::Bounds("BSDIFF diff overflow"))?
            > diff_raw.len()
        {
            return Err(StormError::Format("BSDIFF diff segment truncated"));
        }

        for i in 0..add_len {
            let old_idx = old_pos + i as i64;
            let old_byte = if old_idx >= 0 && (old_idx as usize) < old.len() {
                old[old_idx as usize]
            } else {
                0
            };
            new_buf[new_pos + i] = old_byte.wrapping_add(diff_raw[diff_pos + i]);
        }
        new_pos += add_len;
        old_pos += add_len as i64;
        diff_pos += add_len;

        if new_pos
            .checked_add(copy_len)
            .ok_or(StormError::Bounds("BSDIFF copy overflow"))?
            > new_size
        {
            return Err(StormError::Format("BSDIFF extra segment exceeds output"));
        }
        if extra_pos
            .checked_add(copy_len)
            .ok_or(StormError::Bounds("BSDIFF extra overflow"))?
            > extra_raw.len()
        {
            return Err(StormError::Format("BSDIFF extra segment truncated"));
        }
        new_buf[new_pos..new_pos + copy_len]
            .copy_from_slice(&extra_raw[extra_pos..extra_pos + copy_len]);
        new_pos += copy_len;
        extra_pos += copy_len;
        old_pos = old_pos
            .checked_add(seek_old)
            .ok_or(StormError::Bounds("BSDIFF old position overflow"))?;
    }

    Ok(new_buf)
}

#[cfg(not(feature = "compression-bzip2"))]
fn apply_bsdiff40_patch(_old: &[u8], _patch_data: &[u8], _new_size: usize) -> Result<Vec<u8>> {
    Err(StormError::UnsupportedFeature(
        "BSD0 patches require bzip2 support (feature: compression-bzip2)",
    ))
}

fn apply_patch_payload(base: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let Some(header) = parse_patch_header(payload)? else {
        return Ok(payload.to_vec());
    };

    let patch_data_len = header
        .xfrm_block_size
        .checked_sub(XFRM_HEADER_LEN)
        .ok_or(StormError::Bounds("patch xfrm header underflow"))?;
    let expected_data_len = header
        .size_of_patch_data
        .checked_sub(PATCH_HEADER_LEN)
        .ok_or(StormError::Bounds("patch data length underflow"))?;
    if patch_data_len > expected_data_len {
        return Err(StormError::Format("patch xfrm block exceeds patch data"));
    }

    let patch_data_start = PATCH_HEADER_LEN;
    let patch_data_end = patch_data_start
        .checked_add(patch_data_len)
        .ok_or(StormError::Bounds("patch data slice overflow"))?;
    let patch_data = payload
        .get(patch_data_start..patch_data_end)
        .ok_or(StormError::Format("patch payload truncated"))?;

    match header.patch_type {
        PATCH_TYPE_COPY => apply_copy_patch(base, &header),
        PATCH_TYPE_BSD0 => apply_bsd0_patch(base, patch_data, &header),
        _ => Err(StormError::Format("unsupported patch type")),
    }
}

impl MpqArchive {
    pub(crate) fn read_file_with_patch_chain(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        let mut current =
            lookup_file_name(&self.tables.hash_table, self.tables.block_table.len(), name)
                .map(|m| self.read_file_by_block_index(m.block_index, Some(name)))
                .transpose()?;

        for patch_entry in self.patch_chain.clone() {
            let mut patch = MpqArchive::open(&patch_entry.path)?;
            let mut candidates = Vec::with_capacity(4);
            if let Some(prefix) = patch_entry.prefix.as_deref().filter(|s| !s.is_empty()) {
                let normalized_name = name.replace('/', "\\");
                candidates.push(format!("{prefix}{normalized_name}"));
                candidates.push(format!("{prefix}{name}"));
            }
            candidates.push(name.to_string());
            candidates.push(name.replace('/', "\\"));

            let candidate = candidates
                .iter()
                .find(|candidate| patch.has_file(candidate))
                .cloned();
            let Some(candidate) = candidate else {
                continue;
            };

            let payload = patch.read_file(&candidate)?;
            current = Some(match current {
                Some(ref base) => apply_patch_payload(base, &payload)?,
                None => payload,
            });
        }

        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PATCH_HEADER_LEN, PATCH_SIGNATURE_HEADER, PATCH_SIGNATURE_MD5, PATCH_SIGNATURE_XFRM,
        PATCH_TYPE_COPY, XFRM_HEADER_LEN,
    };
    use crate::error::StormError;
    use crate::types::{AddFileOptions, CreateOptions, MpqArchive};
    use std::io::Write;

    fn encode_offt(value: i64) -> [u8; 8] {
        let mut y = if value < 0 {
            (-value) as u64
        } else {
            value as u64
        };
        let mut out = [0u8; 8];
        for byte in out.iter_mut().take(7) {
            *byte = (y & 0xFF) as u8;
            y >>= 8;
        }
        out[7] = (y & 0x7F) as u8;
        if value < 0 {
            out[7] |= 0x80;
        }
        out
    }

    fn compress_bzip2(payload: &[u8]) -> Vec<u8> {
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    fn build_copy_patch_payload(base: &[u8], md5_before: [u8; 16]) -> Vec<u8> {
        let md5_after = crate::crypto::md5_digest(base);
        let mut out = Vec::new();
        out.extend_from_slice(&PATCH_SIGNATURE_HEADER.to_le_bytes());
        out.extend_from_slice(&(PATCH_HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&(base.len() as u32).to_le_bytes());
        out.extend_from_slice(&(base.len() as u32).to_le_bytes());
        out.extend_from_slice(&PATCH_SIGNATURE_MD5.to_le_bytes());
        out.extend_from_slice(&(40u32).to_le_bytes());
        out.extend_from_slice(&md5_before);
        out.extend_from_slice(&md5_after);
        out.extend_from_slice(&PATCH_SIGNATURE_XFRM.to_le_bytes());
        out.extend_from_slice(&(XFRM_HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&PATCH_TYPE_COPY.to_le_bytes());
        out
    }

    fn build_bsd0_patch_payload(base: &[u8], target: &[u8], md5_before: [u8; 16]) -> Vec<u8> {
        let md5_after = crate::crypto::md5_digest(target);
        let mut ctrl_raw = Vec::new();
        ctrl_raw.extend_from_slice(&encode_offt(0));
        ctrl_raw.extend_from_slice(&encode_offt(target.len() as i64));
        ctrl_raw.extend_from_slice(&encode_offt(0));
        let diff_raw: [u8; 0] = [];
        let extra_raw = target;

        let ctrl_bz2 = compress_bzip2(&ctrl_raw);
        let diff_bz2 = compress_bzip2(&diff_raw);
        let extra_bz2 = compress_bzip2(extra_raw);

        let mut bsdiff_bytes = Vec::new();
        bsdiff_bytes.extend_from_slice(b"BSDIFF40");
        bsdiff_bytes.extend_from_slice(&encode_offt(ctrl_bz2.len() as i64));
        bsdiff_bytes.extend_from_slice(&encode_offt(diff_bz2.len() as i64));
        bsdiff_bytes.extend_from_slice(&encode_offt(target.len() as i64));
        bsdiff_bytes.extend_from_slice(&ctrl_bz2);
        bsdiff_bytes.extend_from_slice(&diff_bz2);
        bsdiff_bytes.extend_from_slice(&extra_bz2);

        let xfrm_block_size = XFRM_HEADER_LEN + bsdiff_bytes.len();
        let size_of_patch_data = PATCH_HEADER_LEN + bsdiff_bytes.len();

        let mut out = Vec::new();
        out.extend_from_slice(&PATCH_SIGNATURE_HEADER.to_le_bytes());
        out.extend_from_slice(&(size_of_patch_data as u32).to_le_bytes());
        out.extend_from_slice(&(base.len() as u32).to_le_bytes());
        out.extend_from_slice(&(target.len() as u32).to_le_bytes());
        out.extend_from_slice(&PATCH_SIGNATURE_MD5.to_le_bytes());
        out.extend_from_slice(&(40u32).to_le_bytes());
        out.extend_from_slice(&md5_before);
        out.extend_from_slice(&md5_after);
        out.extend_from_slice(&PATCH_SIGNATURE_XFRM.to_le_bytes());
        out.extend_from_slice(&(xfrm_block_size as u32).to_le_bytes());
        out.extend_from_slice(&super::PATCH_TYPE_BSD0.to_le_bytes());
        out.extend_from_slice(&bsdiff_bytes);
        out
    }

    #[test]
    fn copy_patch_payload_roundtrips_base_content() {
        let base = b"hello-patch";
        let payload = build_copy_patch_payload(base, crate::crypto::md5_digest(base));
        let out = super::apply_patch_payload(base, &payload).unwrap();
        assert_eq!(out, base);
    }

    #[test]
    fn patch_chain_read_executes_copy_patch_payload() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.mpq");
        let patch_path = dir.path().join("patch.mpq");
        let original = b"hello-patch".to_vec();

        {
            let mut base = MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
            base.add_file_from_bytes("foo.txt", &original, AddFileOptions::default())
                .unwrap();
        }

        let payload = build_copy_patch_payload(&original, crate::crypto::md5_digest(&original));
        {
            let mut patch = MpqArchive::create(&patch_path, CreateOptions::default()).unwrap();
            patch
                .add_file_from_bytes("foo.txt", &payload, AddFileOptions::default())
                .unwrap();
        }

        let mut base = MpqArchive::open(&base_path).unwrap();
        base.open_patch_archive(&patch_path, None).unwrap();
        let out = base.read_file("foo.txt").unwrap();
        assert_eq!(out, original);
    }

    #[test]
    fn patch_chain_prefixed_lookup_falls_back_to_plain_name() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.mpq");
        let patch_path = dir.path().join("patch.mpq");
        let original = b"hello-patch".to_vec();

        {
            let mut base = MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
            base.add_file_from_bytes("foo.txt", &original, AddFileOptions::default())
                .unwrap();
        }

        let payload = build_copy_patch_payload(&original, crate::crypto::md5_digest(&original));
        {
            let mut patch = MpqArchive::create(&patch_path, CreateOptions::default()).unwrap();
            patch
                .add_file_from_bytes("foo.txt", &payload, AddFileOptions::default())
                .unwrap();
        }

        let mut base = MpqArchive::open(&base_path).unwrap();
        base.open_patch_archive(&patch_path, Some("base")).unwrap();
        let out = base.read_file("foo.txt").unwrap();
        assert_eq!(out, original);
    }

    #[test]
    fn patch_chain_prefixed_lookup_supports_slash_separator() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.mpq");
        let patch_path = dir.path().join("patch.mpq");
        let original = b"hello-patch".to_vec();

        {
            let mut base = MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
            base.add_file_from_bytes("foo.txt", &original, AddFileOptions::default())
                .unwrap();
        }

        let payload = build_copy_patch_payload(&original, crate::crypto::md5_digest(&original));
        {
            let mut patch = MpqArchive::create(&patch_path, CreateOptions::default()).unwrap();
            patch
                .add_file_from_bytes("base/foo.txt", &payload, AddFileOptions::default())
                .unwrap();
        }

        let mut base = MpqArchive::open(&base_path).unwrap();
        base.open_patch_archive(&patch_path, Some("base")).unwrap();
        let out = base.read_file("foo.txt").unwrap();
        assert_eq!(out, original);
    }

    #[test]
    fn patch_chain_prefixed_lookup_uses_normalized_backslash_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.mpq");
        let patch_path = dir.path().join("patch.mpq");
        let original = b"hello-patch".to_vec();

        {
            let mut base = MpqArchive::create(&base_path, CreateOptions::default()).unwrap();
            base.add_file_from_bytes("foo.txt", &original, AddFileOptions::default())
                .unwrap();
        }

        let payload = build_copy_patch_payload(&original, crate::crypto::md5_digest(&original));
        {
            let mut patch = MpqArchive::create(&patch_path, CreateOptions::default()).unwrap();
            patch
                .add_file_from_bytes("base\\foo.txt", &payload, AddFileOptions::default())
                .unwrap();
        }

        let mut base = MpqArchive::open(&base_path).unwrap();
        base.open_patch_archive(&patch_path, Some("base/")).unwrap();
        let out = base.read_file("foo.txt").unwrap();
        assert_eq!(out, original);
    }

    #[test]
    fn copy_patch_rejects_md5_before_mismatch() {
        let base = b"hello-patch";
        let payload = build_copy_patch_payload(base, [0u8; 16]);
        let err = super::apply_patch_payload(base, &payload).unwrap_err();
        assert!(matches!(
            err,
            StormError::Format("patch md5_before mismatch")
        ));
    }

    #[test]
    fn bsd0_patch_payload_transforms_base_content() {
        let base = b"hello-patch";
        let target = b"hello-bsd0-patch";
        let payload = build_bsd0_patch_payload(base, target, crate::crypto::md5_digest(base));
        let out = super::apply_patch_payload(base, &payload).unwrap();
        assert_eq!(out, target);
    }

    #[test]
    fn bsd0_patch_rejects_invalid_patch_payload() {
        let base = b"hello-patch";
        let target = b"hello-bsd0-patch";
        let mut payload = build_bsd0_patch_payload(base, target, crate::crypto::md5_digest(base));
        payload.truncate(PATCH_HEADER_LEN);
        let err = super::apply_patch_payload(base, &payload).unwrap_err();
        assert!(matches!(err, StormError::Format(_)));
    }
}
