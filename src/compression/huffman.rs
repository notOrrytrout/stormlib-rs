//! MPQ Huffman compression/decompression (MPQ_COMPRESSION_HUFFMANN / 0x01).
//!
//! This is a Rust reimplementation intended to produce **byte-identical** Huffman
//! streams to StormLib for the same inputs.
//!
//! Reference implementation (kept in this workspace for auditability):
//! - `StormLib-master/src/huffman/huff.cpp`
//! - `StormLib-master/src/huffman/huff.h`
//! - Call site / parameter behavior: `StormLib-master/src/SCompression.cpp` (`Compress_huff`).
//!
//! Notes:
//! - Bit packing is LSB-first (see StormLib's `TOutputStream::PutBits`).
//! - The Huffman stream begins with a single byte "CompressionType".
//!   For plain Huffman in MPQ sectors, StormLib typically uses `nCmpType = 0`.

use crate::compression::huffman_tables;
use crate::error::{Result, StormError};

const HUFF_ITEM_COUNT: usize = 0x203;
const LINK_ITEM_COUNT: usize = 0x80;
const HUFF_DECOMPRESS_ERROR: u32 = 0x1FF;

#[derive(Clone, Copy, Debug, Default)]
struct InputStream<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buffer: u32,
    bit_count: u32,
}

impl<'a> InputStream<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buffer: 0,
            bit_count: 0,
        }
    }

    fn get1bit(&mut self) -> Option<u32> {
        if self.bit_count == 0 {
            if self.pos >= self.data.len() {
                return None;
            }
            self.bit_buffer = self.data[self.pos] as u32;
            self.pos += 1;
            self.bit_count = 8;
        }
        let bit = self.bit_buffer & 0x01;
        self.bit_buffer >>= 1;
        self.bit_count -= 1;
        Some(bit)
    }

    fn get8bits(&mut self) -> Option<u32> {
        if self.bit_count < 8 {
            if self.pos >= self.data.len() {
                return None;
            }
            let reload = self.data[self.pos] as u32;
            self.pos += 1;
            self.bit_buffer |= reload << self.bit_count;
            self.bit_count += 8;
        }
        let out = self.bit_buffer & 0xFF;
        self.bit_buffer >>= 8;
        self.bit_count -= 8;
        Some(out)
    }

    /// Returns 7 bits without consuming them from the bit buffer.
    ///
    /// Matches StormLib behavior: may pull one more input byte into the bit buffer.
    fn peek7bits(&mut self) -> Option<u32> {
        if self.bit_count < 7 {
            if self.pos >= self.data.len() {
                return None;
            }
            let reload = self.data[self.pos] as u32;
            self.pos += 1;
            self.bit_buffer |= reload << self.bit_count;
            self.bit_count += 8;
        }
        Some(self.bit_buffer & 0x7F)
    }

    fn skip_bits(&mut self, bits: u32) {
        if self.bit_count < bits {
            if self.pos >= self.data.len() {
                return;
            }
            let reload = self.data[self.pos] as u32;
            self.pos += 1;
            self.bit_buffer |= reload << self.bit_count;
            self.bit_count += 8;
        }
        self.bit_buffer >>= bits;
        self.bit_count -= bits;
    }
}

#[derive(Clone, Debug, Default)]
struct OutputStream {
    out: Vec<u8>,
    bit_buffer: u32,
    bit_count: u32,
}

impl OutputStream {
    fn new(capacity_hint: usize) -> Self {
        Self {
            out: Vec::with_capacity(capacity_hint),
            bit_buffer: 0,
            bit_count: 0,
        }
    }

    fn put_bits(&mut self, value: u32, bit_count: u32) {
        self.bit_buffer |= value << self.bit_count;
        self.bit_count += bit_count;

        while self.bit_count >= 8 {
            self.out.push((self.bit_buffer & 0xFF) as u8);
            self.bit_buffer >>= 8;
            self.bit_count -= 8;
        }
    }

    fn flush(&mut self) {
        while self.bit_count != 0 {
            self.out.push((self.bit_buffer & 0xFF) as u8);
            self.bit_buffer >>= 8;
            if self.bit_count > 8 {
                self.bit_count -= 8;
            } else {
                self.bit_count = 0;
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum InsertPoint {
    After,
    Before,
}

#[derive(Clone, Copy, Debug, Default)]
struct TreeItem {
    next: usize,
    prev: usize,
    decompressed_value: u32,
    weight: u32,
    parent: Option<usize>,
    child_lo: Option<usize>,
    linked: bool,
}

#[derive(Clone, Copy, Debug)]
enum QuickTarget {
    Item(usize),
    Value(u32),
}

impl Default for QuickTarget {
    fn default() -> Self {
        QuickTarget::Value(0)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct QuickLink {
    valid_value: u32,
    valid_bits: u32,
    target: QuickTarget,
}

#[derive(Debug)]
struct HuffmanTree {
    items: Vec<TreeItem>,
    items_used: usize,
    items_by_byte: [Option<usize>; 0x102],
    quick_links: [QuickLink; LINK_ITEM_COUNT],
    min_valid_value: u32,
    is_cmp0: bool,
}

impl HuffmanTree {
    fn new(for_compression: bool) -> Self {
        let mut quick_links = [QuickLink::default(); LINK_ITEM_COUNT];
        if for_compression {
            // Quick links not used during compression.
        } else {
            // StormLib zeroes these; default already does.
            for q in quick_links.iter_mut() {
                q.valid_value = 0;
                q.valid_bits = 0;
                q.target = QuickTarget::Value(0);
            }
        }

        Self {
            items: vec![TreeItem::default(); HUFF_ITEM_COUNT + 1], // idx 0 is sentinel
            items_used: 0,
            items_by_byte: [None; 0x102],
            quick_links,
            min_valid_value: 1,
            is_cmp0: false,
        }
    }

    fn first(&self) -> usize {
        self.items[0].next
    }

    fn last(&self) -> usize {
        self.items[0].prev
    }

    fn link_two_items(&mut self, item1: usize, item2: usize) {
        // Insert item2 after item1.
        let next = self.items[item1].next;
        self.items[item2].next = next;
        self.items[item2].prev = item1;
        self.items[item2].linked = true;

        self.items[next].prev = item2;
        self.items[item1].next = item2;

        // If list was empty, update sentinel.prev as well.
        if self.items[0].prev == item1 && item1 == 0 {
            self.items[0].prev = item2;
        }
        // If inserting after the last element, update sentinel.prev.
        if next == 0 {
            self.items[0].prev = item2;
        }
    }

    fn insert_before(&mut self, insert_point: usize, new_item: usize) {
        // Insert new_item before insert_point.
        let prev = self.items[insert_point].prev;
        self.items[new_item].next = insert_point;
        self.items[new_item].prev = prev;
        self.items[new_item].linked = true;

        self.items[prev].next = new_item;
        self.items[insert_point].prev = new_item;

        // If inserting before first (i.e. before sentinel.next), update sentinel.next.
        if insert_point == self.items[0].next {
            self.items[0].next = new_item;
        }
        // If insert_point is sentinel (0), then we're inserting at end.
        if insert_point == 0 {
            self.items[0].prev = new_item;
            if self.items[0].next == 0 {
                self.items[0].next = new_item;
            }
        }
    }

    fn remove_item(&mut self, idx: usize) {
        if !self.items[idx].linked {
            return;
        }
        let next = self.items[idx].next;
        let prev = self.items[idx].prev;
        self.items[prev].next = next;
        self.items[next].prev = prev;

        // Fix sentinel pointers if needed
        if self.items[0].next == idx {
            self.items[0].next = next;
        }
        if self.items[0].prev == idx {
            self.items[0].prev = prev;
        }

        self.items[idx].next = 0;
        self.items[idx].prev = 0;
        self.items[idx].linked = false;
    }

    fn insert_item(&mut self, idx: usize, where_: InsertPoint, insert_point: Option<usize>) {
        self.remove_item(idx);
        let ip = insert_point.unwrap_or(0);
        match where_ {
            InsertPoint::After => self.link_two_items(ip, idx),
            InsertPoint::Before => self.insert_before(ip, idx),
        }
    }

    fn create_new_item(
        &mut self,
        decompressed_value: u32,
        weight: u32,
        where_: InsertPoint,
    ) -> Option<usize> {
        if self.items_used >= HUFF_ITEM_COUNT {
            return None;
        }
        self.items_used += 1;
        let idx = self.items_used;
        self.items[idx] = TreeItem {
            decompressed_value,
            weight,
            parent: None,
            child_lo: None,
            ..TreeItem::default()
        };
        self.insert_item(idx, where_, None);
        Some(idx)
    }

    fn find_higher_or_equal_item(&self, mut idx: usize, weight: u32) -> usize {
        while idx != 0 {
            if self.items[idx].weight >= weight {
                return idx;
            }
            idx = self.items[idx].prev;
        }
        0
    }

    fn fixup_item_pos_by_weight(&mut self, new_item: usize, mut max_weight: u32) -> u32 {
        if self.items[new_item].weight < max_weight {
            let higher = self.find_higher_or_equal_item(self.last(), self.items[new_item].weight);
            self.remove_item(new_item);
            self.link_two_items(higher, new_item);
        } else {
            max_weight = self.items[new_item].weight;
        }
        max_weight
    }

    fn build_tree(&mut self, compression_type: u32) -> bool {
        self.items_by_byte = [None; 0x102];
        let mut max_weight = 0u32;

        if (compression_type & 0x0F) > 0x08 {
            return false;
        }
        let table = &huffman_tables::WEIGHT_TABLES[(compression_type & 0x0F) as usize];

        // Build initial list
        for (i, entry) in table.iter().enumerate().take(0x100usize) {
            let w = *entry as u32;
            if w != 0 {
                let idx = match self.create_new_item(i as u32, w, InsertPoint::After) {
                    Some(v) => v,
                    None => return false,
                };
                self.items_by_byte[i] = Some(idx);
                max_weight = self.fixup_item_pos_by_weight(idx, max_weight);
            }
        }

        // Termination entries at end
        if let Some(i100) = self.create_new_item(0x100, 1, InsertPoint::Before) {
            self.items_by_byte[0x100] = Some(i100);
        } else {
            return false;
        }
        if let Some(i101) = self.create_new_item(0x101, 1, InsertPoint::Before) {
            self.items_by_byte[0x101] = Some(i101);
        } else {
            return false;
        }

        // Build the Huffman tree from the lowest weights
        let mut child_lo = self.last();
        while child_lo != 0 {
            let child_hi = self.items[child_lo].prev;
            if child_hi == 0 {
                break;
            }
            let weight_sum = self.items[child_hi].weight + self.items[child_lo].weight;
            let parent = match self.create_new_item(0, weight_sum, InsertPoint::After) {
                Some(v) => v,
                None => return false,
            };
            self.items[child_lo].parent = Some(parent);
            self.items[child_hi].parent = Some(parent);
            self.items[parent].child_lo = Some(child_lo);

            max_weight = self.fixup_item_pos_by_weight(parent, max_weight);
            child_lo = self.items[child_hi].prev;
        }

        self.min_valid_value = 1;
        true
    }

    fn inc_weights_and_rebalance(&mut self, mut item: usize) {
        while item != 0 {
            self.items[item].weight += 1;

            let higher =
                self.find_higher_or_equal_item(self.items[item].prev, self.items[item].weight);
            let child_hi = self.items[higher].next;

            if child_hi != item {
                // Move child_hi to the RIGHT of item
                self.remove_item(child_hi);
                self.link_two_items(item, child_hi);

                // Move item after the higher-weight item
                self.remove_item(item);
                self.link_two_items(higher, item);

                // Rebalance parents
                let parent_of_child_hi = self.items[child_hi].parent;
                if let Some(pch) = parent_of_child_hi {
                    let child_lo = self.items[pch].child_lo;

                    let parent_of_item = self.items[item].parent;
                    if let Some(p) = parent_of_item {
                        if self.items[p].child_lo == Some(item) {
                            self.items[p].child_lo = Some(child_hi);
                        }
                    }

                    if child_lo == Some(child_hi) {
                        self.items[pch].child_lo = Some(item);
                    }

                    // Swap parents (as in StormLib)
                    let p_item = self.items[item].parent;
                    self.items[item].parent = self.items[child_hi].parent;
                    self.items[child_hi].parent = p_item;

                    // Invalidate quick links
                    self.min_valid_value = self.min_valid_value.wrapping_add(1);
                }
            }

            match self.items[item].parent {
                Some(p) => item = p,
                None => break,
            }
        }
    }

    fn insert_new_branch_and_rebalance(&mut self, value1: u32, value2: u32) -> bool {
        let last_item = self.last();
        if last_item == 0 {
            return false;
        }

        let child_hi =
            match self.create_new_item(value1, self.items[last_item].weight, InsertPoint::Before) {
                Some(v) => v,
                None => return false,
            };
        self.items[child_hi].parent = Some(last_item);
        self.items_by_byte[value1 as usize] = Some(child_hi);

        let child_lo = match self.create_new_item(value2, 0, InsertPoint::Before) {
            Some(v) => v,
            None => return false,
        };
        self.items[child_lo].parent = Some(last_item);
        self.items[last_item].child_lo = Some(child_lo);
        self.items_by_byte[value2 as usize] = Some(child_lo);

        self.inc_weights_and_rebalance(child_lo);
        true
    }

    fn encode_one_byte(&self, os: &mut OutputStream, mut item: usize) {
        let mut parent = self.items[item].parent;
        let mut bit_buffer = 0u32;
        let mut bit_count = 0u32;

        while let Some(p) = parent {
            let bit = if self.items[p].child_lo != Some(item) {
                1
            } else {
                0
            };
            bit_buffer = (bit_buffer << 1) | bit;
            bit_count += 1;
            item = p;
            parent = self.items[item].parent;
        }

        os.put_bits(bit_buffer, bit_count);
    }

    fn decode_one_byte(&mut self, is: &mut InputStream<'_>) -> u32 {
        let mut item_link: Option<usize> = None;
        let mut item: usize;
        let mut bit_count: u32 = 0;

        let maybe_idx = is.peek7bits();
        let has_idx = maybe_idx.is_some();
        let item_link_index = maybe_idx.unwrap_or(0) as usize;

        if has_idx {
            let q = self.quick_links[item_link_index];
            if q.valid_value > self.min_valid_value {
                if q.valid_bits <= 7 {
                    is.skip_bits(q.valid_bits);
                    return match q.target {
                        QuickTarget::Value(v) => v,
                        QuickTarget::Item(_) => HUFF_DECOMPRESS_ERROR,
                    };
                }
                item = match q.target {
                    QuickTarget::Item(i) => i,
                    _ => return HUFF_DECOMPRESS_ERROR,
                };
                is.skip_bits(7);
            } else {
                if self.first() == 0 {
                    return HUFF_DECOMPRESS_ERROR;
                }
                item = self.first();
            }
        } else {
            if self.first() == 0 {
                return HUFF_DECOMPRESS_ERROR;
            }
            item = self.first();
        }

        while self.items[item].child_lo.is_some() {
            let bit = match is.get1bit() {
                Some(v) => v,
                None => return HUFF_DECOMPRESS_ERROR,
            };
            let child_lo = self.items[item].child_lo.unwrap();
            item = if bit != 0 {
                // higher-weight child is previous in the list
                self.items[child_lo].prev
            } else {
                child_lo
            };
            bit_count += 1;
            if bit_count == 7 {
                item_link = Some(item);
            }
        }

        // Fill quick-link cache if applicable.
        if has_idx {
            let q = &mut self.quick_links[item_link_index];
            if q.valid_value < self.min_valid_value {
                if bit_count > 7 {
                    q.valid_value = self.min_valid_value;
                    q.valid_bits = bit_count;
                    q.target = QuickTarget::Item(item_link.unwrap_or(item));
                } else {
                    let mut idx = if bit_count != 0 {
                        (item_link_index as u32) & (0xFFFFFFFFu32 >> (32 - bit_count))
                    } else {
                        0
                    };
                    while (idx as usize) < LINK_ITEM_COUNT {
                        let qi = &mut self.quick_links[idx as usize];
                        qi.valid_value = self.min_valid_value;
                        qi.valid_bits = bit_count;
                        qi.target = QuickTarget::Value(self.items[item].decompressed_value);
                        idx += 1u32 << bit_count;
                    }
                }
            }
        }

        self.items[item].decompressed_value
    }

    fn compress_stream(&mut self, input: &[u8], compression_type: u32) -> Option<Vec<u8>> {
        if !self.build_tree(compression_type) {
            return None;
        }
        self.is_cmp0 = compression_type == 0;

        let mut os = OutputStream::new(input.len().saturating_mul(2).saturating_add(32));
        os.put_bits(compression_type, 8);

        for &b in input {
            let idx_opt = self.items_by_byte[b as usize];
            if idx_opt.is_none() {
                // Encode relationship marker 0x101
                let marker = self.items_by_byte[0x101]?;
                self.encode_one_byte(&mut os, marker);

                os.put_bits(b as u32, 8);

                let last_val = self.items[self.last()].decompressed_value;
                if !self.insert_new_branch_and_rebalance(last_val, b as u32) {
                    return None;
                }

                if self.is_cmp0 {
                    self.inc_weights_and_rebalance(self.items_by_byte[b as usize]?);
                    continue;
                }

                self.inc_weights_and_rebalance(self.items_by_byte[b as usize]?);
            } else {
                self.encode_one_byte(&mut os, idx_opt?);
            }

            if self.is_cmp0 {
                self.inc_weights_and_rebalance(self.items_by_byte[b as usize]?);
            }
        }

        // termination mark 0x100
        let term = self.items_by_byte[0x100]?;
        self.encode_one_byte(&mut os, term);

        os.flush();
        Some(os.out)
    }

    fn decompress_stream(&mut self, input: &[u8], expected_len: Option<usize>) -> Option<Vec<u8>> {
        if matches!(expected_len, Some(0)) {
            return Some(Vec::new());
        }
        let mut is = InputStream::new(input);

        let compression_type = is.get8bits()?;
        self.is_cmp0 = compression_type == 0;
        if !self.build_tree(compression_type) {
            return None;
        }

        let mut out = Vec::with_capacity(expected_len.unwrap_or(256));
        loop {
            let mut value = self.decode_one_byte(&mut is);
            if value == 0x100 {
                break;
            }
            if value == HUFF_DECOMPRESS_ERROR {
                return None;
            }

            if value == 0x101 {
                value = is.get8bits()?;
                let last_val = self.items[self.last()].decompressed_value;
                if !self.insert_new_branch_and_rebalance(last_val, value) {
                    return None;
                }
                if !self.is_cmp0 {
                    if let Some(idx) = self.items_by_byte[value as usize] {
                        self.inc_weights_and_rebalance(idx);
                    }
                }
            }

            out.push(value as u8);
            if self.is_cmp0 {
                if let Some(idx) = self.items_by_byte[value as usize] {
                    self.inc_weights_and_rebalance(idx);
                }
            }
            if let Some(expected) = expected_len {
                if out.len() >= expected {
                    break;
                }
            }
        }

        Some(out)
    }
}

/// Compresses a buffer with MPQ Huffman (mask 0x01), producing a StormLib-compatible stream.
/// The returned bytes begin with the one-byte Huffman "CompressionType".
pub fn compress_huffman(input: &[u8], compression_type: u32) -> Result<Vec<u8>> {
    let mut tree = HuffmanTree::new(true);
    tree.compress_stream(input, compression_type)
        .ok_or(StormError::Compression("huffman compression failed"))
}

/// Decompresses a MPQ Huffman stream (mask 0x01, without the MPQ mask byte).
#[allow(dead_code)]
pub fn decompress_huffman(input: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    let out = decompress_huffman_len(input, Some(expected_len))?;
    if out.len() != expected_len {
        return Err(StormError::CompressionOwned {
            message: format!(
                "huffman size mismatch: got {}, expected {}",
                out.len(),
                expected_len
            ),
        });
    }
    Ok(out)
}

/// Decompresses a MPQ Huffman stream, optionally enforcing the expected length.
pub fn decompress_huffman_len(input: &[u8], expected_len: Option<usize>) -> Result<Vec<u8>> {
    let mut tree = HuffmanTree::new(false);
    let out = tree
        .decompress_stream(input, expected_len)
        .ok_or(StormError::Compression("huffman decompression failed"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huffman_roundtrip_small() {
        let data = b"hello hello hello";
        let c = compress_huffman(data, 0).unwrap();
        let d = decompress_huffman(&c, data.len()).unwrap();
        assert_eq!(d, data);
    }
}
