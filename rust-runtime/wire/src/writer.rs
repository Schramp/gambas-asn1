//! BER output — appends TLVs to an in-memory buffer.
//!
//! Unlike `BerWriter` (`runtime/include/asn1cpp/codec/BerWriter.hpp`), which
//! back-fills a constructed TLV's length in place to avoid an extra
//! allocation, this simply builds each nested TLV's content into its own
//! `Vec<u8>` first. Simpler, and the extra allocation doesn't matter for a
//! from-scratch codec that hasn't been performance-tuned yet.

use crate::tag::{write_tag, Tag};

/// Encode and append the length octets for `len` bytes — short form
/// (`len < 128`) or long form (base-256, MSB set on the length-of-length byte).
/// Mirrors `BerWriter::write_length`.
///
/// @see X.690 §8.1.3 — Length octets.
pub fn write_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let mut tmp = [0u8; 8];
        let mut i = 0;
        let mut n = len;
        while n != 0 {
            tmp[i] = (n & 0xFF) as u8;
            i += 1;
            n >>= 8;
        }
        out.push(0x80 | i as u8);
        for j in (0..i).rev() {
            out.push(tmp[j]);
        }
    }
}

/// Write a primitive TLV: tag + length + `value` verbatim.
pub fn write_primitive(out: &mut Vec<u8>, t: Tag, value: &[u8]) {
    write_tag(out, t);
    write_length(out, value.len());
    out.extend_from_slice(value);
}

/// Write a constructed TLV: tag + length + already-encoded `content`
/// (the caller builds `content` by writing its child TLVs into a separate
/// `Vec<u8>` first — see module docs for why this differs from the C++
/// in-place backfill).
pub fn write_constructed(out: &mut Vec<u8>, t: Tag, content: &[u8]) {
    write_tag(out, t);
    write_length(out, content.len());
    out.extend_from_slice(content);
}

/// EXPLICIT tagging (X.690 §8.14.3) — a constructed outer
/// TLV (the declared `[n]` tag, always constructed regardless of the inner
/// type) wrapping the inner value's complete natural-tag encoding
/// unchanged. Distinct from IMPLICIT (`*_tagged` primitives in
/// `boolean.rs`/`integer.rs`/`octet_string.rs`/`strings.rs`, `encode_seq_of_tagged`
/// in `sequence.rs`), which *replaces* the natural tag rather than wrapping
/// it — generic over the inner type since EXPLICIT wrapping only cares
/// about the already-encoded bytes, not what produced them (mirrors the
/// C++ runtime's `ber_encode_explicit_tagged`, `BerCodec.cpp`).
pub fn write_explicit(out: &mut Vec<u8>, tag: Tag, inner_encode: impl FnOnce(&mut Vec<u8>)) {
    let mut content = Vec::new();
    inner_encode(&mut content);
    write_constructed(out, tag, &content);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag::universal;

    #[test]
    fn short_form_length() {
        let mut buf = Vec::new();
        write_length(&mut buf, 2);
        assert_eq!(buf, vec![0x02]);
    }

    #[test]
    fn long_form_length_two_bytes() {
        // 300 = 0x012C -> long form, 2 length-of-length bytes: 0x82 0x01 0x2C
        let mut buf = Vec::new();
        write_length(&mut buf, 300);
        assert_eq!(buf, vec![0x82, 0x01, 0x2C]);
    }

    #[test]
    fn primitive_tlv() {
        let mut buf = Vec::new();
        write_primitive(&mut buf, Tag::universal(universal::OCTET_STRING, false), &[0x68, 0x69]);
        assert_eq!(buf, vec![0x04, 0x02, 0x68, 0x69]);
    }

    #[test]
    fn constructed_tlv() {
        let mut buf = Vec::new();
        let content = vec![0x02, 0x01, 0x05];
        write_constructed(&mut buf, Tag::universal(universal::SEQUENCE, true), &content);
        assert_eq!(buf, vec![0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn explicit_wraps_the_inner_encoding_in_an_outer_constructed_tlv() {
        let mut buf = Vec::new();
        let context_5 = Tag::context(5, true);
        write_explicit(&mut buf, context_5, |inner| {
            write_primitive(inner, Tag::universal(universal::INTEGER, false), &[0x2A]);
        });
        // [5] EXPLICIT (0xA5), len 3, wrapping INTEGER 42 (0x02 0x01 0x2A) —
        // not a tag substitution: the inner universal INTEGER tag survives.
        assert_eq!(buf, vec![0xA5, 0x03, 0x02, 0x01, 0x2A]);
    }
}
