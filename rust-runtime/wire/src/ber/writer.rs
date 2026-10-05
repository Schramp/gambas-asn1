//! BER output — appends TLVs to an in-memory buffer.
//!
//! `write_tagged` mirrors `BerWriter::write_constructed`
//! (`runtime/include/asn1cpp/codec/BerWriter.hpp`): reserve a 3-byte length
//! placeholder, let the caller write content directly into the shared
//! buffer, then back-fill the real length and shift the content down to
//! close the gap. This is `Asn1Value::ber_encode_tagged`'s (`value.rs`) one
//! call site, so it applies uniformly to every TLV in a tree — leaf and
//! constructed alike — without a separate `Vec<u8>` per node.

use crate::ber::tag::{write_tag, Tag};

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

/// Write a constructed TLV when `content` is already a separate, fully-
/// encoded byte slice — test fixtures building expected wire bytes by
/// hand (`sequence.rs`'s tests), not the production encode path: every
/// real SEQUENCE/SET/SEQUENCE OF/SET OF/CHOICE encoder uses `write_tagged`
/// (in-place reserve-and-backfill) instead, so content never needs its
/// own separate `Vec<u8>` just to be measured and copied in.
pub fn write_constructed(out: &mut Vec<u8>, t: Tag, content: &[u8]) {
    write_tag(out, t);
    write_length(out, content.len());
    out.extend_from_slice(content);
}

/// Write a TLV under `t` whose content length isn't known ahead of time:
/// reserve 3 length-placeholder bytes, call `fill` to write content
/// directly into `out`, then back-fill the real length and shift the
/// content down to close the gap (mirrors `BerWriter::write_constructed`'s
/// memmove-based collapse — same technique, used for every tag here since
/// Rust's single `ber_encode_tagged` funnel handles leaf and constructed
/// TLVs alike, unlike C++'s separate `write_primitive`/`write_constructed`).
pub fn write_tagged(out: &mut Vec<u8>, t: Tag, fill: impl FnOnce(&mut Vec<u8>)) {
    write_tag(out, t);
    let len_pos = out.len();
    out.resize(len_pos + 3, 0);
    let content_start = out.len();

    fill(out);

    let content_size = out.len() - content_start;
    if content_size < 128 {
        out.copy_within(content_start..content_start + content_size, len_pos + 1);
        out.truncate(len_pos + 1 + content_size);
        out[len_pos] = content_size as u8;
    } else if content_size < 256 {
        out.copy_within(content_start..content_start + content_size, len_pos + 2);
        out.truncate(len_pos + 2 + content_size);
        out[len_pos] = 0x81;
        out[len_pos + 1] = content_size as u8;
    } else if content_size < 65536 {
        // 3-byte length fits the pre-reserved gap exactly — no shift.
        out[len_pos] = 0x82;
        out[len_pos + 1] = ((content_size >> 8) & 0xFF) as u8;
        out[len_pos + 2] = (content_size & 0xFF) as u8;
    } else {
        // >65535 bytes (up to 16 MiB): 4-byte length (0x83 + 3 bytes) —
        // extend the reserved gap by inserting one byte before content.
        out.insert(content_start, 0);
        out[len_pos] = 0x83;
        out[len_pos + 1] = ((content_size >> 16) & 0xFF) as u8;
        out[len_pos + 2] = ((content_size >> 8) & 0xFF) as u8;
        out[len_pos + 3] = (content_size & 0xFF) as u8;
    }
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
    write_tagged(out, tag, inner_encode);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::tag::universal;

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
