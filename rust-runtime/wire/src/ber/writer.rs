//! BER output — appends TLVs to an in-memory buffer.
//!
//! `write_tagged` mirrors `BerWriter::write_constructed`
//! (`runtime/include/asn1cpp/codec/BerWriter.hpp`): reserve a 3-byte length
//! placeholder, let the caller write content directly into the shared
//! buffer, then back-fill the real length and shift the content down to
//! close the gap. Every TLV the BER walkers write goes through it, so it
//! applies uniformly to every TLV in a tree — leaf and constructed alike —
//! without a separate `Vec<u8>` per node.

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
/// directly into `out`, then back-fill the real length in its shortest
/// definite form (X.690 §8.1.3.3–§8.1.3.5) and shift the content to fit
/// the length octets (mirrors `BerWriter::write_constructed`'s
/// memmove-based collapse — same technique, used for every tag here since
/// Rust's single `ber_encode_tagged` funnel handles leaf and constructed
/// TLVs alike, unlike C++'s separate `write_primitive`/`write_constructed`).
/// Returns whatever `fill` returns, so a fallible walker
/// (`ber::object`, `Result<(), EncodeError>`) propagates its error through
/// the TLV it was writing; the length is back-filled either way.
pub fn write_tagged<R>(out: &mut Vec<u8>, t: Tag, fill: impl FnOnce(&mut Vec<u8>) -> R) -> R {
    write_tag(out, t);
    let len_pos = out.len();
    out.resize(len_pos + 3, 0);
    let content_start = out.len();

    let result = fill(out);

    debug_assert!(out.len() >= content_start, "write_tagged: fill must only append");
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
        // >65535 bytes: long form 0x80|n followed by n ≥ 3 length octets —
        // insert the n - 2 octets the 3 reserved bytes lack before content.
        let n = (usize::BITS - content_size.leading_zeros()).div_ceil(8) as usize;
        out.splice(content_start..content_start, std::iter::repeat_n(0u8, n - 2));
        out[len_pos] = 0x80 | n as u8;
        for i in 0..n {
            out[len_pos + 1 + i] = (content_size >> (8 * (n - 1 - i))) as u8;
        }
    }
    result
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
pub fn write_explicit<R>(out: &mut Vec<u8>, tag: Tag, inner_encode: impl FnOnce(&mut Vec<u8>) -> R) -> R {
    write_tagged(out, tag, inner_encode)
}

#[cfg(test)]
mod tests {
    /// `write_tagged` back-fills the shortest definite length (X.690
    /// §8.1.3.3–§8.1.3.5) at every length-form boundary, with the content
    /// unchanged after the shift.
    #[test]
    fn write_tagged_length_forms() {
        use super::write_tagged;
        use crate::ber::tag::Tag;
        let cases: [(usize, &[u8]); 9] = [
            (0, &[0x00]), (127, &[0x7F]), (128, &[0x81, 0x80]), (255, &[0x81, 0xFF]),
            (256, &[0x82, 0x01, 0x00]), (65535, &[0x82, 0xFF, 0xFF]),
            (65536, &[0x83, 0x01, 0x00, 0x00]), ((1 << 24) - 1, &[0x83, 0xFF, 0xFF, 0xFF]),
            (1 << 24, &[0x84, 0x01, 0x00, 0x00, 0x00]),
        ];
        for (n, len) in cases {
            let content: Vec<u8> = (0..n).map(|i| (i * 7 + 1) as u8).collect();
            let mut out = Vec::new();
            write_tagged(&mut out, Tag::universal(16, true), |o| o.extend_from_slice(&content));
            assert_eq!(out[0], 0x30, "{n} bytes: tag");
            assert_eq!(&out[1..1 + len.len()], len, "{n} bytes: length octets");
            assert!(out[1 + len.len()..] == content[..], "{n} bytes: content");
        }
    }

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
