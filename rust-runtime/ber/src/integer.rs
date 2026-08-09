//! INTEGER encode/decode — X.680 §18, X.690 §8.3.
//!
//! Mirrors `asn1::detail::encode_integer_bytes` and
//! `BerTraits<Integer>::decode_value` (`runtime/include/asn1cpp/types/Integer.hpp`):
//! minimal two's-complement big-endian value bytes.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const INTEGER_TAG: Tag = Tag::universal(universal::INTEGER, false);

/// Minimal two's-complement big-endian encoding of `n` — the fewest bytes
/// that still round-trip through sign extension.
pub fn encode_integer_bytes(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![0x00];
    }
    let u = n as u64;
    let buf: [u8; 8] = u.to_be_bytes();
    let mut start = 0;
    if n > 0 {
        while start < 7 && buf[start] == 0x00 && (buf[start + 1] & 0x80) == 0 {
            start += 1;
        }
    } else {
        while start < 7 && buf[start] == 0xFF && (buf[start + 1] & 0x80) != 0 {
            start += 1;
        }
    }
    buf[start..].to_vec()
}

/// Decode a minimal two's-complement big-endian value into `i64`.
pub fn decode_integer_bytes(bytes: &[u8]) -> Result<i64, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::new("empty INTEGER value", 0));
    }
    if bytes.len() > 8 {
        return Err(DecodeError::new("INTEGER value too large for i64", 0));
    }
    let mut v: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        v = (v << 8) | b as i64;
    }
    Ok(v)
}

pub fn write_integer(out: &mut Vec<u8>, n: i64) {
    write_integer_tagged(out, INTEGER_TAG, n);
}

pub fn read_integer(r: &mut Reader) -> Result<i64, DecodeError> {
    read_integer_tagged(r, INTEGER_TAG)
}

/// IMPLICIT tag override — see `boolean::write_boolean_tagged`'s
/// doc for the general rationale (X.690 §8.14). Same minimal two's-complement
/// content bytes, different tag octets.
pub fn write_integer_tagged(out: &mut Vec<u8>, tag: Tag, n: i64) {
    write_primitive(out, tag, &encode_integer_bytes(n));
}

pub fn read_integer_tagged(r: &mut Reader, tag: Tag) -> Result<i64, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(
            format!("expected INTEGER tag, got {:?}", tlv.tag),
            r.pos(),
        ));
    }
    decode_integer_bytes(tlv.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero() {
        assert_eq!(encode_integer_bytes(0), vec![0x00]);
    }

    #[test]
    fn small_positive_needs_no_padding() {
        assert_eq!(encode_integer_bytes(5), vec![0x05]);
    }

    #[test]
    fn positive_needing_leading_zero_to_stay_positive() {
        // 128 = 0x80 alone would read back as -128 — needs a leading 0x00.
        assert_eq!(encode_integer_bytes(128), vec![0x00, 0x80]);
    }

    #[test]
    fn negative_one() {
        assert_eq!(encode_integer_bytes(-1), vec![0xFF]);
    }

    #[test]
    fn negative_needing_leading_ff() {
        // -129 doesn't fit in one byte's negative range (-128..=-1); needs 0xFF 0x7F.
        assert_eq!(encode_integer_bytes(-129), vec![0xFF, 0x7F]);
    }

    #[test]
    fn round_trips_i64_extremes() {
        for n in [0i64, 1, -1, 127, 128, -128, -129, i64::MAX, i64::MIN, 1_000_000] {
            let bytes = encode_integer_bytes(n);
            assert_eq!(decode_integer_bytes(&bytes).unwrap(), n, "n={n}");
        }
    }

    #[test]
    fn full_tlv_round_trip() {
        let mut buf = Vec::new();
        write_integer(&mut buf, 300);
        assert_eq!(buf, vec![0x02, 0x02, 0x01, 0x2C]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_integer(&mut r).unwrap(), 300);
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x04, 0x01, 0x05]; // OCTET STRING tag, not INTEGER
        let mut r = Reader::new(&data);
        assert!(read_integer(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_0 = Tag::context(0, false);
        let mut buf = Vec::new();
        write_integer_tagged(&mut buf, context_0, 5);
        assert_eq!(buf, vec![0x80, 0x01, 0x05]); // context primitive 0, not 0x02 (universal INTEGER)
        let mut r = Reader::new(&buf);
        assert_eq!(read_integer_tagged(&mut r, context_0).unwrap(), 5);
    }
}
