//! INTEGER encode/decode — X.680 §18, X.690 §8.3.
//!
//! Mirrors `asn1::detail::encode_integer_bytes` and
//! `BerTraits<Integer>::decode_value` (`runtime/include/asn1cpp/types/Integer.hpp`):
//! minimal two's-complement big-endian value bytes.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::value::Asn1Value;
use crate::writer::write_primitive;

pub const INTEGER_TAG: Tag = Tag::universal(universal::INTEGER, false);

/// `IntStorageKind::ARBITRARY` storage (`RustBackend::native_int_type`) —
/// an INTEGER whose constrained range exceeds `i128` (unconstrained or very
/// wide, e.g. cryptographic keys). Its own newtype, not a direct
/// `Asn1Value` impl on bare `Vec<u8>` — same coherence reasoning as
/// `octet_string::OctetString`'s own module doc: a second, unrelated
/// `Asn1Value` impl on the same concrete `Vec<u8>` type is impossible
/// (E0119), and this crate's `unusable_alias_names_` registry
/// (`compiler/src/codegen/RustBackend.hpp`) exists specifically because,
/// before this newtype, an ARBITRARY-storage alias's referencing members
/// had no distinct type of their own to identify as unusable.
///
/// BER content is the value's minimal two's-complement bytes verbatim —
/// unlike `i64`/`u64`/`i128`, there's no fixed-width parse/format step:
/// the wire's own minimal-encoding rule (X.690 §8.3.2) already *is* what
/// `Vec<u8>` stores. No XER leg yet (`Asn1Value`'s own default: panics with
/// "XER leg not yet wired for this type") — X.693's decimal-text INTEGER
/// form needs bignum long division on the byte array to convert, real work
/// deliberately left for when a schema actually exercises this path (none
/// does today — confirmed zero real usage, this storage kind is itself
/// already an edge case for very wide unconstrained ranges).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArbitraryInteger(pub Vec<u8>);

impl Asn1Value for ArbitraryInteger {
    fn ber_natural_tag(&self) -> Tag {
        INTEGER_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "INTEGER"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = content.to_vec();
        Ok(())
    }
}

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

/// Minimal two's-complement big-endian encoding of an unsigned `n` — same
/// trimming as `encode_integer_bytes`, but the wire format is *always*
/// signed two's-complement (X.690 §8.3) regardless of the ASN.1-level
/// constraint being non-negative, so a value whose top bit would otherwise
/// be set needs an explicit leading `0x00` padding byte to stay positive
/// (matching `Integer.hpp`'s `encode_integer_bytes`, widened to u64 storage
/// — used for constrained-range INTEGER members whose upper bound exceeds
/// i64::MAX).
pub fn encode_integer_bytes_u64(n: u64) -> Vec<u8> {
    let buf: [u8; 8] = n.to_be_bytes();
    let mut start = 0;
    while start < 7 && buf[start] == 0x00 {
        start += 1;
    }
    if buf[start] & 0x80 != 0 {
        let mut v = Vec::with_capacity(9 - start);
        v.push(0x00);
        v.extend_from_slice(&buf[start..]);
        v
    } else {
        buf[start..].to_vec()
    }
}

/// Decode a minimal two's-complement big-endian value into `u64`. Rejects a
/// negative encoding outright (a real negative value can never be valid for
/// a member whose Rust storage is u64) and tolerates (but doesn't require)
/// one leading `0x00` padding byte.
pub fn decode_integer_bytes_u64(bytes: &[u8]) -> Result<u64, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::new("empty INTEGER value", 0));
    }
    if bytes[0] & 0x80 != 0 {
        return Err(DecodeError::new("negative INTEGER value cannot decode into u64", 0));
    }
    let content = if bytes.len() > 1 && bytes[0] == 0x00 { &bytes[1..] } else { bytes };
    if content.len() > 8 {
        return Err(DecodeError::new("INTEGER value too large for u64", 0));
    }
    let mut v: u64 = 0;
    for &b in content {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

pub fn write_integer_u64(out: &mut Vec<u8>, n: u64) {
    write_integer_u64_tagged(out, INTEGER_TAG, n);
}

pub fn read_integer_u64(r: &mut Reader) -> Result<u64, DecodeError> {
    read_integer_u64_tagged(r, INTEGER_TAG)
}

pub fn write_integer_u64_tagged(out: &mut Vec<u8>, tag: Tag, n: u64) {
    write_primitive(out, tag, &encode_integer_bytes_u64(n));
}

pub fn read_integer_u64_tagged(r: &mut Reader, tag: Tag) -> Result<u64, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected INTEGER tag, got {:?}", tlv.tag), r.pos()));
    }
    decode_integer_bytes_u64(tlv.value)
}

/// `i128` analogue of `encode_integer_bytes`/`decode_integer_bytes` — same
/// minimal two's-complement logic, 16-byte buffer instead of 8. Used for
/// constrained-range INTEGER members whose range exceeds i64 (and doesn't
/// fit u64 either, e.g. a signed range with a very large negative bound).
pub fn encode_integer_bytes_i128(n: i128) -> Vec<u8> {
    if n == 0 {
        return vec![0x00];
    }
    let u = n as u128;
    let buf: [u8; 16] = u.to_be_bytes();
    let mut start = 0;
    if n > 0 {
        while start < 15 && buf[start] == 0x00 && (buf[start + 1] & 0x80) == 0 {
            start += 1;
        }
    } else {
        while start < 15 && buf[start] == 0xFF && (buf[start + 1] & 0x80) != 0 {
            start += 1;
        }
    }
    buf[start..].to_vec()
}

pub fn decode_integer_bytes_i128(bytes: &[u8]) -> Result<i128, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::new("empty INTEGER value", 0));
    }
    if bytes.len() > 16 {
        return Err(DecodeError::new("INTEGER value too large for i128", 0));
    }
    let mut v: i128 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        v = (v << 8) | b as i128;
    }
    Ok(v)
}

pub fn write_integer_i128(out: &mut Vec<u8>, n: i128) {
    write_integer_i128_tagged(out, INTEGER_TAG, n);
}

pub fn read_integer_i128(r: &mut Reader) -> Result<i128, DecodeError> {
    read_integer_i128_tagged(r, INTEGER_TAG)
}

pub fn write_integer_i128_tagged(out: &mut Vec<u8>, tag: Tag, n: i128) {
    write_primitive(out, tag, &encode_integer_bytes_i128(n));
}

pub fn read_integer_i128_tagged(r: &mut Reader, tag: Tag) -> Result<i128, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected INTEGER tag, got {:?}", tlv.tag), r.pos()));
    }
    decode_integer_bytes_i128(tlv.value)
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

    // ---- u64 -----------------------------------------------------------

    #[test]
    fn u64_zero() {
        assert_eq!(encode_integer_bytes_u64(0), vec![0x00]);
    }

    #[test]
    fn u64_needs_leading_zero_to_stay_non_negative() {
        // 0x80 alone would read back as -128 under two's complement.
        assert_eq!(encode_integer_bytes_u64(0x80), vec![0x00, 0x80]);
    }

    #[test]
    fn u64_round_trips_extremes() {
        for n in [0u64, 1, 127, 128, i64::MAX as u64, u64::MAX, 1_000_000] {
            let bytes = encode_integer_bytes_u64(n);
            assert_eq!(decode_integer_bytes_u64(&bytes).unwrap(), n, "n={n}");
        }
    }

    #[test]
    fn u64_rejects_negative_encoding() {
        let data = [0xFF]; // top bit set, no padding — would be -1 as signed
        assert!(decode_integer_bytes_u64(&data).is_err());
    }

    #[test]
    fn u64_full_tlv_round_trip() {
        let mut buf = Vec::new();
        write_integer_u64(&mut buf, u64::MAX);
        let mut r = Reader::new(&buf);
        assert_eq!(read_integer_u64(&mut r).unwrap(), u64::MAX);
    }

    // ---- i128 ------------------------------------------------------------

    #[test]
    fn i128_round_trips_extremes() {
        for n in [0i128, 1, -1, 127, 128, -128, -129, i64::MAX as i128, i64::MIN as i128,
                  i128::MAX, i128::MIN] {
            let bytes = encode_integer_bytes_i128(n);
            assert_eq!(decode_integer_bytes_i128(&bytes).unwrap(), n, "n={n}");
        }
    }

    #[test]
    fn i128_full_tlv_round_trip() {
        let mut buf = Vec::new();
        write_integer_i128(&mut buf, i128::MIN);
        let mut r = Reader::new(&buf);
        assert_eq!(read_integer_i128(&mut r).unwrap(), i128::MIN);
    }
}
