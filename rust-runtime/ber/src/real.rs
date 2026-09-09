//! REAL encode/decode — X.680 §21, X.690 §8.5.
//!
//! Mirrors `asn1::Real`/`BerTraits<Real>`
//! (`runtime/include/asn1cpp/types/Real.hpp`): IEEE 754 double-precision,
//! encoded per X.690 §8.5.7's binary form (base-2, minimal mantissa
//! bytes) — special values `+INF`/`-INF`/`NaN` per X.690 §8.5.9, zero as
//! an empty value (X.690 §8.5.3). Decimal form (X.690 §8.5.8) is not
//! implemented, matching `asn1::Real`'s own limitation.
//!
//! `native_builtin_type` already mapped REAL to plain `f64` before this
//! issue — no collision to route around (unlike BIT STRING/OID/RELATIVE-OID,
//! `f64` had no prior `Asn1Value` impl claiming it).

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const REAL_TAG: Tag = Tag::universal(universal::REAL, false);

pub fn write_real(out: &mut Vec<u8>, value: f64) {
    write_real_tagged(out, REAL_TAG, value);
}

pub fn read_real(r: &mut Reader) -> Result<f64, DecodeError> {
    read_real_tagged(r, REAL_TAG)
}

/// Content octets only (X.690 §8.5) — empty for zero, one info byte for the
/// special values, info+exponent+mantissa for everything else.
pub(crate) fn encode_real_content(out: &mut Vec<u8>, value: f64) {
    if value == 0.0 {
        return;
    }
    if value.is_infinite() {
        out.push(if value > 0.0 { 0x40 } else { 0x41 });
        return;
    }
    if value.is_nan() {
        out.push(0x42);
        return;
    }

    // Extract mantissa/exponent directly from IEEE 754 bits, same as
    // asn1::Real's own std::memcpy-based extraction.
    let bits = value.to_bits();
    let mut info: u8 = 0x80; // binary encoding, base-2, scaling-factor 0
    if bits >> 63 != 0 {
        info |= 0x40; // negative
    }

    let mut e: i32 = (((bits >> 52) & 0x7FF) as i32) - 1023 - 52;
    let mut m: u64 = (bits & 0x000F_FFFF_FFFF_FFFF) | (1u64 << 52); // implicit leading 1

    // Remove trailing zero bits for minimal encoding.
    while m != 0 && (m & 1) == 0 {
        m >>= 1;
        e += 1;
    }

    // Mantissa bytes, big-endian, minimal.
    let mut mbuf = [0u8; 8];
    let mut mlen = 0usize;
    let mut tmp = m;
    while tmp != 0 {
        mbuf[mlen] = (tmp & 0xFF) as u8;
        mlen += 1;
        tmp >>= 8;
    }
    mbuf[..mlen].reverse();

    // Exponent bytes, signed big-endian, minimal (two's-complement trim).
    let eu = e as u32;
    let ebuf_full = [((eu >> 16) & 0xFF) as u8, ((eu >> 8) & 0xFF) as u8, (eu & 0xFF) as u8];
    let mut start = 0usize;
    let sign_byte: u8 = if e < 0 { 0xFF } else { 0x00 };
    let sign_bit: u8 = if e < 0 { 0x80 } else { 0x00 };
    while start < 2 && ebuf_full[start] == sign_byte && (ebuf_full[start + 1] & 0x80) == sign_bit {
        start += 1;
    }
    let elen = 3 - start;
    info |= ((elen - 1) & 0x03) as u8;

    out.push(info);
    out.extend_from_slice(&ebuf_full[start..start + elen]);
    out.extend_from_slice(&mbuf[..mlen]);
}

pub fn write_real_tagged(out: &mut Vec<u8>, tag: Tag, value: f64) {
    let mut content = Vec::new();
    encode_real_content(&mut content, value);
    write_primitive(out, tag, &content);
}

pub fn read_real_tagged(r: &mut Reader, tag: Tag) -> Result<f64, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected REAL tag, got {:?}", tlv.tag), r.pos()));
    }
    decode_real_value(tlv.value, r.pos())
}

pub(crate) fn decode_real_value(value: &[u8], pos: usize) -> Result<f64, DecodeError> {
    if value.is_empty() {
        return Ok(0.0);
    }
    let info = value[0];
    if info == 0x40 {
        return Ok(f64::INFINITY);
    }
    if info == 0x41 {
        return Ok(f64::NEG_INFINITY);
    }
    if info == 0x42 {
        return Ok(f64::NAN);
    }
    if info & 0x80 == 0 {
        return Err(DecodeError::new("decimal REAL encoding not supported", pos));
    }
    let negative = info & 0x40 != 0;
    let base_bits = (info >> 4) & 0x03;
    if base_bits != 0 {
        return Err(DecodeError::new("only base-2 REAL supported", pos));
    }
    let scaling = ((info >> 2) & 0x03) as i32;
    let exp_len = ((info & 0x03) + 1) as usize;

    let bytes = &value[1..];
    if bytes.len() < exp_len {
        return Err(DecodeError::new("truncated REAL exponent", pos));
    }
    let mut e: i32 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in &bytes[..exp_len] {
        e = (e << 8) | b as i32;
    }
    e += scaling;
    let mbytes = &bytes[exp_len..];

    let mut m: u64 = 0;
    for &b in mbytes {
        m = (m << 8) | b as u64;
    }

    // m has at most 53 significant bits by construction (encode's own
    // mantissa never exceeds that), so `m as f64` is exact (f64 represents
    // all integers up to 2^53 exactly) — the subsequent power-of-two
    // multiply is then also exact for any e in f64's normal exponent
    // range, since the true mathematical product is itself a valid,
    // exactly-representable f64 (same value encode started from) and IEEE
    // 754 multiplication is correctly rounded.
    let mut d = (m as f64) * 2f64.powi(e);
    if negative {
        d = -d;
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_zero_as_empty_value() {
        let mut buf = Vec::new();
        write_real(&mut buf, 0.0);
        assert_eq!(buf, vec![0x09, 0x00]);
    }

    #[test]
    fn encodes_negative_zero_as_empty_value() {
        // Matches asn1::Real: `d == 0.0` is true for -0.0 too, so sign is lost.
        let mut buf = Vec::new();
        write_real(&mut buf, -0.0);
        assert_eq!(buf, vec![0x09, 0x00]);
    }

    #[test]
    fn encodes_special_values() {
        let mut buf = Vec::new();
        write_real(&mut buf, f64::INFINITY);
        assert_eq!(buf, vec![0x09, 0x01, 0x40]);

        buf.clear();
        write_real(&mut buf, f64::NEG_INFINITY);
        assert_eq!(buf, vec![0x09, 0x01, 0x41]);

        buf.clear();
        write_real(&mut buf, f64::NAN);
        assert_eq!(buf, vec![0x09, 0x01, 0x42]);
    }

    #[test]
    fn round_trips_special_values() {
        for v in [f64::INFINITY, f64::NEG_INFINITY] {
            let mut buf = Vec::new();
            write_real(&mut buf, v);
            let mut r = Reader::new(&buf);
            assert_eq!(read_real(&mut r).unwrap(), v);
        }
        let mut buf = Vec::new();
        write_real(&mut buf, f64::NAN);
        let mut r = Reader::new(&buf);
        assert!(read_real(&mut r).unwrap().is_nan());
    }

    #[test]
    fn round_trips_ordinary_values() {
        for v in [1.0, -1.0, 0.5, 3.14159265358979, -2.71828, 1e10, -1e-10, 100.0, 65535.0] {
            let mut buf = Vec::new();
            write_real(&mut buf, v);
            let mut r = Reader::new(&buf);
            assert_eq!(read_real(&mut r).unwrap(), v, "round-trip failed for {v}");
        }
    }

    #[test]
    fn encodes_one_minimally() {
        // 1.0 = 1 * 2^0 -> mantissa byte 0x01, exponent 0 (1 byte: 0x00).
        // info = 0x80 (positive, base-2, scaling 0) | (elen-1=0) = 0x80.
        let mut buf = Vec::new();
        write_real(&mut buf, 1.0);
        assert_eq!(buf, vec![0x09, 0x03, 0x80, 0x00, 0x01]);
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x00]; // INTEGER tag, not REAL
        let mut r = Reader::new(&data);
        assert!(read_real(&mut r).is_err());
    }

    #[test]
    fn decimal_form_is_rejected() {
        // info byte with bit 0x80 clear -> decimal form (ISO 6093), unsupported.
        let data = [0x09, 0x02, 0x03, b'1'];
        let mut r = Reader::new(&data);
        assert!(read_real(&mut r).is_err());
    }

    #[test]
    fn base_8_or_16_is_rejected() {
        // base_bits != 0 in the info byte -> base-8/16, unsupported (only base-2).
        let data = [0x09, 0x03, 0x90, 0x00, 0x01]; // 0x90 = 0x80 | (base_bits=01<<4)
        let mut r = Reader::new(&data);
        assert!(read_real(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_5 = Tag::context(5, false);
        let mut buf = Vec::new();
        write_real_tagged(&mut buf, context_5, 1.0);
        assert_eq!(buf, vec![0x85, 0x03, 0x80, 0x00, 0x01]); // context primitive 5, not 0x09
        let mut r = Reader::new(&buf);
        assert_eq!(read_real_tagged(&mut r, context_5).unwrap(), 1.0);
    }

    #[test]
    fn tagged_rejects_the_natural_tag() {
        let mut buf = Vec::new();
        write_real(&mut buf, 1.0); // natural REAL_TAG
        let mut r = Reader::new(&buf);
        assert!(read_real_tagged(&mut r, Tag::context(5, false)).is_err());
    }
}
