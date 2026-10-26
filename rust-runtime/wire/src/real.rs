//! REAL encode/decode — X.680 §21, X.690 §8.5.
//!
//! Mirrors `asn1::Real`/`BerTraits<Real>`
//! (`runtime/include/asn1cpp/types/Real.hpp`): IEEE 754 double-precision,
//! encoded per X.690 §8.5.7's binary form (base-2, minimal mantissa
//! bytes) — special values `+INF`/`-INF`/`NaN` per X.690 §8.5.9, zero as
//! an empty value (X.690 §8.5.3). Decode also accepts the decimal form
//! (X.690 §8.5.8) and bases 8/16 (§8.5.7.2), rounded to the nearest double.
//!
//! `native_builtin_type` already mapped REAL to plain `f64` before this
//! issue — no collision to route around (unlike BIT STRING/OID/RELATIVE-OID,
//! `f64` had no other ASN.1 kind claiming it).

use crate::ber::reader::{DecodeError, Reader};
use crate::ber::tag::{universal, Tag};
use crate::ber::writer::write_primitive;

pub const REAL_TAG: Tag = Tag::universal(universal::REAL, false);

/// REAL (X.680 §21) — its own newtype, with its own `PrimitiveRef` variant.
#[derive(Debug, Clone, Copy, Default, PartialOrd)]
pub struct Real(pub f64);

/// Equality of REAL abstract values: minus zero and plus zero differ, and
/// NOT-A-NUMBER equals itself: X.690 §8.5.9 gives each its own encoding, so a
/// DEFAULT comparison never conflates -0 with 0. Mirrors `asn1::Real::operator==`.
impl PartialEq for Real {
    fn eq(&self, other: &Self) -> bool {
        if self.0.is_nan() || other.0.is_nan() {
            return self.0.is_nan() && other.0.is_nan();
        }
        self.0 == other.0 && self.0.is_sign_negative() == other.0.is_sign_negative()
    }
}

impl std::ops::Deref for Real {
    type Target = f64;
    fn deref(&self) -> &f64 {
        &self.0
    }
}

impl std::ops::DerefMut for Real {
    fn deref_mut(&mut self) -> &mut f64 {
        &mut self.0
    }
}

impl PartialEq<f64> for Real {
    fn eq(&self, other: &f64) -> bool {
        self.0 == *other
    }
}


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
        // X.690 §8.5.9: PLUS-ZERO is the empty encoding; MINUS-ZERO
        // (distinct from PLUS-ZERO -- `==` can't tell them apart, hence
        // is_sign_negative) is a single content octet 0x43, not empty.
        // Conflating the two used to silently drop the sign of -0.0.
        if value.is_sign_negative() {
            out.push(0x43);
        }
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

/// Bit `i` (0 = least significant) of the unsigned big-endian integer `n`.
fn bit_at(n: &[u8], i: i64) -> bool {
    (n[n.len() - 1 - (i / 8) as usize] >> (i % 8)) & 1 != 0
}

/// Converts S × N × 2^`e2` to the nearest `f64`, rounding half to even.
/// `n` is N as an unsigned big-endian integer with leading zero octets
/// stripped (not empty, first octet non-zero); `e2` is the binary exponent
/// of N's least significant bit. A value whose magnitude rounds to infinity,
/// or to zero although N is non-zero, is outside the double range and an
/// error. Mirrors `real_from_binary` in `runtime/src/Real.cpp`.
/// X.690 §8.5.7; IEEE 754 round-to-nearest-even.
fn real_from_binary(negative: bool, n: &[u8], e2: i64, pos: usize) -> Result<f64, DecodeError> {
    let range = || DecodeError::new("REAL: value outside the double range", pos);
    let bits_n = (n.len() as i64 - 1) * 8 + (8 - n[0].leading_zeros() as i64);
    let e_msb = e2 + bits_n - 1;
    if e_msb > 1023 || e_msb < -1076 {
        return Err(range());
    }

    // Unit of the result's last significand bit: 53 significant bits for a
    // normal double, fewer below 2^-1022 (subnormal, unit 2^-1074).
    let mut unit = (e_msb - 52).max(-1074);
    let shift = unit - e2;
    let mut kept: u64 = 0;
    if shift <= 0 {
        for i in (0..bits_n).rev() {
            kept = (kept << 1) | bit_at(n, i) as u64;
        }
        kept <<= -shift;
    } else {
        for i in (shift..bits_n).rev() {
            kept = (kept << 1) | bit_at(n, i) as u64;
        }
        let round = bit_at(n, shift - 1);
        let sticky = (0..shift - 1).any(|i| bit_at(n, i));
        if round && (sticky || kept & 1 != 0) {
            kept += 1;
        }
    }
    if kept == 1u64 << 53 {
        kept >>= 1;
        unit += 1;
    }
    if kept == 0 {
        return Err(range());
    }

    let mut bits = if kept < 1u64 << 52 {
        kept // subnormal: unit is 2^-1074
    } else {
        let biased = unit + 52 + 1023;
        if biased >= 2047 {
            return Err(range());
        }
        ((biased as u64) << 52) | (kept & ((1u64 << 52) - 1))
    };
    if negative {
        bits |= 1u64 << 63;
    }
    Ok(f64::from_bits(bits))
}

/// Parses an ISO 6093 number (X.690 §8.5.8) in NR `form` 1, 2 or 3 into the
/// nearest `f64`. Accepted: leading spaces, an optional sign, digits; NR2
/// and NR3 add a decimal mark (`.` or `,`); NR3 adds `E`/`e`, an optional
/// sign and exponent digits (the decimal mark is optional in NR3). Text that
/// is not an NR`form` number, or a value beyond the double range, is an
/// error. Mirrors `real_from_decimal` in `runtime/src/Real.cpp`.
fn real_from_decimal(form: u8, text: &[u8], pos: usize) -> Result<f64, DecodeError> {
    let bad = || DecodeError::new("REAL: malformed ISO 6093 number", pos);
    let mut i = 0;
    while i < text.len() && text[i] == b' ' {
        i += 1;
    }
    let mut norm = String::new();
    if i < text.len() && (text[i] == b'+' || text[i] == b'-') {
        norm.push(text[i] as char);
        i += 1;
    }
    let (mut digits, mut nonzero, mut mark) = (false, false, false);
    while i < text.len() {
        let c = text[i];
        if c.is_ascii_digit() {
            digits = true;
            nonzero |= c != b'0';
            norm.push(c as char);
        } else if (c == b'.' || c == b',') && !mark && form >= 2 {
            mark = true;
            norm.push('.');
        } else {
            break;
        }
        i += 1;
    }
    if !digits || (form == 2 && !mark) {
        return Err(bad());
    }
    if form == 3 {
        if i >= text.len() || (text[i] != b'E' && text[i] != b'e') {
            return Err(bad());
        }
        norm.push('e');
        i += 1;
        if i < text.len() && (text[i] == b'+' || text[i] == b'-') {
            norm.push(text[i] as char);
            i += 1;
        }
        let exp_start = i;
        while i < text.len() && text[i].is_ascii_digit() {
            norm.push(text[i] as char);
            i += 1;
        }
        if i == exp_start {
            return Err(bad());
        }
    }
    if i != text.len() {
        return Err(bad());
    }
    let d: f64 = norm.parse().map_err(|_| bad())?;
    if d.is_infinite() || (d == 0.0 && nonzero) {
        return Err(DecodeError::new("REAL: value outside the double range", pos));
    }
    Ok(d)
}

/// Decodes the contents octets of a BER REAL into an `f64`. A reserved or
/// malformed encoding, or a value beyond the double range, is an error.
/// Mirrors `decode_real_contents` in `runtime/src/Real.cpp`.
/// X.690 §8.5 — §8.5.2 plus zero, §8.5.7 binary form (exponent formats a–d
/// of §8.5.7.4, bases 2/8/16 of §8.5.7.2, unnormalized mantissa of §8.5.7.5
/// NOTE 1), §8.5.8 decimal form, §8.5.9 special values.
pub(crate) fn decode_real_value(value: &[u8], pos: usize) -> Result<f64, DecodeError> {
    let err = |what: &str| DecodeError::new(format!("REAL: {what}"), pos);
    if value.is_empty() {
        return Ok(0.0);
    }
    let info = value[0];
    if info & 0xC0 == 0x40 {
        if value.len() != 1 {
            return Err(err("special value with extra contents octets"));
        }
        return match info {
            0x40 => Ok(f64::INFINITY),
            0x41 => Ok(f64::NEG_INFINITY),
            0x42 => Ok(f64::NAN),
            0x43 => Ok(-0.0),
            _ => Err(err("reserved special value")),
        };
    }
    if info & 0x80 == 0 {
        let form = info & 0x3F;
        if !(1..=3).contains(&form) {
            return Err(err("reserved decimal number representation"));
        }
        return real_from_decimal(form, &value[1..], pos);
    }
    let negative = info & 0x40 != 0;
    // B' = 2, 8 or 16: one, three or four binary digits per exponent step.
    let log2_base: i64 = match (info >> 4) & 0x03 {
        0 => 1,
        1 => 3,
        2 => 4,
        _ => return Err(err("reserved base")),
    };
    let scaling = ((info >> 2) & 0x03) as i64;

    let mut rest = &value[1..];
    let exp_len = if info & 0x03 == 0x03 {
        let (&x, tail) = rest.split_first().ok_or_else(|| err("truncated exponent length"))?;
        rest = tail;
        if x == 0 {
            return Err(err("exponent length 0"));
        }
        x as usize
    } else {
        (info & 0x03) as usize + 1
    };
    if rest.len() < exp_len {
        return Err(DecodeError::new("truncated REAL exponent", pos));
    }
    let (exp, mut n) = rest.split_at(exp_len);

    while let [0, tail @ ..] = n {
        n = tail;
    }
    if n.is_empty() {
        return Ok(if negative { -0.0 } else { 0.0 });
    }

    // Two's-complement exponent; redundant sign octets carry no value.
    let sign: u8 = if exp[0] & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut k = 0;
    while k + 1 < exp.len() && exp[k] == sign && (exp[k + 1] & 0x80) == (sign & 0x80) {
        k += 1;
    }
    if exp.len() - k > 7 {
        return Err(err("value outside the double range"));
    }
    let mut e: i64 = if sign != 0 { -1 } else { 0 };
    for &b in &exp[k..] {
        e = ((e as u64) << 8 | b as u64) as i64;
    }

    real_from_binary(negative, n, e * log2_base + scaling, pos)
}

/// X.693 §17.9 textual form for XER. Deliberately NOT shared with
/// `jer::real`'s own formatter despite the superficial similarity (both
/// classify NaN/Inf/signed-zero before formatting a plain decimal):
/// XER follows asn1c's `REAL__dump` (`%.15f` fixed-decimal, never
/// exponential), while JER writes the shortest text that converts back
/// to the same double, with an exponential form outside [1e-4, 1e15)
/// (`jer::real::format_real`). The two also differ in their
/// special-value spelling (`PLUS-INFINITY`/`MINUS-INFINITY`/
/// `NOT-A-NUMBER` elements vs quoted `"INF"`/`"-INF"`/`"NaN"` strings).
/// Kept here, next to the BER codec above and within sight of
/// `jer::real`'s own formatter, specifically so the two classifications
/// stay visible for comparison on review — the signed-zero handling gap
/// this type once had came from exactly this kind of near-identical
/// logic drifting apart while living in different files.
pub(crate) enum XerRealText {
    Special(&'static str),
    Decimal(String),
}

pub(crate) fn format_xer(d: f64) -> XerRealText {
    if d.is_nan() {
        return XerRealText::Special("NOT-A-NUMBER");
    }
    if d.is_infinite() {
        return XerRealText::Special(if d > 0.0 { "PLUS-INFINITY" } else { "MINUS-INFINITY" });
    }
    if d == 0.0 {
        return XerRealText::Decimal(if d.is_sign_negative() { "-0".to_string() } else { "0".to_string() });
    }
    let mut buf = format!("{:.15}", d);
    if let Some(dot) = buf.find('.') {
        let mut last = buf.len() - 1;
        while last > dot + 1 && buf.as_bytes()[last] == b'0' {
            last -= 1;
        }
        buf.truncate(last + 1);
    }
    XerRealText::Decimal(buf)
}

pub(crate) fn parse_xer_special(name: &str) -> Option<f64> {
    match name {
        "PLUS-INFINITY" => Some(f64::INFINITY),
        "MINUS-INFINITY" => Some(f64::NEG_INFINITY),
        "NOT-A-NUMBER" => Some(f64::NAN),
        _ => None,
    }
}

pub(crate) fn parse_xer_decimal(text: &str) -> Result<f64, String> {
    let trimmed = text.trim();
    trimmed.parse::<f64>().map_err(|_| format!("XER: invalid REAL value: {trimmed}"))
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
    fn encodes_negative_zero_as_single_octet_0x43() {
        // X.690 §8.5.9: MINUS-ZERO is a real, distinct encoding from
        // PLUS-ZERO's empty one, not a sign-losing alias for it (a
        // previous version of this test, and of encode_real_content
        // itself, assumed the opposite).
        let mut buf = Vec::new();
        write_real(&mut buf, -0.0);
        assert_eq!(buf, vec![0x09, 0x01, 0x43]);

        let mut r = Reader::new(&buf);
        let got = read_real(&mut r).unwrap();
        assert_eq!(got, 0.0);
        assert!(got.is_sign_negative());
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
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_5 = Tag::context(5, false);
        let mut buf = Vec::new();
        write_real_tagged(&mut buf, context_5, 1.0);
        assert_eq!(buf, vec![0x85, 0x03, 0x80, 0x00, 0x01]); // context primitive 5, not 0x09
        let mut r = Reader::new(&buf);
        assert_eq!(read_real_tagged(&mut r, context_5).unwrap(), 1.0);
    }

    fn zeros(head: &[u8], zeros: usize, tail: &[u8]) -> Vec<u8> {
        let mut v = head.to_vec();
        v.extend(std::iter::repeat(0u8).take(zeros));
        v.extend_from_slice(tail);
        v
    }

    /// Shared with `tests/ber/test_real_ber.cpp`: both runtimes must give
    /// the same bit pattern, or both an error (`None`).
    fn decode_vectors() -> Vec<(&'static str, Vec<u8>, Option<u64>)> {
        vec![
            ("plus zero, no contents (§8.5.2)", vec![], Some(0x0000000000000000)),
            ("1.0, exponent format a", vec![0x80, 0x00, 0x01], Some(0x3FF0000000000000)),
            ("-1.0 (§8.5.7.1)", vec![0xC0, 0x00, 0x01], Some(0xBFF0000000000000)),
            ("2.0 via scaling factor F=1 (§8.5.7.3)", vec![0x84, 0x00, 0x01], Some(0x4000000000000000)),
            ("1.0, format d, X=1 (§8.5.7.4 d)", vec![0x83, 0x01, 0x00, 0x01], Some(0x3FF0000000000000)),
            ("1.0, format d, X=2", vec![0x83, 0x02, 0x00, 0x00, 0x01], Some(0x3FF0000000000000)),
            ("1.0, format d, X=5", vec![0x83, 0x05, 0, 0, 0, 0, 0, 0x01], Some(0x3FF0000000000000)),
            ("1.0, format d, exponent -1 in 9 octets",
             vec![0x83, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02], Some(0x3FF0000000000000)),
            ("2^72, 10-octet mantissa (§8.5.7.5 NOTE 1)", zeros(&[0x80, 0x00, 0x01], 9, &[]), Some(0x4470000000000000)),
            ("2^-64, 11-octet mantissa, exponent -80", zeros(&[0x80, 0xB0], 8, &[0x01, 0x00, 0x00]), Some(0x3BF0000000000000)),
            ("2^53+1 rounds to even 2^53", vec![0x80, 0x00, 0x20, 0, 0, 0, 0, 0, 0x01], Some(0x4340000000000000)),
            ("2^53+3 rounds up to 2^53+4", vec![0x80, 0x00, 0x20, 0, 0, 0, 0, 0, 0x03], Some(0x4340000000000002)),
            ("leading zero mantissa octets", vec![0x80, 0x00, 0x00, 0x00, 0x01], Some(0x3FF0000000000000)),
            ("zero mantissa is zero", vec![0xC0, 0x00, 0x00], Some(0x8000000000000000)),
            ("largest double (2^53-1) * 2^971",
             vec![0x81, 0x03, 0xCB, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], Some(0x7FEFFFFFFFFFFFFF)),
            ("smallest subnormal 2^-1074", vec![0x81, 0xFB, 0xCE, 0x01], Some(0x0000000000000001)),
            ("3 * 2^-1076 rounds to 2^-1074", vec![0x81, 0xFB, 0xCC, 0x03], Some(0x0000000000000001)),
            ("subnormal 3 * 2^-1074", vec![0x81, 0xFB, 0xCE, 0x03], Some(0x0000000000000003)),
            ("smallest normal 2^-1022", vec![0x81, 0xFC, 0x02, 0x01], Some(0x0010000000000000)),
            ("2^1024 is out of range", vec![0x81, 0x04, 0x00, 0x01], None),
            ("exponent ~2^31 is out of range", vec![0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01], None),
            ("2^-1076 rounds to zero: out of range", vec![0x81, 0xFB, 0xCC, 0x01], None),
            ("format d without length octet", vec![0x83], None),
            ("format d, X=0", vec![0x83, 0x00, 0x01], None),
            ("format d, truncated exponent", vec![0x83, 0x02, 0x00], None),
            ("format b, truncated exponent", vec![0x81, 0x00], None),
            ("special value with extra octet", vec![0x40, 0x00], None),
            ("reserved special value 0x44 (§8.5.9)", vec![0x44], None),
            ("decimal NR1 14 (§8.5.8)", vec![0x01, 0x31, 0x34], Some(0x402C000000000000)),
            ("decimal NR1 with spaces and sign", vec![0x01, 0x20, 0x20, 0x2D, 0x31, 0x34], Some(0xC02C000000000000)),
            ("decimal NR1 -0", vec![0x01, 0x2D, 0x30], Some(0x8000000000000000)),
            ("decimal NR2 14.56", vec![0x02, 0x31, 0x34, 0x2E, 0x35, 0x36], Some(0x402D1EB851EB851F)),
            ("decimal NR2 ISO 6093 comma 14,56", vec![0x02, 0x31, 0x34, 0x2C, 0x35, 0x36], Some(0x402D1EB851EB851F)),
            ("decimal NR2 .5", vec![0x02, 0x2E, 0x35], Some(0x3FE0000000000000)),
            ("decimal NR2 5.", vec![0x02, 0x35, 0x2E], Some(0x4014000000000000)),
            ("decimal NR3 14.56E0", vec![0x03, 0x31, 0x34, 0x2E, 0x35, 0x36, 0x45, 0x30], Some(0x402D1EB851EB851F)),
            ("decimal NR3 1456e-2, no decimal mark", vec![0x03, 0x31, 0x34, 0x35, 0x36, 0x65, 0x2D, 0x32], Some(0x402D1EB851EB851F)),
            ("decimal NR3 +1.456E+1", vec![0x03, 0x2B, 0x31, 0x2E, 0x34, 0x35, 0x36, 0x45, 0x2B, 0x31], Some(0x402D1EB851EB851F)),
            ("decimal NR1 with a mark is malformed", vec![0x01, 0x31, 0x2E, 0x35], None),
            ("decimal NR2 without a mark is malformed", vec![0x02, 0x31, 0x34], None),
            ("decimal NR3 without exponent is malformed", vec![0x03, 0x31, 0x34, 0x2E, 0x35, 0x36], None),
            ("decimal NR3 without exponent digits", vec![0x03, 0x31, 0x45], None),
            ("decimal trailing space is malformed", vec![0x01, 0x31, 0x34, 0x20], None),
            ("decimal empty field", vec![0x01], None),
            ("decimal NR3 1E400 is out of range", vec![0x03, 0x31, 0x45, 0x34, 0x30, 0x30], None),
            ("decimal NR3 1E-400 is out of range", vec![0x03, 0x31, 0x45, 0x2D, 0x34, 0x30, 0x30], None),
            ("base 8, exponent 0 (§8.5.7.2)", vec![0x90, 0x00, 0x01], Some(0x3FF0000000000000)),
            ("base 8, exponent 1 is 8", vec![0x90, 0x01, 0x01], Some(0x4020000000000000)),
            ("base 8, exponent 1, F=2 is 32", vec![0x98, 0x01, 0x01], Some(0x4040000000000000)),
            ("base 16, exponent 1 is 16", vec![0xA0, 0x01, 0x01], Some(0x4030000000000000)),
            ("base 16, exponent -1 is 1/16", vec![0xA0, 0xFF, 0x01], Some(0x3FB0000000000000)),
            ("reserved base 11", vec![0xB0, 0x00, 0x01], None),
            ("reserved decimal form 0", vec![0x00, 0x31], None),
            ("reserved decimal form 4", vec![0x04, 0x31], None),
            ("PLUS-INFINITY (§8.5.9)", vec![0x40], Some(0x7FF0000000000000)),
            ("MINUS-INFINITY", vec![0x41], Some(0xFFF0000000000000)),
            ("minus zero", vec![0x43], Some(0x8000000000000000)),
        ]
    }

    #[test]
    fn decode_vectors_match_the_cpp_runtime() {
        for (label, contents, want) in decode_vectors() {
            let got = decode_real_value(&contents, 0).ok().map(f64::to_bits);
            assert_eq!(got, want, "{label}");
        }
        assert!(decode_real_value(&[0x42], 0).unwrap().is_nan());
    }

    #[test]
    fn tagged_rejects_the_natural_tag() {
        let mut buf = Vec::new();
        write_real(&mut buf, 1.0); // natural REAL_TAG
        let mut r = Reader::new(&buf);
        assert!(read_real_tagged(&mut r, Tag::context(5, false)).is_err());
    }
}
