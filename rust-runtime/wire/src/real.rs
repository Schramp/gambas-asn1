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

/// Storage class of a [`Real`]. Mirrors `asn1::Real::Storage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// An IEEE 754 double, base 2: the default, allocation-free.
    Double,
    /// Base 2 with an arbitrary mantissa: a BER binary value an `f64`
    /// cannot hold exactly.
    Binary,
    /// Base 10 with an arbitrary digit string: the BER decimal form or JER
    /// `{"base10Value": n}`.
    Decimal,
}

/// Exact components of a `Binary` or `Decimal` value:
/// (negative ? −1 : 1) × mantissa × base^exponent. `Binary`: `mantissa` is
/// big-endian octets, odd (X.690 §11.3.1). `Decimal`: ASCII digits, neither
/// first nor last digit 0 (X.690 §11.3.2.4). Unique per abstract value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exact {
    pub storage: Storage,
    pub negative: bool,
    pub mantissa: Vec<u8>,
    pub exponent: i64,
}

/// REAL: an abstract value mantissa × base^exponent with base 2 or 10
/// (X.680 §20.3–20.5), in one of three [`Storage`] classes. [`Real::value`]
/// is exact for `Double` and the nearest `f64` (±∞ / ±0 beyond the double
/// range) otherwise. Mirrors `asn1::Real` (`runtime/include/asn1cpp/types/Real.hpp`).
#[derive(Debug, Clone, Default)]
pub struct Real {
    value: f64,
    exact: Option<Box<Exact>>,
}

impl Real {
    /// A base-2 `Double` value.
    pub const fn new(value: f64) -> Self {
        Real { value, exact: None }
    }

    /// A base-2 value S × N × 2^`exponent` (`mantissa` = N, big-endian,
    /// leading zero octets allowed; `exponent` of N's least significant bit).
    /// A value an `f64` holds exactly becomes `Double`, any other `Binary`;
    /// a zero mantissa gives ±0. Mirrors `asn1::Real::binary`. X.690 §8.5.7.
    pub fn binary(negative: bool, mantissa: &[u8], exponent: i64) -> Self {
        let mut m = mantissa;
        while let [0, tail @ ..] = m {
            m = tail;
        }
        if m.is_empty() {
            return Real::new(if negative { -0.0 } else { 0.0 });
        }
        // Odd mantissa (X.690 §11.3.1): trailing zero bits move into the exponent.
        let zero_octets = m.iter().rev().take_while(|&&b| b == 0).count();
        let m = &m[..m.len() - zero_octets];
        let r = m[m.len() - 1].trailing_zeros();
        let mut out = Vec::with_capacity(m.len());
        let mut carry = 0u8;
        for &b in m {
            out.push(if r != 0 { (b >> r) | carry } else { b });
            carry = if r != 0 { b << (8 - r) } else { 0 };
        }
        if out.len() > 1 && out[0] == 0 {
            out.remove(0);
        }
        let exponent = exponent + zero_octets as i64 * 8 + r as i64;
        let (value, exact) = real_from_binary(negative, &out, exponent);
        if exact {
            return Real::new(value);
        }
        Real { value, exact: Some(Box::new(Exact { storage: Storage::Binary, negative, mantissa: out, exponent })) }
    }

    /// A base-10 `Decimal` value S × `digits` × 10^`exponent` (`exponent` of
    /// the last digit; leading and trailing zeros allowed). All-zero digits
    /// give ±0 (`Double`). Mirrors `asn1::Real::decimal`. X.680 §20.5.
    pub fn decimal(negative: bool, digits: &str, exponent: i64) -> Self {
        let digits = digits.trim_start_matches('0');
        if digits.is_empty() {
            return Real::new(if negative { -0.0 } else { 0.0 });
        }
        let trimmed = digits.trim_end_matches('0');
        let exponent = exponent.saturating_add((digits.len() - trimmed.len()) as i64);
        let text = format!("{}{}e{}", if negative { "-" } else { "" }, trimmed, exponent);
        let value = text.parse::<f64>().unwrap_or(if negative { f64::NEG_INFINITY } else { f64::INFINITY });
        Real {
            value,
            exact: Some(Box::new(Exact {
                storage: Storage::Decimal,
                negative,
                mantissa: trimmed.as_bytes().to_vec(),
                exponent,
            })),
        }
    }

    /// The value as an `f64`: exact for `Double`, the nearest `f64` otherwise.
    pub fn value(&self) -> f64 {
        self.value
    }

    /// Sets a base-2 `Double` value.
    pub fn set(&mut self, value: f64) {
        self.value = value;
        self.exact = None;
    }

    pub fn storage(&self) -> Storage {
        self.exact.as_ref().map_or(Storage::Double, |x| x.storage)
    }

    /// 10 for `Decimal`, 2 otherwise.
    pub fn base(&self) -> u32 {
        if self.storage() == Storage::Decimal { 10 } else { 2 }
    }

    /// Exact components; `None` for `Double`.
    pub fn exact(&self) -> Option<&Exact> {
        self.exact.as_deref()
    }

    /// Numeric equality at double precision, ignoring the base: compares
    /// [`Real::value`], with -0 equal to +0 and NaN unequal to itself.
    pub fn numerically_equal(&self, other: &Real) -> bool {
        self.value == other.value
    }

    /// Exact text of a `Decimal` value, `[-]digitsE<exp>` or `[-]digits` when
    /// the exponent is 0: a JSON number (X.697 §23.4) and an X.680
    /// realnumber. `None` for other storage classes. Mirrors
    /// `asn1::Real::decimal_text`.
    pub fn decimal_text(&self) -> Option<String> {
        let x = self.exact.as_ref().filter(|x| x.storage == Storage::Decimal)?;
        let mut t = String::from(if x.negative { "-" } else { "" });
        t.push_str(std::str::from_utf8(&x.mantissa).unwrap_or(""));
        if x.exponent != 0 {
            t.push_str(&format!("E{}", x.exponent));
        }
        Some(t)
    }
}

impl From<f64> for Real {
    fn from(value: f64) -> Self {
        Real::new(value)
    }
}

/// Equality of REAL abstract values: storage class (base) and exact
/// components must match. For `Double`, minus zero and plus zero differ and
/// NOT-A-NUMBER equals itself, since X.690 §8.5.9 gives each its own
/// encoding. X.680 §20.5 NOTE 1: base-2 and base-10 values are distinct.
/// Mirrors `asn1::Real::operator==`.
impl PartialEq for Real {
    fn eq(&self, other: &Self) -> bool {
        match (&self.exact, &other.exact) {
            (Some(a), Some(b)) => a == b,
            (None, None) => {
                if self.value.is_nan() || other.value.is_nan() {
                    return self.value.is_nan() && other.value.is_nan();
                }
                self.value == other.value && self.value.is_sign_negative() == other.value.is_sign_negative()
            }
            _ => false,
        }
    }
}

impl PartialOrd for Real {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl std::ops::Deref for Real {
    type Target = f64;
    fn deref(&self) -> &f64 {
        &self.value
    }
}

impl PartialEq<f64> for Real {
    fn eq(&self, other: &f64) -> bool {
        self.value == *other
    }
}

pub fn write_real(out: &mut Vec<u8>, value: &Real) {
    write_real_tagged(out, REAL_TAG, value);
}

pub fn read_real(r: &mut Reader) -> Result<Real, DecodeError> {
    read_real_tagged(r, REAL_TAG)
}

/// Content octets only (X.690 §8.5): a `Binary` or `Decimal` value in its
/// CER/DER form (X.690 §11.3), a `Double` as below. Mirrors
/// `BerTraits<Real>::encode` / `detail::encode_real_exact`.
pub(crate) fn encode_real_content(out: &mut Vec<u8>, value: &Real) {
    match value.exact() {
        Some(x) if x.storage == Storage::Decimal => {
            // NR3 (X.690 §11.3.2): [-]digits.E<exp>, exponent "+0" when zero.
            out.push(0x03);
            if x.negative {
                out.push(b'-');
            }
            out.extend_from_slice(&x.mantissa);
            out.extend_from_slice(b".E");
            if x.exponent == 0 {
                out.extend_from_slice(b"+0");
            } else {
                out.extend_from_slice(x.exponent.to_string().as_bytes());
            }
        }
        Some(x) => {
            // Binary, base 2, F = 0, odd mantissa, fewest octets (X.690 §11.3.1).
            let be = x.exponent.to_be_bytes();
            let mut start = 0;
            while start < 7
                && ((be[start] == 0x00 && be[start + 1] & 0x80 == 0) || (be[start] == 0xFF && be[start + 1] & 0x80 != 0))
            {
                start += 1;
            }
            let exp = &be[start..];
            let info = 0x80 | if x.negative { 0x40 } else { 0x00 };
            if exp.len() <= 3 {
                out.push(info | (exp.len() as u8 - 1));
            } else {
                out.push(info | 0x03);
                out.push(exp.len() as u8);
            }
            out.extend_from_slice(exp);
            out.extend_from_slice(&x.mantissa);
        }
        None => encode_double_content(out, value.value()),
    }
}

/// Content octets of an `f64` (X.690 §8.5): empty for zero, one info byte
/// for the special values, info+exponent+mantissa for everything else.
fn encode_double_content(out: &mut Vec<u8>, value: f64) {
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

pub fn write_real_tagged(out: &mut Vec<u8>, tag: Tag, value: &Real) {
    let mut content = Vec::new();
    encode_real_content(&mut content, value);
    write_primitive(out, tag, &content);
}

pub fn read_real_tagged(r: &mut Reader, tag: Tag) -> Result<Real, DecodeError> {
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

/// Converts S × N × 2^`e2` to the nearest `f64`, rounding half to even, and
/// says whether it is exact. `n` is N as an unsigned big-endian integer with
/// leading zero octets stripped (not empty, first octet non-zero); `e2` is
/// the binary exponent of N's least significant bit. A magnitude beyond the
/// double range gives ±∞ or ±0, inexact. Mirrors `real_from_binary` in
/// `runtime/src/Real.cpp`. X.690 §8.5.7; IEEE 754 round-to-nearest-even.
fn real_from_binary(negative: bool, n: &[u8], e2: i64) -> (f64, bool) {
    let inf = if negative { f64::NEG_INFINITY } else { f64::INFINITY };
    let zero = if negative { -0.0 } else { 0.0 };
    let bits_n = (n.len() as i64 - 1) * 8 + (8 - n[0].leading_zeros() as i64);
    let e_msb = e2 + bits_n - 1;
    if e_msb > 1023 {
        return (inf, false);
    }
    if e_msb < -1075 {
        // Below half of 2^-1074: rounds to zero.
        return (zero, false);
    }

    // Unit of the result's last significand bit: 53 significant bits for a
    // normal double, fewer below 2^-1022 (subnormal, unit 2^-1074).
    let mut unit = (e_msb - 52).max(-1074);
    let shift = unit - e2;
    let mut kept: u64 = 0;
    let mut exact = true;
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
        exact = !round && !sticky;
        if round && (sticky || kept & 1 != 0) {
            kept += 1;
        }
    }
    if kept == 1u64 << 53 {
        kept >>= 1;
        unit += 1;
    }
    if kept == 0 {
        return (zero, false);
    }

    let mut bits = if kept < 1u64 << 52 {
        kept // subnormal: unit is 2^-1074
    } else {
        let biased = unit + 52 + 1023;
        if biased >= 2047 {
            return (inf, false);
        }
        ((biased as u64) << 52) | (kept & ((1u64 << 52) - 1))
    };
    if negative {
        bits |= 1u64 << 63;
    }
    (f64::from_bits(bits), exact)
}

/// Parses optionally-signed decimal digits as an `i64`; `None` when empty,
/// non-digit or beyond 64 bits.
fn parse_exponent(t: &str) -> Option<i64> {
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse::<i64>().ok()
}

/// A `Decimal` from its digits and exponent, after a fraction of `frac_len`
/// digits was folded into the digit string.
fn decimal_value(negative: bool, digits: &str, exponent: i64, frac_len: usize) -> Option<Real> {
    let e = exponent.checked_sub(frac_len as i64)?;
    Some(Real::decimal(negative, digits, e))
}

/// Parses an ISO 6093 number (X.690 §8.5.8) in NR `form` 1, 2 or 3 into a
/// base-10 value. Accepted: leading spaces, an optional sign, digits; NR2
/// and NR3 add a decimal mark (`.` or `,`); NR3 adds `E`/`e`, an optional
/// sign and exponent digits (the decimal mark is optional in NR3). Text that
/// is not an NR`form` number, or an exponent beyond 64 bits, is an error.
/// Mirrors `real_from_decimal` in `runtime/src/Real.cpp`.
fn real_from_decimal(form: u8, text: &[u8], pos: usize) -> Result<Real, DecodeError> {
    let bad = || DecodeError::new("REAL: malformed ISO 6093 number", pos);
    let wide = || DecodeError::new("REAL: decimal exponent beyond 64 bits", pos);
    let mut i = 0;
    while i < text.len() && text[i] == b' ' {
        i += 1;
    }
    let mut negative = false;
    if i < text.len() && (text[i] == b'+' || text[i] == b'-') {
        negative = text[i] == b'-';
        i += 1;
    }
    let mut digits = String::new();
    let (mut frac_len, mut mark) = (0usize, false);
    while i < text.len() {
        let c = text[i];
        if c.is_ascii_digit() {
            digits.push(c as char);
            if mark {
                frac_len += 1;
            }
        } else if (c == b'.' || c == b',') && !mark && form >= 2 {
            mark = true;
        } else {
            break;
        }
        i += 1;
    }
    if digits.is_empty() || (form == 2 && !mark) {
        return Err(bad());
    }
    let mut exponent = 0i64;
    if form == 3 {
        if i >= text.len() || (text[i] != b'E' && text[i] != b'e') {
            return Err(bad());
        }
        i += 1;
        let exp_start = i;
        if i < text.len() && (text[i] == b'+' || text[i] == b'-') {
            i += 1;
        }
        while i < text.len() && text[i].is_ascii_digit() {
            i += 1;
        }
        let et = std::str::from_utf8(&text[exp_start..i]).map_err(|_| bad())?;
        if et.is_empty() || et == "+" || et == "-" {
            return Err(bad());
        }
        exponent = parse_exponent(et).ok_or_else(wide)?;
    }
    if i != text.len() {
        return Err(bad());
    }
    decimal_value(negative, &digits, exponent, frac_len).ok_or_else(wide)
}

/// Parses `[-]digits[.digits][(e|E)[+-]digits]` (a JSON number, X.697
/// §23.4) exactly into a `Decimal`. Mirrors `detail::parse_decimal_number`.
pub(crate) fn parse_decimal_number(t: &str) -> Option<Real> {
    let b = t.as_bytes();
    let mut i = 0;
    let mut negative = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        negative = b[i] == b'-';
        i += 1;
    }
    let mut digits = String::new();
    while i < b.len() && b[i].is_ascii_digit() {
        digits.push(b[i] as char);
        i += 1;
    }
    if digits.is_empty() {
        return None;
    }
    let mut frac_len = 0;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            digits.push(b[i] as char);
            i += 1;
        }
        frac_len = i - start;
    }
    let mut exponent = 0;
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        exponent = parse_exponent(&t[i + 1..])?;
        i = b.len();
    }
    if i != b.len() {
        return None;
    }
    decimal_value(negative, &digits, exponent, frac_len)
}

/// Decodes the contents octets of a BER REAL: `Double` when an `f64` holds
/// the value exactly, `Binary` for any other binary-form value, `Decimal`
/// for the decimal form. A reserved or malformed encoding, or an exponent
/// beyond 56 bits (binary) or 64 bits (decimal), is an error.
/// Mirrors `decode_real_contents` in `runtime/src/Real.cpp`.
/// X.690 §8.5 — §8.5.2 plus zero, §8.5.7 binary form (exponent formats a–d
/// of §8.5.7.4, bases 2/8/16 of §8.5.7.2, unnormalized mantissa of §8.5.7.5
/// NOTE 1), §8.5.8 decimal form, §8.5.9 special values.
pub(crate) fn decode_real_value(value: &[u8], pos: usize) -> Result<Real, DecodeError> {
    let err = |what: &str| DecodeError::new(format!("REAL: {what}"), pos);
    if value.is_empty() {
        return Ok(Real::new(0.0));
    }
    let info = value[0];
    if info & 0xC0 == 0x40 {
        if value.len() != 1 {
            return Err(err("special value with extra contents octets"));
        }
        return match info {
            0x40 => Ok(Real::new(f64::INFINITY)),
            0x41 => Ok(Real::new(f64::NEG_INFINITY)),
            0x42 => Ok(Real::new(f64::NAN)),
            0x43 => Ok(Real::new(-0.0)),
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
        return Ok(Real::new(if negative { -0.0 } else { 0.0 }));
    }

    // Two's-complement exponent; redundant sign octets carry no value.
    let sign: u8 = if exp[0] & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut k = 0;
    while k + 1 < exp.len() && exp[k] == sign && (exp[k + 1] & 0x80) == (sign & 0x80) {
        k += 1;
    }
    if exp.len() - k > 7 {
        return Err(err("binary exponent beyond 56 bits"));
    }
    let mut e: i64 = if sign != 0 { -1 } else { 0 };
    for &b in &exp[k..] {
        e = ((e as u64) << 8 | b as u64) as i64;
    }

    let e2 = e * log2_base + scaling;
    if n.len() <= 8 {
        // Common case, a value a double holds exactly: at most 53 significant
        // bits and a scale inside the double range (normal or subnormal).
        let m = n.iter().fold(0u64, |m, &b| (m << 8) | b as u64);
        let tz = m.trailing_zeros();
        let m = m >> tz;
        let width = 64 - m.leading_zeros() as i64;
        let lsb = e2 + tz as i64;
        let msb = lsb + width - 1;
        if width <= 53 && lsb >= -1074 && msb <= 1023 {
            let mut bits = if msb >= -1022 {
                ((msb + 1023) as u64) << 52 | ((m << (53 - width)) & ((1u64 << 52) - 1))
            } else {
                m << (lsb + 1074) // subnormal: unit 2^-1074
            };
            if negative {
                bits |= 1u64 << 63;
            }
            return Ok(Real::new(f64::from_bits(bits)));
        }
    }
    Ok(Real::binary(negative, n, e2))
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

    /// Short mantissas take a direct IEEE path; it must agree with the general
    /// normalizing Real::binary at every scale, including subnormal and
    /// out-of-range ones.
    #[test]
    fn short_mantissa_path_matches_general_binary() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut mantissas = vec![1u64, 3, 0xFF, (1 << 53) - 1, (1 << 53) + 1, (1 << 54) - 2, u64::MAX];
        for _ in 0..64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            mantissas.push(x >> (x % 60));
        }
        for &m in &mantissas {
            for e in (-1200i64..1100).step_by(7).chain(-1140..-1060).chain(960..1030) {
                for negative in [false, true] {
                    let mb = m.to_be_bytes();
                    let eb = (e as i16).to_be_bytes();
                    let mut v = vec![0x81 | if negative { 0x40 } else { 0 }];
                    v.extend_from_slice(&eb);
                    v.extend_from_slice(&mb);
                    let got = decode_real_value(&v, 0).unwrap();
                    assert_eq!(got, Real::binary(negative, &mb, e), "m={m:#x} e={e} neg={negative}");
                }
            }
        }
    }

    #[test]
    fn encodes_zero_as_empty_value() {
        let mut buf = Vec::new();
        write_real(&mut buf, &Real::new(0.0));
        assert_eq!(buf, vec![0x09, 0x00]);
    }

    #[test]
    fn encodes_negative_zero_as_single_octet_0x43() {
        // X.690 §8.5.9: MINUS-ZERO is a real, distinct encoding from
        // PLUS-ZERO's empty one, not a sign-losing alias for it (a
        // previous version of this test, and of encode_real_content
        // itself, assumed the opposite).
        let mut buf = Vec::new();
        write_real(&mut buf, &Real::new(-0.0));
        assert_eq!(buf, vec![0x09, 0x01, 0x43]);

        let mut r = Reader::new(&buf);
        let got = read_real(&mut r).unwrap();
        assert_eq!(got, 0.0);
        assert!(got.is_sign_negative());
    }

    #[test]
    fn encodes_special_values() {
        let mut buf = Vec::new();
        write_real(&mut buf, &Real::new(f64::INFINITY));
        assert_eq!(buf, vec![0x09, 0x01, 0x40]);

        buf.clear();
        write_real(&mut buf, &Real::new(f64::NEG_INFINITY));
        assert_eq!(buf, vec![0x09, 0x01, 0x41]);

        buf.clear();
        write_real(&mut buf, &Real::new(f64::NAN));
        assert_eq!(buf, vec![0x09, 0x01, 0x42]);
    }

    #[test]
    fn round_trips_special_values() {
        for v in [f64::INFINITY, f64::NEG_INFINITY] {
            let mut buf = Vec::new();
            write_real(&mut buf, &Real::new(v));
            let mut r = Reader::new(&buf);
            assert_eq!(read_real(&mut r).unwrap(), v);
        }
        let mut buf = Vec::new();
        write_real(&mut buf, &Real::new(f64::NAN));
        let mut r = Reader::new(&buf);
        assert!(read_real(&mut r).unwrap().is_nan());
    }

    #[test]
    fn round_trips_ordinary_values() {
        for v in [1.0, -1.0, 0.5, 3.14159265358979, -2.71828, 1e10, -1e-10, 100.0, 65535.0] {
            let mut buf = Vec::new();
            write_real(&mut buf, &Real::new(v));
            let mut r = Reader::new(&buf);
            assert_eq!(read_real(&mut r).unwrap(), v, "round-trip failed for {v}");
        }
    }

    #[test]
    fn encodes_one_minimally() {
        // 1.0 = 1 * 2^0 -> mantissa byte 0x01, exponent 0 (1 byte: 0x00).
        // info = 0x80 (positive, base-2, scaling 0) | (elen-1=0) = 0x80.
        let mut buf = Vec::new();
        write_real(&mut buf, &Real::new(1.0));
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
        write_real_tagged(&mut buf, context_5, &Real::new(1.0));
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
            ("2^1024: Binary, value +inf", vec![0x81, 0x04, 0x00, 0x01], Some(0x7FF0000000000000)),
            ("exponent ~2^31: Binary, value +inf", vec![0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01], Some(0x7FF0000000000000)),
            ("2^-1076: Binary, value +0", vec![0x81, 0xFB, 0xCC, 0x01], Some(0x0000000000000000)),
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
            ("decimal NR3 1E400: value +inf", vec![0x03, 0x31, 0x45, 0x34, 0x30, 0x30], Some(0x7FF0000000000000)),
            ("decimal NR3 1E-400: value +0", vec![0x03, 0x31, 0x45, 0x2D, 0x34, 0x30, 0x30], Some(0x0000000000000000)),
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
            let got = decode_real_value(&contents, 0).ok().map(|v| v.value().to_bits());
            assert_eq!(got, want, "{label}");
        }
        assert!(decode_real_value(&[0x42], 0).unwrap().is_nan());
    }

    fn ascii(head: u8, t: &str) -> Vec<u8> {
        let mut v = vec![head];
        v.extend_from_slice(t.as_bytes());
        v
    }

    /// Shared with `tests/ber/test_real_ber.cpp` (`storage_vectors`).
    fn storage_vectors() -> Vec<(&'static str, Vec<u8>, Storage, Vec<u8>)> {
        vec![
            ("1.0 is Double", vec![0x80, 0x00, 0x01], Storage::Double, vec![0x80, 0x00, 0x01]),
            ("2^72, 10-octet mantissa, is exact: Double", zeros(&[0x80, 0x00, 0x01], 9, &[]), Storage::Double, vec![0x80, 0x48, 0x01]),
            ("2^60+1 needs 61 bits: Binary, kept exactly",
             vec![0x80, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x01], Storage::Binary, vec![0x80, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x01]),
            ("Binary mantissa normalized odd, base 16 to base 2",
             vec![0xA0, 0x01, 0x20, 0, 0, 0, 0, 0, 0, 0x02], Storage::Binary, vec![0x80, 0x05, 0x10, 0, 0, 0, 0, 0, 0, 0x01]),
            ("2^1024: Binary", vec![0x81, 0x04, 0x00, 0x01], Storage::Binary, vec![0x81, 0x04, 0x00, 0x01]),
            ("-2^-1076: Binary", vec![0xC1, 0xFB, 0xCC, 0x01], Storage::Binary, vec![0xC1, 0xFB, 0xCC, 0x01]),
            ("exponent 2^31 in format d: Binary, 4 exponent octets",
             vec![0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01], Storage::Binary, vec![0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01]),
            ("NR2 14.56: Decimal, NR3 1456.E-2", ascii(0x02, "14.56"), Storage::Decimal, ascii(0x03, "1456.E-2")),
            ("NR1 100: Decimal, NR3 1.E2", ascii(0x01, "100"), Storage::Decimal, ascii(0x03, "1.E2")),
            ("NR1 -7: Decimal, NR3 -7.E+0", ascii(0x01, "-7"), Storage::Decimal, ascii(0x03, "-7.E+0")),
            ("NR3 0.0012E3 normalizes to 12.E-1", ascii(0x03, "0.0012E3"), Storage::Decimal, ascii(0x03, "12.E-1")),
            ("NR3 1E400: Decimal beyond the double range", ascii(0x03, "1E400"), Storage::Decimal, ascii(0x03, "1.E400")),
            ("X.680 pi {3141592653589793238462643383279, 10, -30}",
             ascii(0x03, "3141592653589793238462643383279E-30"), Storage::Decimal,
             ascii(0x03, "3141592653589793238462643383279.E-30")),
            ("NR1 000 is plus zero (Double)", ascii(0x01, "000"), Storage::Double, vec![]),
        ]
    }

    #[test]
    fn storage_classes_match_the_cpp_runtime() {
        for (label, contents, storage, reencoded) in storage_vectors() {
            let got = decode_real_value(&contents, 0).unwrap_or_else(|e| panic!("{label}: {}", e.message));
            assert_eq!(got.storage(), storage, "{label}");
            let mut out = Vec::new();
            encode_real_content(&mut out, &got);
            assert_eq!(out, reencoded, "{label}");
        }
    }

    #[test]
    fn decimal_and_binary_value_semantics() {
        let pi = decode_real_value(&ascii(0x03, "3141592653589793238462643383279E-30"), 0).unwrap();
        let x = pi.exact().unwrap();
        assert_eq!((pi.base(), x.mantissa.as_slice(), x.exponent), (10, b"3141592653589793238462643383279".as_slice(), -30));
        assert_eq!(pi.value(), 3.141592653589793);
        let dec = Real::decimal(false, "1456", -2);
        assert_ne!(dec, Real::new(14.56), "X.680 §20.5 NOTE 1");
        assert!(dec.numerically_equal(&Real::new(14.56)));
        assert_eq!(Real::decimal(false, "14560", -3), dec);
        assert_ne!(Real::decimal(true, "1456", -2), dec);
        assert_eq!(Real::binary(false, &[0x03], -1), Real::new(1.5));
        let mut r = dec.clone();
        r.set(2.0);
        assert_eq!((r.storage(), r), (Storage::Double, Real::new(2.0)));
    }

    #[test]
    fn tagged_rejects_the_natural_tag() {
        let mut buf = Vec::new();
        write_real(&mut buf, &Real::new(1.0)); // natural REAL_TAG
        let mut r = Reader::new(&buf);
        assert!(read_real_tagged(&mut r, Tag::context(5, false)).is_err());
    }
}
