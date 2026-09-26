//! Known-multiplier character string PER encode/decode (X.691 §26.5), core
//! path: SIZE-constrained or unconstrained length, natural (non-FROM)
//! alphabet, no extensibility. Mirrors `StringPerHandler`
//! (`runtime/src/PerCodec.cpp`) for that subset.
//!
//! FROM-alphabet remapping (`encode_table`/`alphabet_bits`) and the
//! extensible out-of-root open-type escape are separate follow-up phases —
//! not implemented here yet.
//!
//! Operates on raw bytes, not `&str`: for a wide-char kind (BMPString/
//! UniversalString), each code point is 2/4 bytes with a wide-char
//! encoding, same representation `AsnStringBase::str()` uses on the C++
//! side (a `std::string` holding raw encoded bytes, not necessarily valid
//! UTF-8). `encode_string`/`decode_string` take the type's own universal
//! tag number and look up its (bits, bytes-per-char, natural alphabet) via
//! this module's own `string_params` table — not a `Tag`/enum reference
//! into `asn1cpp_ber` (this crate's declared independence from that one),
//! just the bare tag number the generated caller already has. Mirrors
//! `string_params` (`runtime/src/PerCodec.cpp`) exactly, so this table only
//! needs updating in one Rust-side place, not per call site.

use crate::constraints::Constraints;
use crate::per::length::{decode_size_field, encode_size_field};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

/// Encode failure — a constraint violation detected during encode (SIZE
/// range, natural-alphabet membership). Mirrors the *meaning* of
/// `PerEncodeStream::set_encode_failed`, as a `Result` rather than an
/// out-of-band flag on the stream — more idiomatic for a fresh Rust API
/// with no existing flag-based convention to match yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError {
    pub message: String,
}

impl EncodeError {
    pub fn new(message: impl Into<String>) -> EncodeError {
        EncodeError { message: message.into() }
    }
}

/// NumericString: space=0, '0'-'9'=1-10 (4 bits per character).
fn encode_numeric_char(c: u8) -> u8 {
    if c == b' ' {
        0
    } else if (b'0'..=b'9').contains(&c) {
        c - b'0' + 1
    } else {
        0
    }
}

fn decode_numeric_char(v: u64) -> u8 {
    if v == 0 {
        b' '
    } else if (1..=10).contains(&v) {
        b'0' + (v as u8 - 1)
    } else {
        b'?'
    }
}

/// `tag_is_numeric_string`/`tag_is_ia5_string`-style discriminants for the
/// two type-intrinsic natural-alphabet checks `StringPerHandler::encode`
/// performs when there's no FROM constraint (X.691 §26.5.3/§26.5.6).
/// Everything else has no narrower-than-`bits`-width natural alphabet to
/// validate against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NaturalAlphabet {
    Numeric,
    Ia5,
    None,
}

// X.680 §41 universal class tag numbers for the known-multiplier character
// string kinds this module covers — duplicated as plain integers (not a
// `Tag`/enum reference into `asn1cpp_ber`) to keep this crate's declared
// independence from that one (this crate's own top-level doc); the
// generated caller, which does link both crates, already has a `Tag`
// constant for its own kind and passes `.number` straight through.
const TAG_NUMERIC_STRING: u32 = 18;
const TAG_PRINTABLE_STRING: u32 = 19;
const TAG_IA5_STRING: u32 = 22;
const TAG_UTC_TIME: u32 = 23;
const TAG_GENERALIZED_TIME: u32 = 24;
const TAG_VISIBLE_STRING: u32 = 26;
const TAG_UNIVERSAL_STRING: u32 = 28;
const TAG_BMP_STRING: u32 = 30;

/// (bits, bytes-per-char, natural alphabet) for a known-multiplier
/// character string kind's own universal tag number, used only when the
/// type has no FROM constraint (X.691 §26.5). Mirrors `string_params`
/// (`runtime/src/PerCodec.cpp`) exactly — same table, same default arm for
/// every other single-byte kind (UTF8String, T61String, GeneralString,
/// GraphicString, VideotexString, ObjectDescriptor).
fn string_params(tag_num: u32) -> (u32, u32, NaturalAlphabet) {
    match tag_num {
        TAG_NUMERIC_STRING => (4, 1, NaturalAlphabet::Numeric),
        TAG_IA5_STRING => (7, 1, NaturalAlphabet::Ia5),
        TAG_PRINTABLE_STRING | TAG_VISIBLE_STRING | TAG_UTC_TIME | TAG_GENERALIZED_TIME => {
            (7, 1, NaturalAlphabet::None)
        }
        TAG_BMP_STRING => (8, 2, NaturalAlphabet::None),
        TAG_UNIVERSAL_STRING => (8, 4, NaturalAlphabet::None),
        _ => (8, 1, NaturalAlphabet::None),
    }
}

pub fn encode_string(w: &mut Writer, pc: &Constraints, tag_num: u32, bytes: &[u8]) -> Result<(), EncodeError> {
    let (bits, bpc, natural) = string_params(tag_num);
    let char_count = bytes.len() / bpc as usize;

    if pc.is_size_constrained()
        && (char_count < pc.size_lower as usize || char_count > pc.size_upper as usize)
    {
        return Err(EncodeError::new("string length violates SIZE constraint"));
    }
    match natural {
        NaturalAlphabet::Numeric => {
            for &c in bytes {
                if c != b' ' && !(b'0'..=b'9').contains(&c) {
                    return Err(EncodeError::new(
                        "character not in NumericString natural alphabet",
                    ));
                }
            }
        }
        NaturalAlphabet::Ia5 => {
            for &c in bytes {
                if c > 0x7F {
                    return Err(EncodeError::new(
                        "character not in IA5String natural alphabet",
                    ));
                }
            }
        }
        NaturalAlphabet::None => {}
    }

    encode_size_field(w, pc, char_count);
    if bpc > 1 {
        for &b in bytes {
            w.put_bits(b as u64, 8);
        }
    } else if bits == 4 {
        for &c in bytes {
            w.put_bits(encode_numeric_char(c) as u64, 4);
        }
    } else if bits == 7 {
        for &c in bytes {
            w.put_bits(c as u64, 7);
        }
    } else {
        for &c in bytes {
            w.put_bits(c as u64, 8);
        }
    }
    Ok(())
}

pub fn decode_string(r: &mut Reader, pc: &Constraints, tag_num: u32) -> Result<Vec<u8>, DecodeError> {
    let (bits, bpc, _natural) = string_params(tag_num);
    let char_count = decode_size_field(r, pc)?;
    let byte_count = char_count * bpc as usize;
    let mut result = Vec::with_capacity(byte_count);
    if bpc > 1 {
        for _ in 0..byte_count {
            result.push(r.get_bits(8)? as u8);
        }
    } else if bits == 4 {
        for _ in 0..char_count {
            result.push(decode_numeric_char(r.get_bits(4)?));
        }
    } else if bits == 7 {
        for _ in 0..char_count {
            result.push(r.get_bits(7)? as u8);
        }
    } else {
        for _ in 0..char_count {
            result.push(r.get_bits(8)? as u8);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sized(lower: i64, upper: i64) -> Constraints {
        let range = (upper - lower + 1) as f64;
        let range_bits = if range <= 1.0 { 0 } else { range.log2().ceil() as u32 };
        Constraints {
            flags: crate::constraints::SIZE_CONSTRAINED,
            size_range_bits: range_bits,
            size_lower: lower,
            size_upper: upper,
            ..Default::default()
        }
    }

    fn roundtrip(pc: &Constraints, tag_num: u32, bytes: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        encode_string(&mut w, pc, tag_num, bytes).unwrap();
        w.flush();
        let out = w.into_bytes();
        let mut r = Reader::new(&out);
        decode_string(&mut r, pc, tag_num).unwrap()
    }

    #[test]
    fn numeric_string_roundtrip() {
        let pc = sized(1, 8);
        assert_eq!(roundtrip(&pc, TAG_NUMERIC_STRING, b"12345"), b"12345");
    }

    #[test]
    fn ia5_string_roundtrip() {
        let pc = Constraints::default();
        assert_eq!(roundtrip(&pc, TAG_IA5_STRING, b"hello"), b"hello");
    }

    #[test]
    fn bmp_string_roundtrip() {
        // Wide chars: 2 bytes/codepoint, e.g. U+0041 'A' = 00 41.
        let pc = Constraints::default();
        let bytes = [0x00u8, 0x41, 0x00, 0x42];
        assert_eq!(roundtrip(&pc, TAG_BMP_STRING, &bytes), bytes);
    }

    #[test]
    fn universal_string_roundtrip() {
        // 4 bytes/codepoint, e.g. U+0041 'A' = 00 00 00 41.
        let pc = Constraints::default();
        let bytes = [0x00u8, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x42];
        assert_eq!(roundtrip(&pc, TAG_UNIVERSAL_STRING, &bytes), bytes);
    }

    #[test]
    fn default_arm_roundtrip() {
        // Any single-byte kind with no dedicated table entry (UTF8String,
        // T61String, GeneralString, GraphicString, VideotexString,
        // ObjectDescriptor) falls to string_params's (8, 1, None) default.
        let pc = Constraints::default();
        assert_eq!(roundtrip(&pc, /* Utf8String */ 12, b"hello"), b"hello");
    }

    #[test]
    fn size_violation_rejected() {
        let pc = sized(5, 5);
        let mut w = Writer::new();
        let err = encode_string(&mut w, &pc, TAG_IA5_STRING, b"abc").unwrap_err();
        assert!(err.message.contains("SIZE"));
    }

    #[test]
    fn numeric_alphabet_violation_rejected() {
        let pc = Constraints::default();
        let mut w = Writer::new();
        let err = encode_string(&mut w, &pc, TAG_NUMERIC_STRING, b"12a45").unwrap_err();
        assert!(err.message.contains("NumericString"));
    }

    #[test]
    fn ia5_alphabet_violation_rejected() {
        let pc = Constraints::default();
        let mut w = Writer::new();
        let err = encode_string(&mut w, &pc, TAG_IA5_STRING, &[0xFF]).unwrap_err();
        assert!(err.message.contains("IA5String"));
    }

    // Cross-checked against a live PerCodec::instance().encode() run
    // through per_string_handler for the identical Constraints/type shape.
    #[test]
    fn matches_cpp_ground_truth() {
        let pc = sized(1, 8); // range_bits=3
        let mut w = Writer::new();
        encode_string(&mut w, &pc, TAG_NUMERIC_STRING, b"12345").unwrap();
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x84, 0x68, 0xac]);

        let unconstrained = Constraints::default();
        let mut w2 = Writer::new();
        encode_string(&mut w2, &unconstrained, TAG_IA5_STRING, b"hello").unwrap();
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0x05, 0xd1, 0x97, 0x66, 0xcd, 0xe0]);

        let mut w3 = Writer::new();
        let ab = [0x00u8, 0x41, 0x00, 0x42];
        encode_string(&mut w3, &unconstrained, TAG_BMP_STRING, &ab).unwrap();
        w3.flush();
        assert_eq!(w3.into_bytes(), vec![0x02, 0x00, 0x41, 0x00, 0x42]);
    }
}
