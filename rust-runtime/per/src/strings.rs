//! Known-multiplier character string PER encode/decode (X.691 §26.5), core
//! path: SIZE-constrained or unconstrained length, natural (non-FROM)
//! alphabet, no extensibility. Mirrors `StringPerHandler`
//! (`runtime/src/PerCodec.cpp`) for that subset.
//!
//! FROM-alphabet remapping (`encode_table`/`alphabet_bits`) and the
//! extensible out-of-root open-type escape are separate follow-up phases —
//! not implemented here yet.
//!
//! Operates on raw bytes, not `&str`: for `bpc > 1` (BMPString/
//! UniversalString), each code point is `bpc` bytes with a wide-char
//! encoding, same representation `AsnStringBase::str()` uses on the C++
//! side (a `std::string` holding raw encoded bytes, not necessarily valid
//! UTF-8). `bits`/`bpc` are supplied by the caller rather than looked up
//! from a tag number — this crate has no BER/tag dependency; the eventual
//! RustBackend codegen decides which (bits, bpc) pair a given string kind
//! uses, mirroring `string_params`'s table (`runtime/src/PerCodec.cpp`):
//! NumericString (4,1), PrintableString/VisibleString/UTCTime/
//! GeneralizedTime/Ia5String (7,1), BMPString (8,2), UniversalString (8,4),
//! default (8,1).

use crate::constraints::Constraints;
use crate::length::{decode_size_field, encode_size_field};
use crate::reader::{DecodeError, Reader};
use crate::writer::Writer;

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

pub fn encode_string(
    w: &mut Writer,
    pc: &Constraints,
    bits: u32,
    bpc: u32,
    natural: NaturalAlphabet,
    bytes: &[u8],
) -> Result<(), EncodeError> {
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

pub fn decode_string(
    r: &mut Reader,
    pc: &Constraints,
    bits: u32,
    bpc: u32,
) -> Result<Vec<u8>, DecodeError> {
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

    fn roundtrip(pc: &Constraints, bits: u32, bpc: u32, bytes: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        encode_string(&mut w, pc, bits, bpc, NaturalAlphabet::None, bytes).unwrap();
        w.flush();
        let out = w.into_bytes();
        let mut r = Reader::new(&out);
        decode_string(&mut r, pc, bits, bpc).unwrap()
    }

    #[test]
    fn numeric_string_roundtrip() {
        let pc = sized(1, 8);
        assert_eq!(roundtrip(&pc, 4, 1, b"12345"), b"12345");
    }

    #[test]
    fn ia5_string_roundtrip() {
        let pc = Constraints::default();
        assert_eq!(roundtrip(&pc, 7, 1, b"hello"), b"hello");
    }

    #[test]
    fn bmp_string_roundtrip() {
        // Wide chars: 2 bytes/codepoint, e.g. U+0041 'A' = 00 41.
        let pc = Constraints::default();
        let bytes = [0x00u8, 0x41, 0x00, 0x42];
        assert_eq!(roundtrip(&pc, 8, 2, &bytes), bytes);
    }

    #[test]
    fn size_violation_rejected() {
        let pc = sized(5, 5);
        let mut w = Writer::new();
        let err = encode_string(&mut w, &pc, 8, 1, NaturalAlphabet::None, b"abc").unwrap_err();
        assert!(err.message.contains("SIZE"));
    }

    #[test]
    fn numeric_alphabet_violation_rejected() {
        let pc = Constraints::default();
        let mut w = Writer::new();
        let err =
            encode_string(&mut w, &pc, 4, 1, NaturalAlphabet::Numeric, b"12a45").unwrap_err();
        assert!(err.message.contains("NumericString"));
    }

    #[test]
    fn ia5_alphabet_violation_rejected() {
        let pc = Constraints::default();
        let mut w = Writer::new();
        let err =
            encode_string(&mut w, &pc, 7, 1, NaturalAlphabet::Ia5, &[0xFF]).unwrap_err();
        assert!(err.message.contains("IA5String"));
    }

    // Cross-checked against a live PerCodec::instance().encode() run
    // through per_string_handler for the identical Constraints/type shape.
    #[test]
    fn matches_cpp_ground_truth() {
        let pc = sized(1, 8); // range_bits=3
        let mut w = Writer::new();
        encode_string(&mut w, &pc, 4, 1, NaturalAlphabet::Numeric, b"12345").unwrap();
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x84, 0x68, 0xac]);

        let unconstrained = Constraints::default();
        let mut w2 = Writer::new();
        encode_string(&mut w2, &unconstrained, 7, 1, NaturalAlphabet::Ia5, b"hello").unwrap();
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0x05, 0xd1, 0x97, 0x66, 0xcd, 0xe0]);

        let mut w3 = Writer::new();
        let ab = [0x00u8, 0x41, 0x00, 0x42];
        encode_string(&mut w3, &unconstrained, 8, 2, NaturalAlphabet::None, &ab).unwrap();
        w3.flush();
        assert_eq!(w3.into_bytes(), vec![0x02, 0x00, 0x41, 0x00, 0x42]);
    }
}
