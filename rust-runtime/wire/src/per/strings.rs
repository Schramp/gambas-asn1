//! Known-multiplier character string PER encode/decode (X.691 §26.5):
//! SIZE-constrained or unconstrained length, natural or FROM-restricted
//! alphabet. Mirrors `StringPerHandler` (`runtime/src/PerCodec.cpp`).
//!
//! FROM-alphabet remapping (X.691 §26.5.4/§26.5.7): each character is
//! written as its ordinal position in the declared alphabet subset
//! (`pc.alphabet_bits` wide) rather than its natural code point width —
//! `pc.encode_table`/`pc.alphabet` (`constraints.rs`) are the encode-
//! direction (`byte -> ordinal`) and decode-direction (`ordinal -> byte`)
//! tables, built by codegen from the schema's own `FROM (...)` clause.
//!
//! An extensible type (X.691 §26.4) adds an extension bit; a value
//! outside the extension root is encoded as if the type had neither a
//! size nor an alphabet constraint.
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
use crate::per::length::{decode_size_and_items, encode_size_and_items};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

pub use crate::encode_error::EncodeError;

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

/// `true` when `pc` carries a real FROM constraint this module can act on
/// (mirrors `StringPerHandler::encode`'s own `has_alpha` exactly: built-in
/// kinds may carry an `encode_table` for `validate()` alone with
/// `alphabet_bits == 0`, which must *not* trigger the remap path).
fn has_alphabet(pc: &Constraints) -> bool {
    pc.alphabet_bits > 0 && pc.encode_table.is_some()
}

pub fn encode_string(w: &mut Writer, pc: &Constraints, tag_num: u32, bytes: &[u8]) -> Result<(), EncodeError> {
    let (bits, bpc, natural) = string_params(tag_num);
    let char_count = bytes.len() / bpc as usize;
    let has_alpha = has_alphabet(pc);

    // X.691 §26.4: an extensible type adds one bit, 0 when the value is in
    // the extension root (size and, if present, alphabet), otherwise 1 and
    // the value is encoded as if neither constraint existed: the general
    // length and the type's own character width.
    if pc.is_extensible() && (pc.is_size_constrained() || has_alpha) {
        let size_ok = !pc.is_size_constrained()
            || (pc.size_lower..=pc.size_upper).contains(&(char_count as i64));
        let alpha_ok = !has_alpha || {
            let table = pc.encode_table.expect("has_alphabet already checked encode_table.is_some()");
            bytes.chunks(bpc as usize).all(|ch| {
                ch[..ch.len() - 1].iter().all(|&b| b == 0) && table[ch[ch.len() - 1] as usize] != 0xFFFF
            })
        };
        let in_root = size_ok && alpha_ok;
        w.put_bits(!in_root as u64, 1);
        if !in_root {
            return encode_string(w, &crate::constraints::UNCONSTRAINED, tag_num, bytes);
        }
    }

    if pc.is_size_constrained()
        && (char_count < pc.size_lower as usize || char_count > pc.size_upper as usize)
    {
        return Err(EncodeError::new("string length violates SIZE constraint"));
    }
    // X.691 §26.5.3/§26.5.6: the type-intrinsic natural-alphabet check only
    // applies with no FROM constraint — a FROM constraint replaces it with
    // membership in the declared subset (checked per-character below).
    if !has_alpha {
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
    }

    if has_alpha {
        // X.691 §26.5.4/§26.5.7: membership in the FROM alphabet is checked
        // for every character before anything is written, since the
        // fragment-aware writer below cannot fail part-way. For a
        // wide-char kind (bpc>1), every high byte must be 0x00 (Basic
        // Latin plane); the low byte is the alphabet index key.
        let table = pc.encode_table.expect("has_alphabet already checked encode_table.is_some()");
        for chunk in bytes.chunks(bpc as usize) {
            if chunk[..chunk.len() - 1].iter().any(|&b| b != 0) {
                return Err(EncodeError::new("codepoint outside Basic Latin in FROM alphabet"));
            }
            if table[chunk[chunk.len() - 1] as usize] == 0xFFFF {
                return Err(EncodeError::new("character not in FROM alphabet"));
            }
        }
    }

    let bpc_us = bpc as usize;
    encode_size_and_items(w, pc, char_count, |w, range| {
        let chars = &bytes[range.start * bpc_us..range.end * bpc_us];
        if has_alpha {
            let table = pc.encode_table.expect("checked above");
            for chunk in chars.chunks(bpc_us) {
                w.put_bits(table[chunk[chunk.len() - 1] as usize] as u64, pc.alphabet_bits);
            }
        } else if bpc > 1 {
            for &b in chars {
                w.put_bits(b as u64, 8);
            }
        } else if bits == 4 {
            for &c in chars {
                w.put_bits(encode_numeric_char(c) as u64, 4);
            }
        } else {
            for &c in chars {
                w.put_bits(c as u64, bits);
            }
        }
    })
}

pub fn decode_string(r: &mut Reader, pc: &Constraints, tag_num: u32) -> Result<Vec<u8>, DecodeError> {
    let (bits, bpc, _natural) = string_params(tag_num);
    let has_alpha = has_alphabet(pc);

    // X.691 §26.4 decode counterpart: out of root, decode as the
    // unconstrained type.
    if pc.is_extensible() && (pc.is_size_constrained() || has_alpha) && r.get_bits(1)? == 1 {
        return decode_string(r, &crate::constraints::UNCONSTRAINED, tag_num);
    }

    let mut result = Vec::new();
    decode_size_and_items(r, pc, |r, m| {
        result.reserve(m * bpc as usize);
        if has_alpha {
            // X.691 §26.5.4/§26.5.7 decode counterpart: read `alphabet_bits`,
            // look up the character via the decode-direction `alphabet` table.
            let alphabet = pc.alphabet.expect("has_alphabet implies a decode-direction table exists too");
            for _ in 0..m {
                let idx = r.get_bits(pc.alphabet_bits)? as usize;
                if idx >= pc.alphabet_size as usize {
                    return Err(DecodeError::new("PER: alphabet index out of range", r.bit_pos()));
                }
                result.extend(std::iter::repeat(0).take(bpc as usize - 1));
                result.push(alphabet[idx]);
            }
        } else if bpc > 1 {
            for _ in 0..m * bpc as usize {
                result.push(r.get_bits(8)? as u8);
            }
        } else if bits == 4 {
            for _ in 0..m {
                result.push(decode_numeric_char(r.get_bits(4)?));
            }
        } else {
            for _ in 0..m {
                result.push(r.get_bits(bits)? as u8);
            }
        }
        Ok(())
    })?;
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

    // FROM alphabet remapping (X.691 §26.5.4/§26.5.7) — mirrors
    // `Code ::= SEQUENCE { tag IA5String (FROM ("a"|"b"|"c")) }`
    // (tests/asn1/rust_alphabet_test.asn1): 3-character alphabet,
    // alphabet_bits = ceil(log2(3)) = 2.
    fn abc_alphabet() -> Constraints {
        static TABLE: [u16; 256] = {
            let mut t = [0xFFFFu16; 256];
            t[b'a' as usize] = 0;
            t[b'b' as usize] = 1;
            t[b'c' as usize] = 2;
            t
        };
        static ALPHABET: [u8; 3] = [b'a', b'b', b'c'];
        Constraints {
            alphabet_bits: 2,
            encode_table: Some(&TABLE),
            alphabet: Some(&ALPHABET),
            alphabet_size: 3,
            ..Default::default()
        }
    }

    #[test]
    fn from_alphabet_round_trips() {
        let pc = abc_alphabet();
        let mut w = Writer::new();
        encode_string(&mut w, &pc, TAG_IA5_STRING, b"cab").unwrap();
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(decode_string(&mut r, &pc, TAG_IA5_STRING).unwrap(), b"cab");
    }

    #[test]
    fn from_alphabet_uses_the_ordinal_bit_width_not_the_natural_one() {
        // Unconstrained length (3, one byte) then 'a'/'b'/'c' as ordinals
        // 0/1/2 in 2 bits each (6 bits, padded to one byte) — not
        // IA5String's natural 7 bits/char.
        let pc = abc_alphabet();
        let mut w = Writer::new();
        encode_string(&mut w, &pc, TAG_IA5_STRING, b"abc").unwrap();
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x03, 0b00_01_10_00]);
    }

    #[test]
    fn from_alphabet_violation_is_rejected() {
        let pc = abc_alphabet();
        let mut w = Writer::new();
        let err = encode_string(&mut w, &pc, TAG_IA5_STRING, b"abz").unwrap_err();
        assert!(err.message.contains("FROM alphabet"));
    }

    #[test]
    fn from_alphabet_decode_rejects_out_of_range_index() {
        let pc = abc_alphabet();
        let mut w = Writer::new();
        crate::per::length::encode_size_and_items(&mut w, &pc, 1, |_, _| {}).unwrap(); // 1 character
        w.put_bits(3, 2); // index 3 — one past the 3-entry alphabet
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert!(decode_string(&mut r, &pc, TAG_IA5_STRING).is_err());
    }

    fn ext_roundtrip(pc: &Constraints, value: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        encode_string(&mut w, pc, TAG_IA5_STRING, value).unwrap();
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(decode_string(&mut r, pc, TAG_IA5_STRING).unwrap(), value);
        bytes
    }

    #[test]
    fn extensible_size_in_root_and_out_of_root() {
        // IA5String (SIZE (1..4, ...)), X.691 §26.4.
        let mut pc = sized(1, 4);
        pc.flags |= crate::constraints::Constraints::EXTENSIBLE;
        // In root, "ab": ext 0, length-1 = 1 in 2 bits, two 7-bit chars.
        // 0 01 1100001 1100010 -> 0011 1000 0111 0001 0
        assert_eq!(ext_roundtrip(&pc, b"ab"), vec![0x38, 0x71, 0x00]);
        // Out of root, "abcde": ext 1, general length 5, five 7-bit chars.
        let b = ext_roundtrip(&pc, b"abcde");
        assert_eq!(b[0] >> 7, 1);
        assert_eq!((b[0] << 1) | (b[1] >> 7), 5);
    }

    #[test]
    fn extensible_alphabet_out_of_root_uses_the_natural_alphabet() {
        // A visible FROM ("abc") plus an extensible SIZE: "abz" is outside
        // the root (z not in FROM), so it goes out with the IA5 7-bit form.
        let mut pc = abc_alphabet();
        pc.flags |= crate::constraints::Constraints::EXTENSIBLE;
        let b = ext_roundtrip(&pc, b"abz");
        assert_eq!(b[0] >> 7, 1);
    }
}
