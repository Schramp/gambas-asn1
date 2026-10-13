//! BIT STRING PER encode/decode (X.691 §16). Mirrors `BitStringPerHandler`
//! (`runtime/src/PerCodec.cpp`): the length field carries the *bit* count
//! (not the byte count), then each byte contributes its used bits MSB-first
//! (the last byte may be partial when `bit_count % 8 != 0`).
//!
//! Operates on raw `(&[u8], bit_count)`/`(Vec<u8>, unused_bits)`, not
//! `asn1cpp_ber::bit_string::BitString` — this crate has no BER dependency
//! (see `strings.rs`'s own doc for why); the generated `Constrained`
//! closure bridges to/from the real field type.

use crate::constraints::Constraints;
use crate::per::length::{decode_ext_size_and_items, encode_ext_size_and_items};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

/// `bit_count` is the logical length (`bytes.len() * 8 - unused_bits` in the
/// caller's own representation) — passed explicitly rather than derived
/// here, since this crate doesn't know the caller's unused-bits convention.
pub fn encode_bit_string(w: &mut Writer, pc: &Constraints, bytes: &[u8], bit_count: usize) {
    encode_ext_size_and_items(w, pc, bit_count, |w, range| {
        for i in range {
            w.put_bits(((bytes[i / 8] >> (7 - i % 8)) & 1) as u64, 1);
        }
    });
}

/// Returns `(bytes, unused_bits)` — the last byte is left-justified (unused
/// low bits zeroed), matching `asn1::BitString`'s own storage convention.
pub fn decode_bit_string(r: &mut Reader, pc: &Constraints) -> Result<(Vec<u8>, u8), DecodeError> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut nbits = 0usize;
    let bit_count = decode_ext_size_and_items(r, pc, |r, m| {
        for _ in 0..m {
            if nbits % 8 == 0 {
                bytes.push(0);
            }
            let bit = r.get_bits(1)? as u8;
            *bytes.last_mut().unwrap() |= bit << (7 - nbits % 8);
            nbits += 1;
        }
        Ok(())
    })?;
    if bit_count == 0 {
        return Ok((Vec::new(), 0));
    }
    let unused = ((8 - bit_count % 8) % 8) as u8;
    Ok((bytes, unused))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(pc: &Constraints, bytes: &[u8], bit_count: usize) -> (Vec<u8>, u8) {
        let mut w = Writer::new();
        encode_bit_string(&mut w, pc, bytes, bit_count);
        w.flush();
        let out = w.into_bytes();
        let mut r = Reader::new(&out);
        decode_bit_string(&mut r, pc).unwrap()
    }

    #[test]
    fn empty_roundtrip() {
        let pc = Constraints::default();
        assert_eq!(roundtrip(&pc, &[], 0), (Vec::new(), 0));
    }

    #[test]
    fn whole_bytes_roundtrip() {
        let pc = Constraints::default();
        assert_eq!(roundtrip(&pc, &[0xCA, 0xFE], 16), (vec![0xCA, 0xFE], 0));
    }

    #[test]
    fn partial_last_byte_roundtrip() {
        let pc = Constraints::default();
        // 12 bits: 0xFF, 0xF0 (top nibble of second byte used) -> unused_bits 4.
        assert_eq!(roundtrip(&pc, &[0xFF, 0xF0], 12), (vec![0xFF, 0xF0], 4));
    }

    /// Cross-checked against a live `PerCodec::instance().encode()` run
    /// through a real `Flags ::= BIT STRING (SIZE(0..16))` TypeDescriptor.
    #[test]
    fn matches_cpp_ground_truth() {
        let pc = Constraints {
            flags: crate::constraints::SIZE_CONSTRAINED,
            size_range_bits: 5,
            size_lower: 0,
            size_upper: 16,
            ..Default::default()
        };
        let mut w = Writer::new();
        encode_bit_string(&mut w, &pc, &[0xFF, 0xF0], 12);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x67, 0xff, 0x80]);

        let mut w2 = Writer::new();
        encode_bit_string(&mut w2, &pc, &[], 0);
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0x00]);
    }

    #[test]
    fn size_constrained_roundtrip() {
        let pc = Constraints {
            flags: crate::constraints::SIZE_CONSTRAINED,
            size_range_bits: 4,
            size_lower: 0,
            size_upper: 15,
            ..Default::default()
        };
        assert_eq!(roundtrip(&pc, &[0b1010_1000], 4), (vec![0b1010_0000], 4));
    }
}
