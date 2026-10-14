//! BIT STRING PER encode/decode (X.691 §16). Mirrors `BitStringPerHandler`
//! (`runtime/src/PerCodec.cpp`): the length field carries the *bit* count
//! (not the byte count), then each byte contributes its used bits MSB-first
//! (the last byte may be partial when `bit_count % 8 != 0`).
//!
//! Operates on raw `(&[u8], bit_count)`/`(Vec<u8>, unused_bits)`, not
//! `asn1cpp_ber::bit_string::BitString` — this crate has no BER dependency
//! (see `strings.rs`'s own doc for why); the generated `Constrained`
//! closure bridges to/from the real field type.

use crate::bit_string::significant_bits;
use crate::constraints::Constraints;
use crate::per::length::{decode_ext_size_and_items, encode_ext_size_and_items};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

/// `bit_count` is the logical length (`bytes.len() * 8 - unused_bits` in the
/// caller's own representation) — passed explicitly rather than derived
/// here, since this crate doesn't know the caller's unused-bits convention.
/// A NamedBitList type (`NAMED_BITS`) is sent with its trailing 0 bits
/// removed, then padded with 0 bits up to the SIZE lower bound (X.691
/// §15.2, §15.3).
pub fn encode_bit_string(w: &mut Writer, pc: &Constraints, bytes: &[u8], bit_count: usize) {
    let n = if pc.flags & crate::constraints::NAMED_BITS != 0 {
        significant_bits(bytes, bit_count).max(pc.size_lower.max(0) as usize)
    } else {
        bit_count
    };
    encode_ext_size_and_items(w, pc, n, |w, range| {
        for i in range {
            let bit = if i < bit_count { (bytes[i / 8] >> (7 - i % 8)) & 1 } else { 0 };
            w.put_bits(bit as u64, 1);
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

    fn encode(pc: &Constraints, bytes: &[u8], bit_count: usize) -> Vec<u8> {
        let mut w = Writer::new();
        encode_bit_string(&mut w, pc, bytes, bit_count);
        w.flush();
        w.into_bytes()
    }

    fn named(size_lower: i64, size_upper: i64, size_range_bits: u32) -> Constraints {
        Constraints {
            flags: crate::constraints::NAMED_BITS | crate::constraints::SIZE_CONSTRAINED,
            size_range_bits,
            size_lower,
            size_upper,
            ..Default::default()
        }
    }

    /// X.691 §15.2: no PER-visible constraint, trailing 0 bits removed —
    /// '01000000'B is sent as length 2, bits 01.
    #[test]
    fn named_bits_unconstrained_drops_trailing_zeros() {
        let pc = Constraints { flags: crate::constraints::NAMED_BITS, ..Default::default() };
        assert_eq!(encode(&pc, &[0x40], 8), vec![0x02, 0x40]);
        assert_eq!(encode(&pc, &[0x00], 8), vec![0x00]);
    }

    /// X.691 §15.3: SIZE(2..8) — '01000000'B trims to 2 bits = lb (length
    /// field 000); '1'B pads up to lb 2.
    #[test]
    fn named_bits_pad_to_size_lower_bound() {
        let pc = named(2, 8, 3);
        assert_eq!(encode(&pc, &[0x40], 8), vec![0b0000_1000]);
        assert_eq!(encode(&pc, &[0x80], 1), vec![0b0001_0000]);
        assert_eq!(roundtrip(&pc, &[0x40], 8), (vec![0x40], 6));
    }

    /// X.691 §15.8: fixed SIZE(8) — '01'B is padded to the full 8 bits.
    #[test]
    fn named_bits_fixed_size_pads_to_full_width() {
        let pc = named(8, 8, 0);
        assert_eq!(encode(&pc, &[0x40], 2), vec![0x40]);
        assert_eq!(encode(&pc, &[0x40, 0x00], 16), vec![0x40]);
    }

    /// Without NAMED_BITS the value is sent at its own length.
    #[test]
    fn plain_bit_string_keeps_trailing_zeros() {
        let pc = Constraints::default();
        assert_eq!(encode(&pc, &[0x40], 8), vec![0x08, 0x40]);
    }
}
