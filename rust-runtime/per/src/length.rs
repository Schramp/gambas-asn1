//! Length-determinant and SIZE-field encoding shared by strings and (later)
//! SEQUENCE OF. Mirrors `per_detail::put_length`/`get_length` and
//! `encode_size_field`/`decode_size_field` (`runtime/src/PerCodec.cpp`).
//!
//! Fragmented lengths (X.691 §10.9, values needing more than 16383 octets)
//! aren't implemented — matches the C++ side's own scope exactly (it
//! returns a decode error for that case rather than supporting it).

use crate::constraints::Constraints;
use crate::reader::{DecodeError, Reader};
use crate::writer::Writer;

/// X.691 §10.9 general length determinant: short form (≤127, one octet) or
/// long form (≤16383, two octets with the top two bits as a 0b10 marker).
pub fn put_length(w: &mut Writer, n: usize) {
    if n <= 127 {
        w.put_bits(n as u64, 8);
    } else if n <= 16383 {
        w.put_bits(0x80 | (n as u64 >> 8), 8);
        w.put_bits(n as u64 & 0xFF, 8);
    }
    // n > 16383: matches the C++ side, which silently emits nothing for
    // this unimplemented case rather than a partial/corrupt encoding.
}

pub fn get_length(r: &mut Reader) -> Result<usize, DecodeError> {
    let first = r.get_bits(8)?;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    if first & 0xC0 == 0x80 {
        let second = r.get_bits(8)?;
        return Ok((((first & 0x3F) << 8) | second) as usize);
    }
    Err(DecodeError::new("PER: fragmented length not implemented", r.bit_pos()))
}

/// X.691 §10.5 (SIZE-constrained case) / §10.9 (unconstrained case). Fixed
/// SIZE (`size_range_bits == 0`): no bits written. Constrained: encode the
/// offset from the lower bound. Mirrors `encode_size_field` exactly.
pub fn encode_size_field(w: &mut Writer, pc: &Constraints, len: usize) {
    if pc.is_size_constrained() && pc.size_range_bits == 0 {
        // Fixed SIZE(n): no length field.
    } else if pc.is_size_constrained() {
        w.put_bits((len as i64 - pc.size_lower) as u64, pc.size_range_bits);
    } else {
        put_length(w, len);
    }
}

pub fn decode_size_field(r: &mut Reader, pc: &Constraints) -> Result<usize, DecodeError> {
    if pc.is_size_constrained() && pc.size_range_bits == 0 {
        Ok(pc.size_lower as usize)
    } else if pc.is_size_constrained() {
        let v = r.get_bits(pc.size_range_bits)?;
        Ok(v as usize + pc.size_lower as usize)
    } else {
        get_length(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_length(n: usize) -> usize {
        let mut w = Writer::new();
        put_length(&mut w, n);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        get_length(&mut r).unwrap()
    }

    #[test]
    fn short_and_long_form_roundtrip() {
        for n in [0usize, 1, 127, 128, 200, 16383] {
            assert_eq!(roundtrip_length(n), n);
        }
    }

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

    #[test]
    fn fixed_size_writes_nothing() {
        let pc = sized(5, 5);
        let mut w = Writer::new();
        encode_size_field(&mut w, &pc, 5);
        assert_eq!(w.bit_pos(), 0);
    }

    #[test]
    fn size_range_roundtrip() {
        let pc = sized(1, 8); // range_bits = 3
        for len in 1..=8usize {
            let mut w = Writer::new();
            encode_size_field(&mut w, &pc, len);
            w.flush();
            let bytes = w.into_bytes();
            let mut r = Reader::new(&bytes);
            assert_eq!(decode_size_field(&mut r, &pc).unwrap(), len);
        }
    }

    #[test]
    fn unconstrained_size_uses_length_determinant() {
        let pc = Constraints::default();
        let mut w = Writer::new();
        encode_size_field(&mut w, &pc, 200);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(decode_size_field(&mut r, &pc).unwrap(), 200);
    }

    // Cross-checked against a live encode_size_field()/decode_size_field()
    // call in runtime/src/PerCodec.cpp for the identical Constraints shape.
    #[test]
    fn matches_cpp_ground_truth() {
        let pc = sized(1, 8);
        let mut w = Writer::new();
        encode_size_field(&mut w, &pc, 5);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0b100_00000]); // 3 bits: (5-1)=4=0b100
    }
}
