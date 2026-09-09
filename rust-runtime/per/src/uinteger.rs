//! Unsigned INTEGER PER encode/decode. Mirrors `UIntegerPerHandler`
//! (`runtime/src/PerCodec.cpp`) exactly — same structure as
//! [`crate::integer`]'s signed encode/decode, using the `lower_u64`/
//! `upper_u64` bounds instead.
//!
//! The unconstrained/out-of-root escape path reuses the *signed*
//! `encode_unconstrained_int`/`decode_unconstrained_int` primitives on the
//! `u64`'s raw bit pattern (`value as i64` / `result as u64`) rather than a
//! separate unsigned variant — not a bug, this is what the C++ handler does
//! too: `encode_unconstrained_int` represents an exact 64-bit pattern as
//! 2's-complement-minimal bytes regardless of whether the caller's logical
//! type is signed, and `decode_unconstrained_int`'s sign-extension-from-
//! top-bit reconstructs that exact pattern back — a `u64` bit pattern
//! round-trips through the signed primitive unchanged either way.

use crate::constraints::Constraints;
use crate::integer::{decode_unconstrained_int, encode_unconstrained_int};
use crate::reader::{DecodeError, Reader};
use crate::writer::Writer;

pub fn encode_uint(w: &mut Writer, pc: &Constraints, value: u64) {
    if pc.is_constrained() {
        if pc.is_extensible() {
            let in_root = value >= pc.lower_u64 && value <= pc.upper_u64;
            w.put_bits(if in_root { 0 } else { 1 }, 1);
            if !in_root {
                encode_unconstrained_int(w, value as i64);
                return;
            }
        }
        let encoded = value - pc.lower_u64;
        w.put_bits(encoded, pc.range_bits);
    } else if pc.is_semi_constrained() {
        if pc.is_extensible() {
            let in_root = value >= pc.lower_u64;
            w.put_bits(if in_root { 0 } else { 1 }, 1);
            if !in_root {
                encode_unconstrained_int(w, value as i64);
                return;
            }
        }
        encode_unconstrained_int(w, (value - pc.lower_u64) as i64);
    } else {
        encode_unconstrained_int(w, value as i64);
    }
}

pub fn decode_uint(r: &mut Reader, pc: &Constraints) -> Result<u64, DecodeError> {
    if pc.is_constrained() {
        if pc.is_extensible() {
            let ext = r.get_bits(1)?;
            if ext != 0 {
                return Ok(decode_unconstrained_int(r)? as u64);
            }
        }
        let bits = r.get_bits(pc.range_bits)?;
        Ok(bits + pc.lower_u64)
    } else if pc.is_semi_constrained() {
        if pc.is_extensible() {
            let ext = r.get_bits(1)?;
            if ext != 0 {
                return Ok(decode_unconstrained_int(r)? as u64);
            }
        }
        let adjusted = decode_unconstrained_int(r)? as u64;
        Ok(adjusted + pc.lower_u64)
    } else {
        Ok(decode_unconstrained_int(r)? as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constrained(lower: u64, upper: u64, extensible: bool) -> Constraints {
        let range = (upper - lower + 1) as f64;
        let range_bits = if range <= 1.0 { 0 } else { range.log2().ceil() as u32 };
        Constraints {
            flags: crate::constraints::CONSTRAINED
                | if extensible { crate::constraints::EXTENSIBLE } else { 0 },
            range_bits,
            lower_u64: lower,
            upper_u64: upper,
            ..Default::default()
        }
    }

    fn semi_constrained(lower: u64, extensible: bool) -> Constraints {
        Constraints {
            flags: crate::constraints::SEMI_CONSTRAINED
                | if extensible { crate::constraints::EXTENSIBLE } else { 0 },
            lower_u64: lower,
            ..Default::default()
        }
    }

    fn roundtrip(pc: &Constraints, value: u64) -> u64 {
        let mut w = Writer::new();
        encode_uint(&mut w, pc, value);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_uint(&mut r, pc).unwrap()
    }

    #[test]
    fn unconstrained_roundtrip() {
        let pc = Constraints::default();
        for v in [0u64, 1, 255, 256, u64::MAX / 2, u64::MAX] {
            assert_eq!(roundtrip(&pc, v), v);
        }
    }

    #[test]
    fn constrained_roundtrip() {
        let pc = constrained(0, 15, false);
        for v in 0..=15u64 {
            assert_eq!(roundtrip(&pc, v), v);
        }
    }

    #[test]
    fn constrained_extensible_out_of_root() {
        let pc = constrained(0, 15, true);
        assert_eq!(roundtrip(&pc, 5), 5);
        assert_eq!(roundtrip(&pc, 1000), 1000);
    }

    #[test]
    fn semi_constrained_roundtrip() {
        let pc = semi_constrained(0, false);
        for v in [0u64, 1, 1000, u64::MAX] {
            assert_eq!(roundtrip(&pc, v), v);
        }
    }

    #[test]
    fn semi_constrained_extensible() {
        let pc = semi_constrained(10, true);
        assert_eq!(roundtrip(&pc, 10), 10);
        assert_eq!(roundtrip(&pc, 1000), 1000);
    }

    #[test]
    fn near_u64_max_roundtrips_through_signed_primitive() {
        // Exercises the "bit pattern round-trips through the i64 primitive
        // even though it's logically unsigned and > i64::MAX" case this
        // module's own doc explains.
        let pc = Constraints::default();
        assert_eq!(roundtrip(&pc, u64::MAX), u64::MAX);
        assert_eq!(roundtrip(&pc, u64::MAX - 1), u64::MAX - 1);
        assert_eq!(roundtrip(&pc, (i64::MAX as u64) + 1), (i64::MAX as u64) + 1);
    }

    // Cross-checked against a real PerCodec::instance().encode() run through
    // per_uinteger_handler for the identical Constraints shape and value.
    #[test]
    fn matches_cpp_ground_truth() {
        let c = constrained(0, 15, false);
        assert_eq!(enc_bytes(&c, 5), vec![0x50]);

        let ce = constrained(0, 15, true);
        assert_eq!(enc_bytes(&ce, 100), vec![0x80, 0xb2, 0x00]);

        let s = semi_constrained(0, false);
        assert_eq!(enc_bytes(&s, 1000), vec![0x02, 0x03, 0xe8]);

        let u = Constraints::default();
        assert_eq!(enc_bytes(&u, 5), vec![0x01, 0x05]);
    }

    fn enc_bytes(pc: &Constraints, value: u64) -> Vec<u8> {
        let mut w = Writer::new();
        encode_uint(&mut w, pc, value);
        w.flush();
        w.into_bytes()
    }
}
