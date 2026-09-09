//! Signed INTEGER PER encode/decode (X.691 §10.5 constrained whole number,
//! §10.6 semi-constrained, §10.8 unconstrained). Mirrors `IntegerPerHandler`
//! (`runtime/src/PerCodec.cpp`) exactly, including its extensible-marker
//! handling (X.691 §10.5.7.4/§10.6, out-of-root-range escape to the
//! unconstrained form).

use crate::constraints::Constraints;
use crate::reader::{DecodeError, Reader};
use crate::writer::Writer;

/// X.691 §10.8 "Encoding of an unconstrained whole number" — 2's-complement,
/// minimum octets, preceded by an 8-bit octet count.
pub fn encode_unconstrained_int(w: &mut Writer, value: i64) {
    let mut buf = [0u8; 8];
    let len;
    if value == 0 {
        buf[0] = 0;
        len = 1;
    } else {
        let mut u = value as u64;
        for i in (0..8).rev() {
            buf[i] = (u & 0xFF) as u8;
            u >>= 8;
        }
        let mut start = 0usize;
        if value > 0 {
            while start < 7 && buf[start] == 0x00 && (buf[start + 1] & 0x80) == 0 {
                start += 1;
            }
        } else {
            while start < 7 && buf[start] == 0xFF && (buf[start + 1] & 0x80) != 0 {
                start += 1;
            }
        }
        len = 8 - start;
        buf.copy_within(start..start + len, 0);
    }
    w.put_bits(len as u64, 8);
    for &byte in &buf[..len] {
        w.put_bits(byte as u64, 8);
    }
}

/// X.691 §10.8 — see [`encode_unconstrained_int`].
pub fn decode_unconstrained_int(r: &mut Reader) -> Result<i64, DecodeError> {
    let len = r.get_bits(8)? as usize;
    if len == 0 || len > 8 {
        return Err(DecodeError::new("PER: INTEGER length out of range", r.bit_pos()));
    }
    let mut value: i64 = 0;
    for i in 0..len {
        let b = r.get_bits(8)?;
        if i == 0 && (b & 0x80) != 0 {
            value = -1;
        }
        value = (value << 8) | b as i64;
    }
    Ok(value)
}

/// Full signed-INTEGER PER encode, matching `IntegerPerHandler::encode`'s
/// four cases (constrained/semi-constrained/unconstrained, each with an
/// optional extensible escape).
pub fn encode_int(w: &mut Writer, pc: &Constraints, value: i64) {
    if pc.is_constrained() {
        if pc.is_extensible() {
            let in_root = value >= pc.lower_bound && value <= pc.upper_bound;
            w.put_bits(if in_root { 0 } else { 1 }, 1);
            if !in_root {
                encode_unconstrained_int(w, value);
                return;
            }
        }
        // X.691 §10.5.7.1 UPER: value in [lb..ub] encoded in minimum bits, no length prefix.
        let encoded = (value - pc.lower_bound) as u64;
        w.put_bits(encoded, pc.range_bits);
    } else if pc.is_semi_constrained() {
        if pc.is_extensible() {
            let in_root = value >= pc.lower_bound;
            w.put_bits(if in_root { 0 } else { 1 }, 1);
            if !in_root {
                encode_unconstrained_int(w, value);
                return;
            }
        }
        encode_unconstrained_int(w, value - pc.lower_bound);
    } else {
        encode_unconstrained_int(w, value);
    }
}

/// Decode counterpart of [`encode_int`].
pub fn decode_int(r: &mut Reader, pc: &Constraints) -> Result<i64, DecodeError> {
    if pc.is_constrained() {
        if pc.is_extensible() {
            let ext = r.get_bits(1)?;
            if ext != 0 {
                return decode_unconstrained_int(r);
            }
        }
        let bits = r.get_bits(pc.range_bits)?;
        Ok(pc.lower_bound + bits as i64)
    } else if pc.is_semi_constrained() {
        if pc.is_extensible() {
            let ext = r.get_bits(1)?;
            if ext != 0 {
                return decode_unconstrained_int(r);
            }
        }
        let adjusted = decode_unconstrained_int(r)?;
        Ok(adjusted + pc.lower_bound)
    } else {
        decode_unconstrained_int(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constrained(lower: i64, upper: i64, extensible: bool) -> Constraints {
        let range = (upper - lower + 1) as f64;
        let range_bits = if range <= 1.0 { 0 } else { range.log2().ceil() as u32 };
        Constraints {
            flags: crate::constraints::CONSTRAINED
                | if extensible { crate::constraints::EXTENSIBLE } else { 0 },
            range_bits,
            lower_bound: lower,
            upper_bound: upper,
        }
    }

    fn semi_constrained(lower: i64, extensible: bool) -> Constraints {
        Constraints {
            flags: crate::constraints::SEMI_CONSTRAINED
                | if extensible { crate::constraints::EXTENSIBLE } else { 0 },
            range_bits: 0,
            lower_bound: lower,
            upper_bound: 0,
        }
    }

    fn roundtrip(pc: &Constraints, value: i64) -> i64 {
        let mut w = Writer::new();
        encode_int(&mut w, pc, value);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_int(&mut r, pc).unwrap()
    }

    #[test]
    fn unconstrained_roundtrip() {
        let pc = Constraints::default();
        for v in [0i64, 1, -1, 127, -128, 255, -256, i64::MAX, i64::MIN] {
            assert_eq!(roundtrip(&pc, v), v);
        }
    }

    #[test]
    fn constrained_small_range() {
        // INTEGER (0..15) — 4 bits, no length prefix.
        let pc = constrained(0, 15, false);
        assert_eq!(pc.range_bits, 4);
        for v in 0..=15 {
            assert_eq!(roundtrip(&pc, v), v);
        }
    }

    #[test]
    fn constrained_extensible_in_and_out_of_root() {
        let pc = constrained(0, 15, true);
        assert_eq!(roundtrip(&pc, 5), 5);
        assert_eq!(roundtrip(&pc, 100), 100); // out-of-root escape
        assert_eq!(roundtrip(&pc, -1), -1); // out-of-root escape
    }

    #[test]
    fn semi_constrained_roundtrip() {
        let pc = semi_constrained(0, false); // INTEGER (0..MAX)
        for v in [0i64, 1, 1000, i64::MAX] {
            assert_eq!(roundtrip(&pc, v), v);
        }
    }

    #[test]
    fn semi_constrained_extensible() {
        let pc = semi_constrained(10, true);
        assert_eq!(roundtrip(&pc, 10), 10);
        assert_eq!(roundtrip(&pc, 1000), 1000);
        assert_eq!(roundtrip(&pc, 5), 5); // below lower bound -> extension escape
    }

    // Every expected byte string below was cross-checked against a real,
    // live `PerCodec::instance().encode()` run through `per_integer_handler`
    // (runtime/src/PerCodec.cpp) for the identical Constraints shape and
    // value -- a throwaway C++ program built against the real runtime, not
    // hand-computed. All 15 cases matched byte-for-byte.
    #[test]
    fn matches_cpp_ground_truth() {
        let c = constrained(0, 15, false);
        assert_eq!(enc_bytes(&c, 5), vec![0x50]);
        assert_eq!(enc_bytes(&c, 0), vec![0x00]);
        assert_eq!(enc_bytes(&c, 15), vec![0xf0]);

        let ce = constrained(0, 15, true);
        assert_eq!(enc_bytes(&ce, 5), vec![0x28]);
        assert_eq!(enc_bytes(&ce, 100), vec![0x80, 0xb2, 0x00]);
        assert_eq!(enc_bytes(&ce, -1), vec![0x80, 0xff, 0x80]);

        let s = semi_constrained(0, false);
        assert_eq!(enc_bytes(&s, 0), vec![0x01, 0x00]);
        assert_eq!(enc_bytes(&s, 1), vec![0x01, 0x01]);
        assert_eq!(enc_bytes(&s, 1000), vec![0x02, 0x03, 0xe8]);

        let se = semi_constrained(10, true);
        assert_eq!(enc_bytes(&se, 10), vec![0x00, 0x80, 0x00]);
        assert_eq!(enc_bytes(&se, 1000), vec![0x01, 0x01, 0xef, 0x00]);
        assert_eq!(enc_bytes(&se, 5), vec![0x80, 0x82, 0x80]);

        let u = Constraints::default();
        assert_eq!(enc_bytes(&u, 5), vec![0x01, 0x05]);
        assert_eq!(enc_bytes(&u, 0), vec![0x01, 0x00]);
        assert_eq!(enc_bytes(&u, -1), vec![0x01, 0xff]);
    }

    fn enc_bytes(pc: &Constraints, value: i64) -> Vec<u8> {
        let mut w = Writer::new();
        encode_int(&mut w, pc, value);
        w.flush();
        w.into_bytes()
    }
}
