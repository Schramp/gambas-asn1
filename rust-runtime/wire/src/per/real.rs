//! Generic PER REAL encode/decode — X.691 §16. Mirrors `RealPerHandler`
//! (`runtime/src/PerCodec.cpp`) exactly: not bit-packed like INTEGER/
//! ENUMERATED — the value's own BER content bytes (X.690 §8.5), length-
//! prefixed. X.691 §16.5: PLUS-ZERO encodes as a zero-length field,
//! since BER's own encoding of it has no content octets to reuse;
//! MINUS-ZERO is one content octet (0x43, X.690 §8.5.9), not
//! zero-length — `encode_real_content` is where that split lives, not
//! here (a previous version of this function special-cased `value ==
//! 0.0` directly, which is true for both signs of zero and silently
//! dropped MINUS-ZERO's sign; see its own call site below).

use crate::per::length::{get_length, put_length};
use crate::per::reader::{DecodeError, Reader};
use crate::per::writer::Writer;

pub fn encode_real(w: &mut Writer, value: f64) {
    // Not `if value == 0.0` -- that's true for both +0.0 and -0.0, and
    // -0.0's BER content is the single octet 0x43, not empty (see
    // encode_real_content's own doc). Always go through the general
    // content encoder so the length prefix matches what was actually
    // written, even when that's zero bytes for PLUS-ZERO.
    let mut content = Vec::new();
    crate::real::encode_real_content(&mut content, value);
    put_length(w, content.len());
    for b in content {
        w.put_bits(b as u64, 8);
    }
}

pub fn decode_real(r: &mut Reader) -> Result<f64, DecodeError> {
    let len = get_length(r)?;
    if len == 0 {
        return Ok(0.0);
    }
    let mut content = Vec::with_capacity(len);
    for _ in 0..len {
        content.push(r.get_bits(8)? as u8);
    }
    crate::real::decode_real_value(&content, r.bit_pos())
        .map_err(|e| DecodeError::new(e.message, r.bit_pos()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: f64) -> f64 {
        let mut w = Writer::new();
        encode_real(&mut w, v);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        decode_real(&mut r).unwrap()
    }

    #[test]
    fn zero_is_a_zero_length_field() {
        let mut w = Writer::new();
        encode_real(&mut w, 0.0);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x00]);
        assert_eq!(roundtrip(0.0), 0.0);
    }

    #[test]
    fn minus_zero_is_one_content_octet_and_keeps_its_sign() {
        let mut w = Writer::new();
        encode_real(&mut w, -0.0);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x01, 0x43]);
        let got = roundtrip(-0.0);
        assert_eq!(got, 0.0);
        assert!(got.is_sign_negative());
    }

    #[test]
    fn nonzero_values_round_trip() {
        for v in [1.0, -1.0, 0.5, 3.14159, -273.15, 1e100, 1e-100] {
            assert_eq!(roundtrip(v), v);
        }
    }

    #[test]
    fn length_prefix_matches_the_ber_content_byte_count() {
        // 1.5's BER content (X.690 §8.5, real.rs's own encode_real_content):
        // 0x80 (base-2, positive), 0xFF (exponent -1, signed byte), 0x03
        // (mantissa 3) — 3 content bytes, so PER's length prefix is 3.
        let mut w = Writer::new();
        encode_real(&mut w, 1.5);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x03, 0x80, 0xFF, 0x03]);
    }
}
