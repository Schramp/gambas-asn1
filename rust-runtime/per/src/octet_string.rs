//! OCTET STRING PER encode/decode (X.691 §17). Mirrors `OctetStringPerHandler`
//! (`runtime/src/PerCodec.cpp`): SIZE-constrained or unconstrained length
//! field (`length::encode_size_field`/`decode_size_field`), then raw bytes
//! as 8-bit fields — no alphabet, no per-byte constraint at all.
//!
//! Operates on raw `&[u8]`/`Vec<u8>`, not `asn1cpp_ber::octet_string::
//! OctetString` — this crate has no BER dependency (see `strings.rs`'s own
//! doc for why); the generated `Constrained` closure bridges to/from the
//! real field type, same pattern already used for character strings.

use crate::constraints::Constraints;
use crate::length::{decode_size_field, encode_size_field};
use crate::reader::{DecodeError, Reader};
use crate::writer::Writer;

pub fn encode_octet_string(w: &mut Writer, pc: &Constraints, bytes: &[u8]) {
    encode_size_field(w, pc, bytes.len());
    for b in bytes {
        w.put_bits(*b as u64, 8);
    }
}

pub fn decode_octet_string(r: &mut Reader, pc: &Constraints) -> Result<Vec<u8>, DecodeError> {
    let len = decode_size_field(r, pc)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(r.get_bits(8)? as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(pc: &Constraints, bytes: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        encode_octet_string(&mut w, pc, bytes);
        w.flush();
        let out = w.into_bytes();
        let mut r = Reader::new(&out);
        decode_octet_string(&mut r, pc).unwrap()
    }

    #[test]
    fn unconstrained_roundtrip() {
        let pc = Constraints::default();
        assert_eq!(roundtrip(&pc, &[0xDE, 0xAD, 0xBE, 0xEF]), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(roundtrip(&pc, &[]), Vec::<u8>::new());
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
        assert_eq!(roundtrip(&pc, &[1, 2, 3]), vec![1, 2, 3]);
        assert_eq!(roundtrip(&pc, &[]), Vec::<u8>::new());
    }

    /// Cross-checked against a live `PerCodec::instance().encode()` run
    /// through a real `Blob ::= OCTET STRING (SIZE(0..8))` TypeDescriptor.
    #[test]
    fn matches_cpp_ground_truth() {
        let pc = Constraints {
            flags: crate::constraints::SIZE_CONSTRAINED,
            size_range_bits: 4,
            size_lower: 0,
            size_upper: 8,
            ..Default::default()
        };
        let mut w = Writer::new();
        encode_octet_string(&mut w, &pc, &[0xDE, 0xAD, 0xBE]);
        w.flush();
        assert_eq!(w.into_bytes(), vec![0x3d, 0xea, 0xdb, 0xe0]);

        let mut w2 = Writer::new();
        encode_octet_string(&mut w2, &pc, &[]);
        w2.flush();
        assert_eq!(w2.into_bytes(), vec![0x00]);
    }

    #[test]
    fn fixed_size_no_length_field() {
        let pc = Constraints {
            flags: crate::constraints::SIZE_CONSTRAINED,
            size_range_bits: 0,
            size_lower: 3,
            size_upper: 3,
            ..Default::default()
        };
        let mut w = Writer::new();
        encode_octet_string(&mut w, &pc, &[9, 8, 7]);
        w.flush();
        // No length field: exactly 3 bytes, nothing more.
        assert_eq!(w.into_bytes(), vec![9, 8, 7]);
    }
}
