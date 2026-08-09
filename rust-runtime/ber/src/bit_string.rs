//! BIT STRING encode/decode — X.680 §21, X.690 §8.6.
//!
//! Mirrors `asn1::BitString`/`BitStringBerHandler`
//! (`runtime/include/asn1cpp/types/BitString.hpp`, `runtime/src/BerCodec.cpp`):
//! raw payload bytes plus an unused-bits count (0-7) for the last byte. Not a
//! `Vec<u8>` newtype like OCTET STRING/the restricted-character-string kinds
//! — `Vec<u8>` alone can't carry the unused-bits count, and even if it
//! could, `RustBackend::native_builtin_type` already maps OCTET STRING to
//! plain `Vec<u8>`, so a second, different `Asn1Value`
//! impl for the same concrete type would conflict (Rust allows only one
//! trait impl per concrete type — same reasoning `strings.rs`'s module doc
//! gives for the 11 restricted-character-string newtypes).

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const BIT_STRING_TAG: Tag = Tag::universal(universal::BIT_STRING, false);

/// A BIT STRING value. `bytes` excludes the BER unused-bits prefix byte —
/// same split as `asn1::BitString::bytes()`/`unused_bits()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BitString {
    pub bytes: Vec<u8>,
    pub unused_bits: u8,
}

impl BitString {
    /// Logical bit length: `bytes.len()*8 - unused_bits`. Mirrors
    /// `asn1::BitString::bit_count()`.
    pub fn bit_count(&self) -> usize {
        if self.bytes.is_empty() {
            0
        } else {
            self.bytes.len() * 8 - self.unused_bits as usize
        }
    }
}

pub fn write_bit_string(out: &mut Vec<u8>, value: &BitString) {
    write_bit_string_tagged(out, BIT_STRING_TAG, value);
}

pub fn read_bit_string(r: &mut Reader) -> Result<BitString, DecodeError> {
    read_bit_string_tagged(r, BIT_STRING_TAG)
}

/// IMPLICIT tag override — see `boolean::write_boolean_tagged`'s
/// doc comment for the general rationale.
pub fn write_bit_string_tagged(out: &mut Vec<u8>, tag: Tag, value: &BitString) {
    let mut val = Vec::with_capacity(1 + value.bytes.len());
    val.push(value.unused_bits);
    val.extend_from_slice(&value.bytes);
    write_primitive(out, tag, &val);
}

pub fn read_bit_string_tagged(r: &mut Reader, tag: Tag) -> Result<BitString, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected BIT STRING tag, got {:?}", tlv.tag), r.pos()));
    }
    if tlv.value.is_empty() {
        return Err(DecodeError::new(
            "BIT STRING: empty value (need at least unused-bits byte)".to_string(),
            r.pos(),
        ));
    }
    let unused = tlv.value[0];
    if unused > 7 {
        return Err(DecodeError::new(
            format!("BIT STRING unused bits out of range: {unused}"),
            r.pos(),
        ));
    }
    Ok(BitString { bytes: tlv.value[1..].to_vec(), unused_bits: unused })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_value_with_unused_bits_prefix() {
        let mut buf = Vec::new();
        write_bit_string(&mut buf, &BitString { bytes: vec![0b1010_1000], unused_bits: 4 });
        assert_eq!(buf, vec![0x03, 0x02, 0x04, 0b1010_1000]);
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        let v = BitString { bytes: vec![0xCA, 0xFE], unused_bits: 0 };
        write_bit_string(&mut buf, &v);
        let mut r = Reader::new(&buf);
        assert_eq!(read_bit_string(&mut r).unwrap(), v);
    }

    #[test]
    fn empty_bit_string_round_trips() {
        let mut buf = Vec::new();
        let v = BitString::default();
        write_bit_string(&mut buf, &v);
        assert_eq!(buf, vec![0x03, 0x01, 0x00]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_bit_string(&mut r).unwrap(), v);
    }

    #[test]
    fn bit_count_accounts_for_unused_bits() {
        assert_eq!(BitString { bytes: vec![0xFF, 0xF0], unused_bits: 4 }.bit_count(), 12);
        assert_eq!(BitString::default().bit_count(), 0);
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x00]; // INTEGER tag, not BIT STRING
        let mut r = Reader::new(&data);
        assert!(read_bit_string(&mut r).is_err());
    }

    #[test]
    fn empty_value_is_error() {
        let data = [0x03, 0x00]; // no unused-bits byte at all
        let mut r = Reader::new(&data);
        assert!(read_bit_string(&mut r).is_err());
    }

    #[test]
    fn unused_bits_out_of_range_is_error() {
        let data = [0x03, 0x02, 0x08, 0xFF]; // 8 is out of the valid 0-7 range
        let mut r = Reader::new(&data);
        assert!(read_bit_string(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_5 = Tag::context(5, false);
        let mut buf = Vec::new();
        let v = BitString { bytes: vec![0xFF], unused_bits: 0 };
        write_bit_string_tagged(&mut buf, context_5, &v);
        assert_eq!(buf, vec![0x85, 0x02, 0x00, 0xFF]); // context primitive 5, not 0x03
        let mut r = Reader::new(&buf);
        assert_eq!(read_bit_string_tagged(&mut r, context_5).unwrap(), v);
    }

    #[test]
    fn tagged_rejects_the_natural_tag() {
        let mut buf = Vec::new();
        write_bit_string(&mut buf, &BitString::default()); // natural BIT_STRING_TAG
        let mut r = Reader::new(&buf);
        assert!(read_bit_string_tagged(&mut r, Tag::context(5, false)).is_err());
    }
}
