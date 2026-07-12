//! Character-string type encode/decode — X.680 §41, X.690 §8.7 (same
//! primitive-octet-string shape OCTET STRING uses, just under each string
//! type's own universal tag).
//!
//! Mirrors `AsnStringBerHandler` (`runtime/src/BerCodec.cpp`): value octets
//! are the raw string bytes, no escaping at the BER layer (escaping is an
//! XER-only concern, see `xer.rs`). Scoped to `IA5String` for now
//! (gambas-asn1#282) — the other 11 string kinds share this exact shape,
//! differing only in universal tag number, so widening later is adding a
//! tag constant, not new logic.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const IA5_STRING_TAG: Tag = Tag::universal(universal::IA5_STRING, false);

pub fn write_ia5_string(out: &mut Vec<u8>, value: &str) {
    write_primitive(out, IA5_STRING_TAG, value.as_bytes());
}

pub fn read_ia5_string(r: &mut Reader) -> Result<String, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != IA5_STRING_TAG {
        return Err(DecodeError::new(format!("expected IA5String tag, got {:?}", tlv.tag), r.pos()));
    }
    String::from_utf8(tlv.value.to_vec())
        .map_err(|_| DecodeError::new("IA5String: invalid UTF-8".to_string(), r.pos()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ascii() {
        let mut buf = Vec::new();
        write_ia5_string(&mut buf, "hi");
        assert_eq!(buf, vec![0x16, 0x02, 0x68, 0x69]);
    }

    #[test]
    fn empty_string_round_trip() {
        let mut buf = Vec::new();
        write_ia5_string(&mut buf, "");
        let mut r = Reader::new(&buf);
        assert_eq!(read_ia5_string(&mut r).unwrap(), "");
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_ia5_string(&mut buf, "hello");
        let mut r = Reader::new(&buf);
        assert_eq!(read_ia5_string(&mut r).unwrap(), "hello");
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x04, 0x02, 0x68, 0x69]; // OCTET STRING tag, not IA5String
        let mut r = Reader::new(&data);
        assert!(read_ia5_string(&mut r).is_err());
    }
}
