//! BOOLEAN encode/decode — X.680 §22, X.690 §8.2.
//!
//! Mirrors `BerTraits<Boolean>`/`BooleanBerHandler`
//! (`runtime/include/asn1cpp/types/Boolean.hpp`,
//! `runtime/src/BerCodec.cpp`): DER-strict on encode (`FALSE` = `0x00`,
//! `TRUE` = `0xFF`), BER-lenient on decode (any nonzero byte is `TRUE`).

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const BOOLEAN_TAG: Tag = Tag::universal(universal::BOOLEAN, false);

pub fn write_boolean(out: &mut Vec<u8>, value: bool) {
    write_boolean_tagged(out, BOOLEAN_TAG, value);
}

pub fn read_boolean(r: &mut Reader) -> Result<bool, DecodeError> {
    read_boolean_tagged(r, BOOLEAN_TAG)
}

/// gambas-asn1#332: IMPLICIT tag override. A member declared with its own
/// `[n]` context/application/private tag (or an AUTOMATIC TAGS-assigned
/// one) replaces BOOLEAN's natural universal tag entirely on the wire
/// (X.690 §8.14, IMPLICIT tagging) — same content bytes, different tag
/// octets. `write_boolean`/`read_boolean` above are the natural-tag case
/// (`tag == BOOLEAN_TAG`); codegen calls this directly, with the member's
/// real resolved tag, whenever one applies (`RustBackend`'s per-member
/// closure emission, `emit_sequence_definition`).
pub fn write_boolean_tagged(out: &mut Vec<u8>, tag: Tag, value: bool) {
    write_primitive(out, tag, &[if value { 0xFF } else { 0x00 }]);
}

pub fn read_boolean_tagged(r: &mut Reader, tag: Tag) -> Result<bool, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected BOOLEAN tag, got {:?}", tlv.tag), r.pos()));
    }
    if tlv.value.is_empty() {
        return Err(DecodeError::new("BOOLEAN: empty value".to_string(), r.pos()));
    }
    Ok(tlv.value[0] != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_der_strict() {
        let mut buf = Vec::new();
        write_boolean(&mut buf, true);
        assert_eq!(buf, vec![0x01, 0x01, 0xFF]);

        buf.clear();
        write_boolean(&mut buf, false);
        assert_eq!(buf, vec![0x01, 0x01, 0x00]);
    }

    #[test]
    fn decodes_any_nonzero_as_true() {
        let data = [0x01, 0x01, 0x2A]; // BER-lenient: nonzero, not just 0xFF
        let mut r = Reader::new(&data);
        assert!(read_boolean(&mut r).unwrap());
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_boolean(&mut buf, true);
        let mut r = Reader::new(&buf);
        assert!(read_boolean(&mut r).unwrap());
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x00]; // INTEGER tag, not BOOLEAN
        let mut r = Reader::new(&data);
        assert!(read_boolean(&mut r).is_err());
    }

    #[test]
    fn empty_value_is_error() {
        let data = [0x01, 0x00];
        let mut r = Reader::new(&data);
        assert!(read_boolean(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_5 = Tag::context(5, false);
        let mut buf = Vec::new();
        write_boolean_tagged(&mut buf, context_5, true);
        assert_eq!(buf, vec![0x85, 0x01, 0xFF]); // context primitive 5, not 0x01 (universal BOOLEAN)
        let mut r = Reader::new(&buf);
        assert!(read_boolean_tagged(&mut r, context_5).unwrap());
    }

    #[test]
    fn tagged_rejects_the_natural_tag() {
        let mut buf = Vec::new();
        write_boolean(&mut buf, true); // natural BOOLEAN_TAG
        let mut r = Reader::new(&buf);
        assert!(read_boolean_tagged(&mut r, Tag::context(5, false)).is_err());
    }
}
