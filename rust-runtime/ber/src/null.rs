//! NULL encode/decode — X.680 §23, X.690 §8.8.
//!
//! Mirrors `BerTraits<Null>`/`NullBerHandler`
//! (`runtime/include/asn1cpp/types/Null.hpp`, `runtime/src/BerCodec.cpp`):
//! NULL carries no data — the value field is always empty.
//! `RustBackend::native_builtin_type` maps ASN.1 NULL to Rust's unit type
//! `()`, so this impl lives on `()` itself (`value.rs`), not a newtype —
//! there's nothing to wrap.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const NULL_TAG: Tag = Tag::universal(universal::NULL, false);

pub fn write_null(out: &mut Vec<u8>) {
    write_null_tagged(out, NULL_TAG);
}

pub fn read_null(r: &mut Reader) -> Result<(), DecodeError> {
    read_null_tagged(r, NULL_TAG)
}

/// gambas-asn1#332: IMPLICIT tag override — see `boolean::write_boolean_tagged`'s
/// doc comment for the general rationale. NULL's own natural tag never
/// substitutes any content bytes (there are none), so this differs from
/// every other `*_tagged` primitive only in writing an empty value.
pub fn write_null_tagged(out: &mut Vec<u8>, tag: Tag) {
    write_primitive(out, tag, &[]);
}

pub fn read_null_tagged(r: &mut Reader, tag: Tag) -> Result<(), DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected NULL tag, got {:?}", tlv.tag), r.pos()));
    }
    if !tlv.value.is_empty() {
        return Err(DecodeError::new("NULL: expected empty value".to_string(), r.pos()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_empty_value() {
        let mut buf = Vec::new();
        write_null(&mut buf);
        assert_eq!(buf, vec![0x05, 0x00]);
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_null(&mut buf);
        let mut r = Reader::new(&buf);
        assert!(read_null(&mut r).is_ok());
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x00]; // INTEGER tag, not NULL
        let mut r = Reader::new(&data);
        assert!(read_null(&mut r).is_err());
    }

    #[test]
    fn non_empty_value_is_error() {
        let data = [0x05, 0x01, 0x00]; // NULL tag but a stray value byte
        let mut r = Reader::new(&data);
        assert!(read_null(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_5 = Tag::context(5, false);
        let mut buf = Vec::new();
        write_null_tagged(&mut buf, context_5);
        assert_eq!(buf, vec![0x85, 0x00]); // context primitive 5, not 0x05 (universal NULL)
        let mut r = Reader::new(&buf);
        assert!(read_null_tagged(&mut r, context_5).is_ok());
    }

    #[test]
    fn tagged_rejects_the_natural_tag() {
        let mut buf = Vec::new();
        write_null(&mut buf); // natural NULL_TAG
        let mut r = Reader::new(&buf);
        assert!(read_null_tagged(&mut r, Tag::context(5, false)).is_err());
    }
}
