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
    write_primitive(out, BOOLEAN_TAG, &[if value { 0xFF } else { 0x00 }]);
}

pub fn read_boolean(r: &mut Reader) -> Result<bool, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != BOOLEAN_TAG {
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
}
