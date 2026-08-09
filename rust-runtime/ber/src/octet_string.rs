//! OCTET STRING encode/decode — X.680 §22, X.690 §8.7.
//!
//! The value octets *are* the encoding — no length/sign massaging like
//! INTEGER needs.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const OCTET_STRING_TAG: Tag = Tag::universal(universal::OCTET_STRING, false);

pub fn write_octet_string(out: &mut Vec<u8>, value: &[u8]) {
    write_octet_string_tagged(out, OCTET_STRING_TAG, value);
}

pub fn read_octet_string<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], DecodeError> {
    read_octet_string_tagged(r, OCTET_STRING_TAG)
}

/// IMPLICIT tag override — see `boolean::write_boolean_tagged`'s
/// doc for the general rationale (X.690 §8.14). Same raw value octets,
/// different tag octets.
pub fn write_octet_string_tagged(out: &mut Vec<u8>, tag: Tag, value: &[u8]) {
    write_primitive(out, tag, value);
}

pub fn read_octet_string_tagged<'a>(r: &mut Reader<'a>, tag: Tag) -> Result<&'a [u8], DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(
            format!("expected OCTET STRING tag, got {:?}", tlv.tag),
            r.pos(),
        ));
    }
    Ok(tlv.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value() {
        let mut buf = Vec::new();
        write_octet_string(&mut buf, &[]);
        assert_eq!(buf, vec![0x04, 0x00]);
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_octet_string(&mut buf, b"hi");
        assert_eq!(buf, vec![0x04, 0x02, 0x68, 0x69]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_octet_string(&mut r).unwrap(), b"hi");
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x05]; // INTEGER tag, not OCTET STRING
        let mut r = Reader::new(&data);
        assert!(read_octet_string(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_2 = Tag::context(2, false);
        let mut buf = Vec::new();
        write_octet_string_tagged(&mut buf, context_2, b"hi");
        assert_eq!(buf, vec![0x82, 0x02, 0x68, 0x69]); // context primitive 2, not 0x04
        let mut r = Reader::new(&buf);
        assert_eq!(read_octet_string_tagged(&mut r, context_2).unwrap(), b"hi");
    }
}
