//! SEQUENCE encode/decode — X.680 §24, X.690 §8.9.
//!
//! No codegen or descriptor-table wiring yet (that's gambas-asn1#219) — this
//! is one hand-written example type proving the constructed-TLV mechanics
//! (`write_constructed`/nested `read_tlv` calls) work end to end: a
//! two-field SEQUENCE of two required INTEGERs, fields encoded/decoded in
//! declaration order inside one constructed TLV, no tagging beyond each
//! field's own natural universal tag (IMPLICIT/AUTOMATIC TAGS is future
//! codegen-wiring scope, not a core-primitive concern).

use crate::integer::{read_integer, write_integer};
use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_constructed;

pub const SEQUENCE_TAG: Tag = Tag::universal(universal::SEQUENCE, true);

/// `Point ::= SEQUENCE { x INTEGER, y INTEGER }`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Point {
    pub x: i64,
    pub y: i64,
}

impl Point {
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        write_integer(&mut content, self.x);
        write_integer(&mut content, self.y);
        let mut out = Vec::new();
        write_constructed(&mut out, SEQUENCE_TAG, &content);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Point, DecodeError> {
        let mut r = Reader::new(data);
        let tlv = r.read_tlv()?;
        if tlv.tag != SEQUENCE_TAG {
            return Err(DecodeError::new(format!("expected SEQUENCE tag, got {:?}", tlv.tag), 0));
        }
        let mut inner = Reader::new(tlv.value);
        let x = read_integer(&mut inner)?;
        let y = read_integer(&mut inner)?;
        Ok(Point { x, y })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_hand_computed_vector() {
        let p = Point { x: 1, y: 2 };
        // SEQUENCE (0x30), length 6, then two INTEGER TLVs (0x02 0x01 0x01, 0x02 0x01 0x02).
        assert_eq!(
            p.encode(),
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
        );
    }

    #[test]
    fn round_trips() {
        let p = Point { x: -5, y: 300 };
        let bytes = p.encode();
        assert_eq!(Point::decode(&bytes).unwrap(), p);
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x05]; // INTEGER tag, not SEQUENCE
        assert!(Point::decode(&data).is_err());
    }

    #[test]
    fn truncated_second_field_is_error() {
        // SEQUENCE containing only one INTEGER, second read must fail.
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        assert!(Point::decode(&data).is_err());
    }
}
