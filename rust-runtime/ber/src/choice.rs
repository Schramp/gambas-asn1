//! CHOICE encode/decode — X.680 §29, X.690 §8.13.
//!
//! No codegen wiring yet (gambas-asn1#219) — one hand-written example enum
//! proving tag-dispatch decode works: a CHOICE is untagged at the outer
//! level (X.690 §8.13.1 — "the value is that of the chosen alternative"),
//! so decode must peek the wire tag and match it against each alternative's
//! *own* natural tag to find which variant to decode. Both alternatives
//! here have distinct natural universal tags (INTEGER vs OCTET STRING) —
//! same principle CHOICE-with-a-context-tagged-alternative would use, just
//! without needing an EXPLICIT/IMPLICIT wrapper on top (that's
//! Generator::compute_member_tag's job on the C++/codegen side, out of
//! scope for this standalone crate).

use crate::integer::{read_integer, write_integer, INTEGER_TAG};
use crate::octet_string::{read_octet_string, write_octet_string, OCTET_STRING_TAG};
use crate::reader::{DecodeError, Reader};

/// `Choice ::= CHOICE { num INTEGER, data OCTET STRING }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Num(i64),
    Data(Vec<u8>),
}

impl Choice {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Choice::Num(n) => write_integer(&mut out, *n),
            Choice::Data(d) => write_octet_string(&mut out, d),
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Choice, DecodeError> {
        let mut r = Reader::new(data);
        let tag = r
            .peek_tag()
            .ok_or_else(|| DecodeError::new("empty CHOICE input", 0))?;
        if tag == INTEGER_TAG {
            Ok(Choice::Num(read_integer(&mut r)?))
        } else if tag == OCTET_STRING_TAG {
            Ok(Choice::Data(read_octet_string(&mut r)?.to_vec()))
        } else {
            Err(DecodeError::new(format!("unrecognized CHOICE alternative tag {:?}", tag), 0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_num_alternative() {
        assert_eq!(Choice::Num(5).encode(), vec![0x02, 0x01, 0x05]);
    }

    #[test]
    fn encodes_data_alternative() {
        assert_eq!(Choice::Data(vec![1, 2, 3]).encode(), vec![0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn round_trips_both_alternatives() {
        for c in [Choice::Num(-42), Choice::Data(vec![0xAA, 0xBB])] {
            let bytes = c.encode();
            assert_eq!(Choice::decode(&bytes).unwrap(), c);
        }
    }

    #[test]
    fn unrecognized_tag_is_error() {
        let data = [0x30, 0x00]; // SEQUENCE tag — not a Choice alternative
        assert!(Choice::decode(&data).is_err());
    }

    #[test]
    fn empty_input_is_error() {
        assert!(Choice::decode(&[]).is_err());
    }
}
