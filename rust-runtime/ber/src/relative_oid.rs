//! RELATIVE-OID encode/decode — X.680 §33, X.690 §8.20.
//!
//! Mirrors `asn1::RelativeOid`/`BerTraits<RelativeOid>`
//! (`runtime/include/asn1cpp/types/Oid.hpp`): like OBJECT IDENTIFIER
//! (`oid.rs`), a sequence of non-negative integer arcs, each base-128-
//! encoded (X.690 §8.20.2) — but *without* OID's first-two-arc combining
//! trick (X.680 §33 defines no such rule for RELATIVE-OID; every arc is
//! encoded individually).
//!
//! Its own type, not a reuse of `oid::ObjectIdentifier` or a plain
//! `Vec<u64>`: same "distinct type per ASN.1 kind" convention this crate
//! already follows everywhere else (`bit_string::BitString`, the 11
//! `strings.rs` newtypes, `oid::ObjectIdentifier` itself) — the C++ side
//! treats `Oid`/`RelativeOid` as separate classes with near-identical
//! bodies too, not one class plus a raw container. A bare `Vec<u64>` field
//! on a generated struct would also be ambiguous (could be any list of
//! numbers) where `RelativeOid` is self-documenting.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const RELATIVE_OID_TAG: Tag = Tag::universal(universal::RELATIVE_OID, false);

/// A RELATIVE-OID value: the decoded arc list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelativeOid(pub Vec<u64>);

/// Base-128 encode one arc (X.690 §8.20.2) — same shape as `oid::encode_arc`.
fn encode_arc(out: &mut Vec<u8>, mut arc: u64) {
    let mut tmp = [0u8; 10];
    let mut n = 0;
    loop {
        tmp[n] = (arc & 0x7F) as u8;
        n += 1;
        arc >>= 7;
        if arc == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        out.push(tmp[i] | if i > 0 { 0x80 } else { 0x00 });
    }
}

/// Decode one base-128 arc from `bytes`, advancing `idx` past it.
fn decode_arc(bytes: &[u8], idx: &mut usize) -> Result<u64, DecodeError> {
    let mut v: u64 = 0;
    for _ in 0..10 {
        if *idx >= bytes.len() {
            return Err(DecodeError::new("truncated RELATIVE-OID arc", 0));
        }
        let b = bytes[*idx];
        *idx += 1;
        v = (v << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(DecodeError::new("RELATIVE-OID arc overflow", 0))
}

pub fn write_relative_oid(out: &mut Vec<u8>, value: &RelativeOid) {
    write_relative_oid_tagged(out, RELATIVE_OID_TAG, value);
}

pub fn read_relative_oid(r: &mut Reader) -> Result<RelativeOid, DecodeError> {
    read_relative_oid_tagged(r, RELATIVE_OID_TAG)
}

/// gambas-asn1#332: IMPLICIT tag override — see `boolean::write_boolean_tagged`'s
/// doc comment for the general rationale.
pub fn write_relative_oid_tagged(out: &mut Vec<u8>, tag: Tag, value: &RelativeOid) {
    let mut val = Vec::new();
    for &arc in &value.0 {
        encode_arc(&mut val, arc);
    }
    write_primitive(out, tag, &val);
}

pub fn read_relative_oid_tagged(r: &mut Reader, tag: Tag) -> Result<RelativeOid, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected RELATIVE-OID tag, got {:?}", tlv.tag), r.pos()));
    }
    let bytes = tlv.value;
    let mut idx = 0usize;
    let mut arcs = Vec::new();
    while idx < bytes.len() {
        arcs.push(decode_arc(bytes, &mut idx)?);
    }
    Ok(RelativeOid(arcs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_arcs_individually_no_combining() {
        // Unlike OID, arc[0] and arc[1] are NOT combined into arc[0]*40+arc[1]
        // here — each arc gets its own base-128 group.
        let mut buf = Vec::new();
        write_relative_oid(&mut buf, &RelativeOid(vec![8571, 1]));
        assert_eq!(buf, vec![0x0D, 0x03, 0xC2, 0x7B, 0x01]);
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        let v = RelativeOid(vec![8571, 1]);
        write_relative_oid(&mut buf, &v);
        let mut r = Reader::new(&buf);
        assert_eq!(read_relative_oid(&mut r).unwrap(), v);
    }

    #[test]
    fn single_arc_round_trips_exactly() {
        // Unlike OID, a single-arc RELATIVE-OID has no ambiguity (no
        // first-two-arc combining to collapse it with a two-arc value).
        let mut buf = Vec::new();
        let v = RelativeOid(vec![2]);
        write_relative_oid(&mut buf, &v);
        assert_eq!(buf, vec![0x0D, 0x01, 0x02]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_relative_oid(&mut r).unwrap(), v);
    }

    #[test]
    fn empty_relative_oid_round_trips() {
        let mut buf = Vec::new();
        let v = RelativeOid::default();
        write_relative_oid(&mut buf, &v);
        assert_eq!(buf, vec![0x0D, 0x00]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_relative_oid(&mut r).unwrap(), v);
    }

    #[test]
    fn multi_byte_arc_round_trips() {
        let mut buf = Vec::new();
        let v = RelativeOid(vec![840113549, 1]);
        write_relative_oid(&mut buf, &v);
        let mut r = Reader::new(&buf);
        assert_eq!(read_relative_oid(&mut r).unwrap(), v);
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x00]; // INTEGER tag, not RELATIVE-OID
        let mut r = Reader::new(&data);
        assert!(read_relative_oid(&mut r).is_err());
    }

    #[test]
    fn truncated_arc_is_error() {
        let data = [0x0D, 0x01, 0x86]; // continuation bit set, no following byte
        let mut r = Reader::new(&data);
        assert!(read_relative_oid(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_5 = Tag::context(5, false);
        let mut buf = Vec::new();
        let v = RelativeOid(vec![2, 3]);
        write_relative_oid_tagged(&mut buf, context_5, &v);
        assert_eq!(buf, vec![0x85, 0x02, 0x02, 0x03]); // context primitive 5, not 0x0D
        let mut r = Reader::new(&buf);
        assert_eq!(read_relative_oid_tagged(&mut r, context_5).unwrap(), v);
    }

    #[test]
    fn tagged_rejects_the_natural_tag() {
        let mut buf = Vec::new();
        write_relative_oid(&mut buf, &RelativeOid(vec![2, 3])); // natural tag
        let mut r = Reader::new(&buf);
        assert!(read_relative_oid_tagged(&mut r, Tag::context(5, false)).is_err());
    }
}
