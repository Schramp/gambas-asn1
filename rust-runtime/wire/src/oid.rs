//! OBJECT IDENTIFIER encode/decode — X.680 §32, X.690 §8.19.
//!
//! Mirrors `asn1::Oid`/`BerTraits<Oid>`
//! (`runtime/include/asn1cpp/types/Oid.hpp`): a sequence of non-negative
//! integer arcs, with the first two arcs combined on the wire as
//! `first*40 + second` (X.680 §32.3) and every arc base-128-encoded
//! (X.690 §8.19.2).
//!
//! Not a `Vec<u64>` type alias — OBJECT IDENTIFIER and RELATIVE-OID have
//! different wire encodings (OID's first-two-arc combining trick,
//! RELATIVE-OID has none — X.680 §33), so they can't share one plain
//! `Vec<u64>` `Asn1Value` impl (Rust allows only one trait impl per
//! concrete type — same reasoning `bit_string.rs`'s module doc gives for
//! not reusing OCTET STRING's `Vec<u8>`). RELATIVE-OID gets its own
//! newtype too (`relative_oid::RelativeOid`), same "distinct type per
//! ASN.1 kind" convention as every other kind in this crate.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::writer::write_primitive;

pub const OBJECT_IDENTIFIER_TAG: Tag = Tag::universal(universal::OBJECT_IDENTIFIER, false);

/// An OBJECT IDENTIFIER value: the decoded arc list (already split into
/// individual arcs — the first-two-arc wire encoding is purely an encode/
/// decode-time concern, same split `asn1::Oid::arcs()` already makes).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectIdentifier(pub Vec<u64>);

/// Base-128 encode one arc (X.690 §8.19.2) — up to 10 groups, enough for a
/// full `u64` arc (`native_builtin_type`'s choice; `asn1::Oid` itself uses
/// `uint32_t` arcs and needs only 5).
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
            return Err(DecodeError::new("truncated OID arc", 0));
        }
        let b = bytes[*idx];
        *idx += 1;
        v = (v << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(DecodeError::new("OID arc overflow", 0))
}

pub fn write_object_identifier(out: &mut Vec<u8>, value: &ObjectIdentifier) {
    write_object_identifier_tagged(out, OBJECT_IDENTIFIER_TAG, value);
}

pub fn read_object_identifier(r: &mut Reader) -> Result<ObjectIdentifier, DecodeError> {
    read_object_identifier_tagged(r, OBJECT_IDENTIFIER_TAG)
}

/// Content octets only (X.690 §8.19): base-128 arc encoding, first two arcs
/// combined per the OID-specific `X*40+Y` rule.
pub(crate) fn encode_object_identifier_content(out: &mut Vec<u8>, value: &ObjectIdentifier) {
    let arcs = &value.0;
    if arcs.len() >= 2 {
        encode_arc(out, arcs[0] * 40 + arcs[1]);
        for &a in &arcs[2..] {
            encode_arc(out, a);
        }
    } else if arcs.len() == 1 {
        encode_arc(out, arcs[0] * 40);
    }
}

pub(crate) fn decode_object_identifier_content(content: &[u8]) -> Result<ObjectIdentifier, DecodeError> {
    if content.is_empty() {
        return Ok(ObjectIdentifier::default());
    }
    let mut idx = 0usize;
    let first = decode_arc(content, &mut idx)?;
    let mut arcs = vec![first / 40, first % 40];
    while idx < content.len() {
        arcs.push(decode_arc(content, &mut idx)?);
    }
    Ok(ObjectIdentifier(arcs))
}

/// IMPLICIT tag override — see `boolean::write_boolean_tagged`'s
/// doc comment for the general rationale.
pub fn write_object_identifier_tagged(out: &mut Vec<u8>, tag: Tag, value: &ObjectIdentifier) {
    let mut val = Vec::new();
    encode_object_identifier_content(&mut val, value);
    write_primitive(out, tag, &val);
}

pub fn read_object_identifier_tagged(r: &mut Reader, tag: Tag) -> Result<ObjectIdentifier, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected OBJECT IDENTIFIER tag, got {:?}", tlv.tag), r.pos()));
    }
    decode_object_identifier_content(tlv.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_2_5_4_3() {
        // 2.5.4.3 -> first arc = 2*40+5 = 85 = 0x55; then 4, then 3.
        let mut buf = Vec::new();
        write_object_identifier(&mut buf, &ObjectIdentifier(vec![2, 5, 4, 3]));
        assert_eq!(buf, vec![0x06, 0x03, 0x55, 0x04, 0x03]);
    }

    #[test]
    fn encodes_multi_byte_arc() {
        // 1.2.840.113549 (the RSADSI arc prefix) -> first = 1*40+2 = 42 = 0x2A;
        // 840113549 base-128 (5 groups, since it exceeds 2^21): 0x83 0x90 0xCC 0xBB 0x0D.
        let mut buf = Vec::new();
        write_object_identifier(&mut buf, &ObjectIdentifier(vec![1, 2, 840113549]));
        assert_eq!(buf, vec![0x06, 0x06, 0x2A, 0x83, 0x90, 0xCC, 0xBB, 0x0D]);
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        let v = ObjectIdentifier(vec![2, 5, 4, 3]);
        write_object_identifier(&mut buf, &v);
        let mut r = Reader::new(&buf);
        assert_eq!(read_object_identifier(&mut r).unwrap(), v);
    }

    #[test]
    fn single_arc_is_not_round_trip_safe() {
        // Not a real X.680 OID (grammar requires >= 2 arcs) — documenting
        // existing, deliberate ground-truth behavior (asn1::Oid's own encode
        // does the same `arc[0]*40` collapse), not asserting it round-trips:
        // encoding [2] and [2, 0] both produce byte value 80 on the wire, so
        // decoding 80 can only ever recover [2, 0].
        let mut buf = Vec::new();
        write_object_identifier(&mut buf, &ObjectIdentifier(vec![2]));
        let mut r = Reader::new(&buf);
        assert_eq!(read_object_identifier(&mut r).unwrap(), ObjectIdentifier(vec![2, 0]));
    }

    #[test]
    fn empty_oid_round_trips() {
        let mut buf = Vec::new();
        let v = ObjectIdentifier::default();
        write_object_identifier(&mut buf, &v);
        assert_eq!(buf, vec![0x06, 0x00]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_object_identifier(&mut r).unwrap(), v);
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x00]; // INTEGER tag, not OID
        let mut r = Reader::new(&data);
        assert!(read_object_identifier(&mut r).is_err());
    }

    #[test]
    fn truncated_arc_is_error() {
        let data = [0x06, 0x01, 0x86]; // continuation bit set, no following byte
        let mut r = Reader::new(&data);
        assert!(read_object_identifier(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_5 = Tag::context(5, false);
        let mut buf = Vec::new();
        let v = ObjectIdentifier(vec![2, 5, 4, 3]);
        write_object_identifier_tagged(&mut buf, context_5, &v);
        assert_eq!(buf, vec![0x85, 0x03, 0x55, 0x04, 0x03]); // context primitive 5, not 0x06
        let mut r = Reader::new(&buf);
        assert_eq!(read_object_identifier_tagged(&mut r, context_5).unwrap(), v);
    }

    #[test]
    fn tagged_rejects_the_natural_tag() {
        let mut buf = Vec::new();
        write_object_identifier(&mut buf, &ObjectIdentifier(vec![2, 5, 4, 3])); // natural tag
        let mut r = Reader::new(&buf);
        assert!(read_object_identifier_tagged(&mut r, Tag::context(5, false)).is_err());
    }
}
