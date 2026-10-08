//! Non-generic BER walker for `spec::object::Asn1Seq` (gambas-asn1#681
//! second pass — see that module's doc for the full rationale). One
//! function, shared by every SEQUENCE/SET type in the program: calling
//! it never needs a fresh monomorphization per concrete type the way
//! `ber::sequence::encode_sequence_content::<T>` did, so a BER-only
//! caller never has to compile (or address-take) anything XER/JER/PER-
//! shaped to reach a nested SEQUENCE/SET member.

use crate::ber::reader::{DecodeError, Reader};
use crate::ber::tag::Tag;
use crate::ber::writer::write_tagged;
use crate::spec::choice::BerTagging;
use crate::spec::object::{Asn1Seq, MemberRef, MemberRefMut};
use crate::spec::primitive::{ber_decode_primitive, ber_encode_primitive};

fn encode_composite_member(inner: &dyn Asn1Seq, ber: BerTagging, out: &mut Vec<u8>) {
    match ber {
        BerTagging::Explicit(tag) => write_tagged(out, tag, |out| encode_seq_into(inner, out)),
        BerTagging::Implicit(tag) => write_tagged(out, tag, |out| encode_seq_content(inner, out)),
        BerTagging::Delegate => encode_seq_into(inner, out),
        BerTagging::Unsupported(reason) => panic!("member not supported: {reason}"),
    }
}

/// The member-loop content, no outer TLV — shared by `encode_seq` (natural
/// tag) and a containing member's own tag override (X.690 §8.14).
pub fn encode_seq_content(obj: &dyn Asn1Seq, out: &mut Vec<u8>) {
    let spec = obj.spec();
    for (i, m) in spec.members.iter().enumerate() {
        if obj.is_default_equal(i) {
            continue;
        }
        let member = obj.get_member(i);
        match member {
            MemberRef::Absent => {}
            MemberRef::Primitive(p) => ber_encode_primitive(p, m.ber, out),
            MemberRef::Composite(inner) => encode_composite_member(inner, m.ber, out),
        }
        if !matches!(obj.get_member(i), MemberRef::Absent) {
            let delta = obj.validate(i);
            if delta != 0 {
                crate::validate::check_delta(delta, m.name, "encode");
            }
        }
    }
}

/// Appends a SEQUENCE/SET's complete TLV (its own natural tag).
pub fn encode_seq_into(obj: &dyn Asn1Seq, out: &mut Vec<u8>) {
    write_tagged(out, obj.spec().tag, |out| encode_seq_content(obj, out));
}

pub fn encode_seq(obj: &dyn Asn1Seq) -> Vec<u8> {
    let mut out = Vec::new();
    encode_seq_into(obj, &mut out);
    out
}

/// IMPLICIT/EXPLICIT retag of a SEQUENCE/SET-typed member (X.690 §8.14) —
/// same content, different outer tag or an extra wrapping TLV. Used by a
/// *containing* type's own member override reaching this SEQUENCE/SET.
pub fn encode_seq_tagged(obj: &dyn Asn1Seq, tag: Tag, explicit: bool, out: &mut Vec<u8>) {
    if explicit {
        write_tagged(out, tag, |out| encode_seq_into(obj, out));
    } else {
        write_tagged(out, tag, |out| encode_seq_content(obj, out));
    }
}

fn decode_composite_member(inner: &mut dyn Asn1Seq, ber: BerTagging, r: &mut Reader) -> Result<(), DecodeError> {
    match ber {
        BerTagging::Explicit(tag) => {
            let tlv = r.read_tlv()?;
            if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
            }
            let mut outer = Reader::new(tlv.value);
            let inner_tlv = outer.read_tlv()?;
            let mut content = Reader::new(inner_tlv.value);
            decode_seq_content_into(inner, &mut content)
        }
        BerTagging::Implicit(tag) => {
            let tlv = r.read_tlv()?;
            if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
            }
            let mut content = Reader::new(tlv.value);
            decode_seq_content_into(inner, &mut content)
        }
        BerTagging::Delegate => {
            let natural = inner.spec().tag;
            let tlv = r.read_tlv()?;
            if tlv.tag.class != natural.class || tlv.tag.number != natural.number {
                return Err(DecodeError::new(format!("expected tag {natural:?}, got {:?}", tlv.tag), r.pos()));
            }
            let mut content = Reader::new(tlv.value);
            decode_seq_content_into(inner, &mut content)
        }
        BerTagging::Unsupported(reason) => panic!("member not supported: {reason}"),
    }
}

fn decode_member(obj: &mut dyn Asn1Seq, i: usize, r: &mut Reader) -> Result<(), DecodeError> {
    let ber = obj.spec().members[i].ber;
    match obj.get_member_mut(i) {
        MemberRefMut::Absent => Ok(()),
        MemberRefMut::Primitive(p) => ber_decode_primitive(p, ber, r),
        MemberRefMut::Composite(inner) => decode_composite_member(inner, ber, r),
    }
}

/// Decodes a SEQUENCE/SET's member-loop content into an already-
/// default-initialized `obj` (its fields start at whatever `Default`
/// left them, same contract `ber::sequence::decode_sequence_content`
/// documents for required-but-not-yet-filled members). OPTIONAL member
/// detection peeks the wire tag first, same canonical-order assumption
/// `ber::sequence`'s own decoder documents.
pub fn decode_seq_content_into(obj: &mut dyn Asn1Seq, r: &mut Reader) -> Result<(), DecodeError> {
    let member_count = obj.spec().members.len();
    for i in 0..member_count {
        let (name, tag, optional) = {
            let m = &obj.spec().members[i];
            (m.name, m.tag, m.optional)
        };
        let mut has_value = true;
        if optional {
            if r.peek_tag() == Some(tag) {
                decode_member(obj, i, r)?;
            } else {
                obj.set_default(i);
                if matches!(obj.get_member(i), MemberRef::Absent) {
                    has_value = false;
                }
            }
        } else {
            decode_member(obj, i, r)?;
        }
        if has_value {
            let delta = obj.validate(i);
            if delta != 0 {
                crate::validate::check_delta(delta, name, "decode");
            }
        }
    }
    Ok(())
}

pub fn decode_seq_into(obj: &mut dyn Asn1Seq, r: &mut Reader) -> Result<(), DecodeError> {
    let tag = obj.spec().tag;
    let tlv = r.read_tlv()?;
    if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
        return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
    }
    let mut content = Reader::new(tlv.value);
    decode_seq_content_into(obj, &mut content)
}

/// Decode counterpart of `encode_seq_tagged`.
pub fn decode_seq_tagged_into(obj: &mut dyn Asn1Seq, r: &mut Reader, tag: Tag, explicit: bool) -> Result<(), DecodeError> {
    decode_composite_member(obj, if explicit { BerTagging::Explicit(tag) } else { BerTagging::Implicit(tag) }, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::UNCONSTRAINED;
    use crate::integer::{Integer, INTEGER_TAG};
    use crate::spec::object::{MemberMeta, SequenceSpec};
    use crate::spec::sequence::SEQUENCE_TAG;

    /// `Inner ::= SEQUENCE { x INTEGER }` — worked example + test subject
    /// for the reflective `Asn1Seq` design (gambas-asn1#681 second pass),
    /// same dogfooding role `Point` plays for `ber::sequence`.
    #[derive(Debug, Default, Clone, PartialEq)]
    struct Inner {
        x: Integer,
    }

    static INNER_MEMBERS: [MemberMeta; 1] = [MemberMeta {
        name: "x",
        tag: INTEGER_TAG,
        optional: false,
        ber: BerTagging::Delegate,
        constraints: &UNCONSTRAINED,
        per_unsupported: None,
    }];

    static INNER_SPEC: SequenceSpec = SequenceSpec {
        name: "Inner",
        tag: SEQUENCE_TAG,
        members: &INNER_MEMBERS,
        ext_at: -1,
        roms_count: 0,
    };

    impl Asn1Seq for Inner {
        fn spec(&self) -> &'static SequenceSpec {
            &INNER_SPEC
        }
        fn get_member(&self, i: usize) -> MemberRef<'_> {
            match i {
                0 => MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(&self.x)),
                _ => unreachable!(),
            }
        }
        fn get_member_mut(&mut self, i: usize) -> MemberRefMut<'_> {
            match i {
                0 => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(&mut self.x)),
                _ => unreachable!(),
            }
        }
        fn set_default(&mut self, _i: usize) {}
        fn is_default_equal(&self, _i: usize) -> bool {
            false
        }
        fn validate(&self, _i: usize) -> i64 {
            0
        }
    }

    /// `Outer ::= SEQUENCE { y INTEGER, inner Inner, maybe INTEGER OPTIONAL }`
    /// — exercises required scalar + required composite + absent-optional
    /// recursion together, the same shape `Contact`/`PhoneNumber` have.
    #[derive(Debug, Default, Clone, PartialEq)]
    struct Outer {
        y: Integer,
        inner: Inner,
        maybe: Option<Integer>,
    }

    static OUTER_MEMBERS: [MemberMeta; 3] = [
        MemberMeta { name: "y", tag: INTEGER_TAG, optional: false, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, per_unsupported: None },
        MemberMeta { name: "inner", tag: SEQUENCE_TAG, optional: false, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, per_unsupported: None },
        MemberMeta { name: "maybe", tag: INTEGER_TAG, optional: true, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, per_unsupported: None },
    ];

    static OUTER_SPEC: SequenceSpec = SequenceSpec {
        name: "Outer",
        tag: SEQUENCE_TAG,
        members: &OUTER_MEMBERS,
        ext_at: -1,
        roms_count: 1,
    };

    impl Asn1Seq for Outer {
        fn spec(&self) -> &'static SequenceSpec {
            &OUTER_SPEC
        }
        fn get_member(&self, i: usize) -> MemberRef<'_> {
            match i {
                0 => MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(&self.y)),
                1 => MemberRef::Composite(&self.inner),
                2 => self.maybe.as_ref().map_or(MemberRef::Absent, |v| MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(v))),
                _ => unreachable!(),
            }
        }
        fn get_member_mut(&mut self, i: usize) -> MemberRefMut<'_> {
            match i {
                0 => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(&mut self.y)),
                1 => MemberRefMut::Composite(&mut self.inner),
                2 => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(self.maybe.get_or_insert_with(Default::default))),
                _ => unreachable!(),
            }
        }
        fn set_default(&mut self, _i: usize) {}
        fn is_default_equal(&self, _i: usize) -> bool {
            false
        }
        fn validate(&self, _i: usize) -> i64 {
            0
        }
    }

    fn roundtrip(v: &Outer) -> Outer {
        let bytes = encode_seq(v);
        let mut r = Reader::new(&bytes);
        let mut out = Outer::default();
        decode_seq_into(&mut out, &mut r).unwrap();
        out
    }

    #[test]
    fn encodes_nested_sequence() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: None };
        // SEQUENCE { INTEGER 7, SEQUENCE { INTEGER 5 } } — no `maybe` (absent optional).
        assert_eq!(encode_seq(&v), vec![0x30, 0x08, 0x02, 0x01, 0x07, 0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn round_trips_without_optional() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: None };
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn round_trips_with_optional_present() {
        let v = Outer { y: Integer(-3), inner: Inner { x: Integer(42) }, maybe: Some(Integer(99)) };
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn xer_round_trips_nested_sequence() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: Some(Integer(1)) };
        let xml = crate::xer::object::encode_seq(&v);
        let mut r = crate::xer::reader::XerReader::new(&xml);
        let mut out = Outer::default();
        crate::xer::object::decode_seq_into(&mut out, &mut r).unwrap();
        assert_eq!(out, v);
    }

    #[test]
    fn jer_round_trips_nested_sequence() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: None };
        let json = crate::jer::object::encode_seq(&v);
        let mut r = crate::jer::reader::Reader::new(&json);
        let mut out = Outer::default();
        crate::jer::object::decode_seq_into(&mut out, &mut r).unwrap();
        assert_eq!(out, v);
    }

    #[test]
    fn per_round_trips_nested_sequence() {
        let v = Outer { y: Integer(7), inner: Inner { x: Integer(5) }, maybe: Some(Integer(3)) };
        let mut w = crate::per::writer::Writer::new();
        crate::per::object::encode_seq_content(&v, &mut w);
        w.flush();
        let bytes = w.into_bytes();
        let mut r = crate::per::reader::Reader::new(&bytes);
        let mut out = Outer::default();
        crate::per::object::decode_seq_content_into(&mut out, &mut r).unwrap();
        assert_eq!(out, v);
    }
}
