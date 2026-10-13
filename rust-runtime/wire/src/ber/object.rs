//! Non-generic BER walker for every reflective construct kind
//! (see `spec::object`'s own doc for the trait design this drives).
//! One function per operation per kind, shared by every type of that
//! kind in the program: calling any of them never needs a fresh
//! monomorphization per concrete type, so a BER-only caller never has
//! to compile (or address-take) anything XER/JER/PER-shaped to reach a
//! nested member/alternative/element of any kind.

use crate::ber::enumerated::{read_enumerated_tagged_into, write_enumerated_tagged, ENUMERATED_TAG};
use crate::ber::reader::{DecodeError, Reader};
use crate::ber::tag::Tag;
use crate::ber::writer::{write_explicit, write_primitive, write_tagged};
use crate::spec::choice::BerTagging;
use crate::spec::object::{Asn1Choice, Asn1Pdu, Asn1Seq, Asn1SeqOf, MemberRef, MemberRefMut};
use crate::spec::primitive::{ber_decode_primitive, ber_encode_primitive};

/// Encodes one member/alternative/element value under `framing` — the
/// one place that dispatches on `MemberRef`'s kind, shared by the
/// SEQUENCE/SET member loop, the CHOICE alternative dispatch, and the
/// SEQUENCE OF/SET OF element loop (each of those three callers differs
/// only in *how* it picks a row/index and *what* framing it already
/// resolved, never in what happens once it has a `MemberRef` + framing).
fn encode_member_ref(m: MemberRef, framing: BerTagging, out: &mut Vec<u8>) {
    match m {
        MemberRef::Absent => {}
        MemberRef::Primitive(p) => ber_encode_primitive(p, framing, out),
        MemberRef::Composite(inner) => match framing {
            BerTagging::Explicit(tag) => write_tagged(out, tag, |out| encode_seq_into(inner, out)),
            BerTagging::Implicit(tag) => write_tagged(out, tag, |out| encode_seq_content(inner, out)),
            BerTagging::Delegate => encode_seq_into(inner, out),
            BerTagging::Unsupported(reason) => panic!("member not supported: {reason}"),
        },
        MemberRef::Choice(inner) => match framing {
            BerTagging::Explicit(tag) => write_explicit(out, tag, |out| encode_choice_dispatch(inner, out)),
            BerTagging::Implicit(tag) => encode_choice_tagged(inner, tag, out),
            BerTagging::Delegate => encode_choice_into(inner, out),
            BerTagging::Unsupported(reason) => panic!("member not supported: {reason}"),
        },
        MemberRef::SeqOf(inner) => {
            let natural = inner.natural_tag();
            match framing {
                BerTagging::Explicit(tag) => write_tagged(out, tag, |out| write_tagged(out, natural, |out| encode_seqof_content(inner, out))),
                BerTagging::Implicit(tag) => write_tagged(out, tag, |out| encode_seqof_content(inner, out)),
                BerTagging::Delegate => write_tagged(out, natural, |out| encode_seqof_content(inner, out)),
                BerTagging::Unsupported(reason) => panic!("member not supported: {reason}"),
            }
        }
        MemberRef::Enumerated(slot, _spec) => {
            let v = slot.enum_get();
            match framing {
                BerTagging::Explicit(tag) => write_tagged(out, tag, |out| write_enumerated_tagged(out, ENUMERATED_TAG, v)),
                BerTagging::Implicit(tag) => write_enumerated_tagged(out, tag, v),
                BerTagging::Delegate => write_enumerated_tagged(out, ENUMERATED_TAG, v),
                BerTagging::Unsupported(reason) => panic!("member not supported: {reason}"),
            }
        }
    }
}

/// Decode counterpart of `encode_member_ref`.
fn decode_member_ref(m: MemberRefMut, framing: BerTagging, r: &mut Reader) -> Result<(), DecodeError> {
    match m {
        MemberRefMut::Absent => Ok(()),
        MemberRefMut::Primitive(p) => ber_decode_primitive(p, framing, r),
        MemberRefMut::Composite(inner) => decode_composite_member(inner, framing, r),
        MemberRefMut::Choice(inner) => match framing {
            BerTagging::Explicit(tag) => {
                let tlv = r.read_tlv()?;
                if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                    return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
                }
                let mut inner_r = Reader::new(tlv.value);
                decode_choice_dispatch(inner, &mut inner_r)
            }
            BerTagging::Implicit(tag) => decode_choice_tagged_into(inner, r, tag),
            BerTagging::Delegate => decode_choice_into(inner, r),
            BerTagging::Unsupported(reason) => panic!("member not supported: {reason}"),
        },
        MemberRefMut::SeqOf(inner) => {
            let natural = inner.natural_tag();
            match framing {
                BerTagging::Explicit(tag) => {
                    let tlv = r.read_tlv()?;
                    if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                        return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
                    }
                    let mut outer = Reader::new(tlv.value);
                    let inner_tlv = outer.read_tlv()?;
                    decode_seqof_content(inner, inner_tlv.value)
                }
                BerTagging::Implicit(tag) => {
                    let tlv = r.read_tlv()?;
                    if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                        return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
                    }
                    decode_seqof_content(inner, tlv.value)
                }
                BerTagging::Delegate => {
                    let tlv = r.read_tlv()?;
                    if tlv.tag.class != natural.class || tlv.tag.number != natural.number {
                        return Err(DecodeError::new(format!("expected tag {natural:?}, got {:?}", tlv.tag), r.pos()));
                    }
                    decode_seqof_content(inner, tlv.value)
                }
                BerTagging::Unsupported(reason) => panic!("member not supported: {reason}"),
            }
        }
        MemberRefMut::Enumerated(slot, _spec) => match framing {
            BerTagging::Explicit(tag) => {
                let tlv = r.read_tlv()?;
                if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                    return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
                }
                let mut inner_r = Reader::new(tlv.value);
                read_enumerated_tagged_into(slot, &mut inner_r, ENUMERATED_TAG)
            }
            BerTagging::Implicit(tag) => read_enumerated_tagged_into(slot, r, tag),
            BerTagging::Delegate => read_enumerated_tagged_into(slot, r, ENUMERATED_TAG),
            BerTagging::Unsupported(reason) => panic!("member not supported: {reason}"),
        },
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

// ---------------------------------------------------------------------
// SEQUENCE / SET
// ---------------------------------------------------------------------

/// The member-loop content, no outer TLV — shared by `encode_seq` (natural
/// tag) and a containing member's own tag override (X.690 §8.14).
pub fn encode_seq_content(obj: &dyn Asn1Seq, out: &mut Vec<u8>) {
    let spec = obj.spec();
    for (i, m) in spec.members.iter().enumerate() {
        if obj.is_default_equal(i) {
            continue;
        }
        let member = obj.get_member(i);
        let present = !matches!(member, MemberRef::Absent);
        encode_member_ref(member, m.ber, out);
        if present {
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

/// Decodes a SEQUENCE/SET's member-loop content into an already-
/// default-initialized `obj`. OPTIONAL member detection peeks the wire
/// tag first, same canonical-order assumption `ber::sequence`'s own
/// decoder makes.
pub fn decode_seq_content_into(obj: &mut dyn Asn1Seq, r: &mut Reader) -> Result<(), DecodeError> {
    let member_count = obj.spec().members.len();
    for i in 0..member_count {
        let (name, tag, optional, ber) = {
            let m = &obj.spec().members[i];
            (m.name, m.tag, m.optional, m.ber)
        };
        let mut has_value = true;
        if optional {
            if r.peek_tag() == Some(tag) {
                decode_member_ref(obj.get_member_mut(i), ber, r)?;
            } else {
                obj.set_default(i);
                if matches!(obj.get_member(i), MemberRef::Absent) {
                    has_value = false;
                }
            }
        } else {
            decode_member_ref(obj.get_member_mut(i), ber, r)?;
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

// ---------------------------------------------------------------------
// CHOICE
// ---------------------------------------------------------------------

/// The alternative-dispatch encoding (X.680 §28 — no outer wrapper of its
/// own), before any `own_tag` wrap.
fn encode_choice_dispatch(obj: &dyn Asn1Choice, out: &mut Vec<u8>) {
    if let Some(i) = obj.active_index() {
        let ber = obj.spec().alternatives[i].ber;
        encode_member_ref(obj.get_active(), ber, out);
        return;
    }
    if let Some((tag, bytes)) = obj.extract_unknown_extension() {
        write_primitive(out, tag, bytes);
        return;
    }
    panic!("encode_choice: no alternative matched — codegen/table mismatch");
}

/// Appends a CHOICE's encoding to an existing buffer.
pub fn encode_choice_into(obj: &dyn Asn1Choice, out: &mut Vec<u8>) {
    match obj.spec().own_tag {
        Some(tag) => write_explicit(out, tag, |inner| encode_choice_dispatch(obj, inner)),
        None => encode_choice_dispatch(obj, out),
    }
}

pub fn encode_choice(obj: &dyn Asn1Choice) -> Vec<u8> {
    let mut out = Vec::new();
    encode_choice_into(obj, &mut out);
    out
}

/// IMPLICIT-retags a CHOICE-with-own_tag value under `tag` instead of its
/// own declared `[n]` (X.680 §22.5/§28.4).
pub fn encode_choice_tagged(obj: &dyn Asn1Choice, tag: Tag, out: &mut Vec<u8>) {
    write_tagged(out, tag, |out| encode_choice_dispatch(obj, out));
}

/// Decode counterpart of `encode_choice_tagged`.
pub fn decode_choice_tagged_into(obj: &mut dyn Asn1Choice, r: &mut Reader, tag: Tag) -> Result<(), DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
        return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
    }
    let mut inner = Reader::new(tlv.value);
    decode_choice_dispatch(obj, &mut inner)
}

pub fn decode_choice_into(obj: &mut dyn Asn1Choice, r: &mut Reader) -> Result<(), DecodeError> {
    match obj.spec().own_tag {
        Some(tag) => {
            let tlv = r.read_tlv()?;
            if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
                return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
            }
            let mut inner = Reader::new(tlv.value);
            decode_choice_dispatch(obj, &mut inner)
        }
        None => decode_choice_dispatch(obj, r),
    }
}

/// Peeks the wire tag, selects the alternative through `ber_tags` and
/// decodes its payload in place. Falls back to the unknown-extension
/// capture (if present) by capturing the whole TLV instead of erroring.
fn decode_choice_dispatch(obj: &mut dyn Asn1Choice, r: &mut Reader) -> Result<(), DecodeError> {
    let tag = r.peek_tag().ok_or_else(|| DecodeError::new("empty CHOICE input".to_string(), 0))?;
    let found = obj
        .spec()
        .ber_tags
        .binary_search_by_key(&tag.identifier_key(), |d| d.tag.identifier_key())
        .ok()
        .map(|i| obj.spec().ber_tags[i].alt);
    if let Some(alt_idx) = found {
        let ber = obj.spec().alternatives[alt_idx].ber;
        return decode_member_ref(obj.select_mut(alt_idx), ber, r);
    }
    let tlv = r.read_tlv()?;
    obj.construct_unknown_extension(tlv.tag, tlv.value.to_vec());
    if obj.extract_unknown_extension().is_some() {
        return Ok(());
    }
    // Trace a CHOICE tag miss (DBG_BER_CHOICE) before falling back to the
    // unknown-extension path, so a decode failure here is diagnosable
    // without a rebuild.
    if crate::debug::debug_flags() & crate::debug::DBG_BER_CHOICE != 0 {
        let alt_tags: Vec<Tag> = obj.spec().ber_tags.iter().map(|d| d.tag).collect();
        eprintln!("[DBG_BER_CHOICE] no alternative matches peek tag {tag:?} — known tags: {alt_tags:?}");
    }
    Err(DecodeError::new(format!("unrecognized CHOICE alternative tag {tag:?}"), 0))
}

// ---------------------------------------------------------------------
// SEQUENCE OF / SET OF
// ---------------------------------------------------------------------

pub fn encode_seqof_content(obj: &dyn Asn1SeqOf, out: &mut Vec<u8>) {
    for i in 0..obj.len() {
        encode_member_ref(obj.get(i), BerTagging::Delegate, out);
    }
}

/// Mirrors `ber::sequence::decode_seq_of_content`'s own zero-copy
/// top-level-TLV pre-count (`count_top_level_tlvs`): reserves the
/// backing `Vec` once via `Asn1SeqOf::reserve` instead of letting
/// `push_default_mut` regrow it geometrically one element at a time.
pub fn decode_seqof_content(obj: &mut dyn Asn1SeqOf, content: &[u8]) -> Result<(), DecodeError> {
    obj.reserve(crate::ber::sequence::count_top_level_tlvs(content));
    let mut inner = Reader::new(content);
    while !inner.at_end() {
        decode_member_ref(obj.push_default_mut(), BerTagging::Delegate, &mut inner)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Top-level (document root) entry points
// ---------------------------------------------------------------------

/// Top-level SIZE check on a named SEQUENCE OF/SET OF (X.680 §51.5);
/// a SEQUENCE/SET/CHOICE root validates its own members inside the
/// member loop instead.
fn check_pdu_size<T: Asn1Pdu + ?Sized>(v: &T, phase: &str) {
    if let MemberRef::SeqOf(s) = v.as_member_ref() {
        let delta = crate::constraints::validate_size(s.len(), T::PDU_CONSTRAINTS);
        if delta != 0 {
            crate::validate::check_delta(delta, s.own_xer_name(), phase);
        }
    }
}

/// @brief Appends `v`'s complete BER TLV under its own natural (or
///        type-assignment-overridden) tag to `out`.
/// @param v    Any generated SEQUENCE/SET/CHOICE/SEQUENCE OF type.
/// @param out  Output buffer; existing bytes are kept (multi-record
///             streams append one record per call).
/// @see X.690 §8.9–§8.13 — constructed-type encodings; §8.14 tagging.
pub fn encode_pdu_into<T: Asn1Pdu + ?Sized>(v: &T, out: &mut Vec<u8>) {
    check_pdu_size(v, "encode");
    encode_member_ref(v.as_member_ref(), BerTagging::Delegate, out);
}

/// @brief One-record convenience form of `encode_pdu_into`.
/// @return The encoded TLV.
pub fn encode_pdu<T: Asn1Pdu + ?Sized>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    encode_pdu_into(v, &mut out);
    out
}

/// @brief Decodes one top-level TLV from `r` into `v`, leaving `r`
///        positioned just past it — the streaming form for files that
///        concatenate records (callers read `r.pos()` afterwards).
/// @param v  Destination; expected to be `Default`-fresh.
/// @param r  Reader positioned at the record's tag octet.
/// @return `Err` on malformed BER or a tag mismatch.
/// @see X.690 §8.1 — TLV structure.
pub fn decode_pdu_into<T: Asn1Pdu + ?Sized>(v: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
    decode_member_ref(v.as_member_ref_mut(), BerTagging::Delegate, r)?;
    check_pdu_size(v, "decode");
    Ok(())
}

/// @brief Whole-buffer form of `decode_pdu_into`: decodes the first
///        record in `data`.
/// @return The decoded value.
pub fn decode_pdu<T: Asn1Pdu>(data: &[u8]) -> Result<T, DecodeError> {
    let mut v = T::default();
    decode_pdu_into(&mut v, &mut Reader::new(data))?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::UNCONSTRAINED;
    use crate::integer::{Integer, INTEGER_TAG};
    use crate::spec::object::{MemberMeta, SequenceSpec};
    use crate::spec::sequence::SEQUENCE_TAG;

    /// `Inner ::= SEQUENCE { x INTEGER }` — worked example + test subject
    /// for the reflective `Asn1Seq` design, same dogfooding role `Point`
    /// plays for `ber::sequence`.
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
        xer_instruction: crate::spec::object::XerInstruction::Default,
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
        MemberMeta { name: "y", tag: INTEGER_TAG, optional: false, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, xer_instruction: crate::spec::object::XerInstruction::Default, per_unsupported: None },
        MemberMeta { name: "inner", tag: SEQUENCE_TAG, optional: false, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, xer_instruction: crate::spec::object::XerInstruction::Default, per_unsupported: None },
        MemberMeta { name: "maybe", tag: INTEGER_TAG, optional: true, ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, xer_instruction: crate::spec::object::XerInstruction::Default, per_unsupported: None },
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

    /// `Choice ::= CHOICE { num INTEGER, nested Inner }` — worked example
    /// for `Asn1Choice`.
    #[derive(Debug, Clone, PartialEq)]
    enum Choice {
        Num(Integer),
        Nested(Inner),
    }
    impl Default for Choice {
        fn default() -> Self {
            Choice::Num(Integer(0))
        }
    }

    static CHOICE_ALTS: [crate::spec::object::AltMeta; 2] = [
        crate::spec::object::AltMeta { name: "num", ber: BerTagging::Implicit(INTEGER_TAG), constraints: &UNCONSTRAINED, per_unsupported: None },
        crate::spec::object::AltMeta { name: "nested", ber: BerTagging::Delegate, constraints: &UNCONSTRAINED, per_unsupported: None },
    ];
    static CHOICE_BER_TAGS: [crate::spec::choice::BerDispatch; 2] = [
        crate::spec::choice::BerDispatch { tag: INTEGER_TAG, alt: 0 },
        crate::spec::choice::BerDispatch { tag: SEQUENCE_TAG, alt: 1 },
    ];
    static CHOICE_SPEC: crate::spec::object::ChoiceSpec = crate::spec::object::ChoiceSpec {
        name: "Choice",
        alternatives: &CHOICE_ALTS,
        ber_tags: &CHOICE_BER_TAGS,
        own_tag: None,
        ext_at: -1,
        range_bits: 1,
    };
    impl Asn1Choice for Choice {
        fn spec(&self) -> &'static crate::spec::object::ChoiceSpec {
            &CHOICE_SPEC
        }
        fn active_index(&self) -> Option<usize> {
            match self {
                Choice::Num(_) => Some(0),
                Choice::Nested(_) => Some(1),
            }
        }
        fn get_active(&self) -> MemberRef<'_> {
            match self {
                Choice::Num(v) => MemberRef::Primitive(crate::spec::primitive::PrimitiveRef::Integer(v)),
                Choice::Nested(v) => MemberRef::Composite(v),
            }
        }
        fn select_mut(&mut self, index: usize) -> MemberRefMut<'_> {
            match index {
                0 => {
                    if !matches!(self, Choice::Num(_)) {
                        *self = Choice::Num(Default::default());
                    }
                    match self {
                        Choice::Num(v) => MemberRefMut::Primitive(crate::spec::primitive::PrimitiveRefMut::Integer(v)),
                        _ => unreachable!(),
                    }
                }
                1 => {
                    if !matches!(self, Choice::Nested(_)) {
                        *self = Choice::Nested(Default::default());
                    }
                    match self {
                        Choice::Nested(v) => MemberRefMut::Composite(v),
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
        }
        fn construct_unknown_extension(&mut self, _tag: Tag, _bytes: Vec<u8>) {}
        fn extract_unknown_extension(&self) -> Option<(Tag, &[u8])> {
            None
        }
    }

    fn roundtrip_choice(v: &Choice) -> Choice {
        let bytes = encode_choice(v);
        let mut r = Reader::new(&bytes);
        let mut out = Choice::default();
        decode_choice_into(&mut out, &mut r).unwrap();
        out
    }

    #[test]
    fn choice_round_trips_primitive_alternative() {
        let v = Choice::Num(Integer(42));
        assert_eq!(roundtrip_choice(&v), v);
    }

    #[test]
    fn choice_round_trips_composite_alternative() {
        let v = Choice::Nested(Inner { x: Integer(7) });
        assert_eq!(roundtrip_choice(&v), v);
    }

    /// `Basket ::= SEQUENCE OF INTEGER` — worked example for `Asn1SeqOf`.
    fn roundtrip_seqof(v: &crate::ber::sequence::SeqOf<Integer>) -> crate::ber::sequence::SeqOf<Integer> {
        let mut out = Vec::new();
        out.push(0x30u8); // placeholder, overwritten below
        let mut content = Vec::new();
        encode_seqof_content(v, &mut content);
        let mut full = Vec::new();
        write_tagged(&mut full, SEQUENCE_TAG, |out| out.extend_from_slice(&content));
        let mut r = Reader::new(&full);
        let tlv = r.read_tlv().unwrap();
        let mut result = crate::ber::sequence::SeqOf::<Integer>::default();
        decode_seqof_content(&mut result, tlv.value).unwrap();
        let _ = out;
        result
    }

    #[test]
    fn seqof_round_trips_primitive_elements() {
        let v = crate::ber::sequence::SeqOf(vec![Integer(1), Integer(2), Integer(3)]);
        assert_eq!(roundtrip_seqof(&v), v);
    }
}
