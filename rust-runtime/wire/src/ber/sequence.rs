//! SEQUENCE OF/SET OF wrapper types and shared BER helpers — X.680
//! §25/§26, X.690 §8.10/§8.12.
//!
//! `SeqOf<T>`/`SetOf<T>` are the generic field types for an *inline*
//! (unnamed) SEQUENCE OF/SET OF member: one blanket `Asn1SeqOf`/
//! `AsMemberRef` impl per wrapper covers every element type, so no
//! per-occurrence codegen is needed. A *named* SEQUENCE OF/SET OF type
//! gets its own struct (`RustBackend::emit_seq_of_definition`) with the
//! same reflective impls plus `Asn1Pdu` (see `NamedTags` in this module's
//! tests). Every codec reaches either one through `MemberRef::SeqOf` in
//! its own `<codec>::object` walker.

use crate::ber::reader::Reader;
use crate::ber::tag::{universal, Tag};

pub const SEQUENCE_TAG: Tag = Tag::universal(universal::SEQUENCE, true);

/// SET's own natural tag (X.680 §26, universal 17, constructed) — what
/// `Asn1SeqOf::natural_tag` answers for `SetOf<T>` and a named SET OF type
/// instead of `SEQUENCE_TAG`. X.690 §8.11/
/// §8.12 SET encoding is canonically member-tag-ordered on the wire,
/// which this crate doesn't enforce — same simplifying scope note
/// `decode_sequence`'s own doc used to make for member ordering generally.
pub const SET_TAG: Tag = Tag::universal(universal::SET, true);

/// Cheap element-count hint for `ber::object::decode_seqof_content`'s
/// `Asn1SeqOf::reserve` call — walks top-level TLVs via `read_tlv` (zero-copy, no
/// allocation) without decoding any of them, so one `SEQUENCE OF`/`SET OF`
/// member's `Vec` grows exactly once instead of geometrically (profiled via
/// `valgrind --massif`: this loop's absent reservation was ~97% of all
/// decode-phase allocation bytes for a deeply nested schema). Stops early on
/// any malformed TLV — correctness still comes entirely from the real decode
/// loop; an undercount here only costs one extra reallocation, never a
/// wrong result.
pub(crate) fn count_top_level_tlvs(content: &[u8]) -> usize {
    let mut r = Reader::new(content);
    let mut n = 0;
    while !r.at_end() {
        if r.read_tlv().is_err() {
            break;
        }
        n += 1;
    }
    n
}

/// Generic SEQUENCE OF wrapper (see `SetOf<T>` just below for the SET OF
/// sibling) — the field type for an inline SEQUENCE OF member or CHOICE
/// alternative (`RustBackend::emit_sequence_declaration`/
/// `rust_seqof_alt_mtype`). A bare `Vec<T>` can't serve: SEQUENCE OF and
/// SET OF need different natural tags (X.680 §25 vs §26 — universal 16
/// vs 17), and one blanket impl on `Vec<T>` could only pick one.
/// `SeqOf<T>`/`SetOf<T>` are distinct types, so each answers its own
/// `Asn1SeqOf::natural_tag`, which `ber::object` uses both for an
/// untagged member and as the inner TLV of an EXPLICIT one (X.690
/// §8.14.3). An inline collection is named by its containing field, so
/// `own_xer_name` answers the X.680 Table 4 `xmlasn1typename`
/// `"SEQUENCE_OF"`/`"SET_OF"`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SeqOf<T>(pub Vec<T>);

impl<T> std::ops::Deref for SeqOf<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for SeqOf<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Reflective `Asn1SeqOf` impl — shared by every SEQUENCE OF element
/// kind via `AsMemberRef`, never generated per collection type.
impl<T: crate::spec::object::AsMemberRef + Default> crate::spec::object::Asn1SeqOf for SeqOf<T> {
    fn natural_tag(&self) -> Tag {
        SEQUENCE_TAG
    }
    fn own_xer_name(&self) -> &'static str {
        "SEQUENCE_OF"
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> crate::spec::object::MemberRef<'_> {
        self.0[index].as_member_ref()
    }
    fn push_default_mut(&mut self) -> crate::spec::object::MemberRefMut<'_> {
        self.0.push(T::default());
        self.0.last_mut().unwrap().as_member_ref_mut()
    }
    fn reserve(&mut self, additional: usize) {
        self.0.reserve(additional);
    }
    fn elem_natural_xer_name(&self, index: usize) -> &'static str {
        self.0[index].own_element_xer_name()
    }
    fn elem_xer_instruction(&self) -> crate::spec::object::XerInstruction {
        <T as crate::spec::object::AsMemberRef>::XER_INSTRUCTION
    }
    fn elem_ber_framing(&self) -> crate::spec::choice::BerTagging {
        <T as crate::spec::object::AsMemberRef>::BER_FRAMING
    }
}

/// Lets a `SeqOf<T>` itself be a SEQUENCE OF/SET OF element — closes the
/// nested-collection case (`SeqOf<SeqOf<Inner>>`) reflectively, the same
/// way every primitive already does via `spec::primitive`'s own
/// `define_as_member_ref!`.
impl<T: crate::spec::object::AsMemberRef + Default> crate::spec::object::AsMemberRef for SeqOf<T> {
    fn as_member_ref(&self) -> crate::spec::object::MemberRef<'_> {
        crate::spec::object::MemberRef::SeqOf(self)
    }
    fn as_member_ref_mut(&mut self) -> crate::spec::object::MemberRefMut<'_> {
        crate::spec::object::MemberRefMut::SeqOf(self)
    }
    fn own_element_xer_name(&self) -> &'static str {
        <Self as crate::spec::object::Asn1SeqOf>::own_xer_name(self)
    }
}

/// SET OF analogue of `SeqOf<T>` — identical shape, only
/// `Asn1SeqOf::natural_tag` differs (X.680 §26: SET's own universal tag
/// 17, not SEQUENCE's 16 — see `SeqOf<T>`'s own doc for why it matters).
/// A separate type rather than a parameter on `SeqOf<T>`, so the tag is a
/// fixed fact of the type.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SetOf<T>(pub Vec<T>);

impl<T> std::ops::Deref for SetOf<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for SetOf<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: crate::spec::object::AsMemberRef + Default> crate::spec::object::Asn1SeqOf for SetOf<T> {
    fn natural_tag(&self) -> Tag {
        SET_TAG
    }
    fn own_xer_name(&self) -> &'static str {
        "SET_OF"
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> crate::spec::object::MemberRef<'_> {
        self.0[index].as_member_ref()
    }
    fn push_default_mut(&mut self) -> crate::spec::object::MemberRefMut<'_> {
        self.0.push(T::default());
        self.0.last_mut().unwrap().as_member_ref_mut()
    }
    fn reserve(&mut self, additional: usize) {
        self.0.reserve(additional);
    }
    fn elem_natural_xer_name(&self, index: usize) -> &'static str {
        self.0[index].own_element_xer_name()
    }
    fn elem_xer_instruction(&self) -> crate::spec::object::XerInstruction {
        <T as crate::spec::object::AsMemberRef>::XER_INSTRUCTION
    }
    fn elem_ber_framing(&self) -> crate::spec::choice::BerTagging {
        <T as crate::spec::object::AsMemberRef>::BER_FRAMING
    }
}

/// `SetOf<T>` analogue of `SeqOf<T>`'s own `AsMemberRef` impl above.
impl<T: crate::spec::object::AsMemberRef + Default> crate::spec::object::AsMemberRef for SetOf<T> {
    fn as_member_ref(&self) -> crate::spec::object::MemberRef<'_> {
        crate::spec::object::MemberRef::SeqOf(self)
    }
    fn as_member_ref_mut(&mut self) -> crate::spec::object::MemberRefMut<'_> {
        crate::spec::object::MemberRefMut::SeqOf(self)
    }
    fn own_element_xer_name(&self) -> &'static str {
        <Self as crate::spec::object::Asn1SeqOf>::own_xer_name(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::Integer;
    use crate::spec::object::AsMemberRef;

    /// Complete TLV of a bare `SeqOf<T>`/`SetOf<T>` under its own natural
    /// tag, through the reflective `ber::object` SEQUENCE OF walker.
    fn ber_encode_seqof(v: &dyn crate::spec::object::Asn1SeqOf) -> Vec<u8> {
        let mut out = Vec::new();
        crate::ber::writer::write_tagged(&mut out, v.natural_tag(), |out| crate::ber::object::encode_seqof_content(v, out, None)).unwrap();
        out
    }

    /// Decode counterpart of `ber_encode_seqof`.
    fn ber_decode_seqof<T: crate::spec::object::Asn1SeqOf + Default>(data: &[u8]) -> T {
        let mut v = T::default();
        let tlv = Reader::new(data).read_tlv().unwrap();
        assert_eq!(tlv.tag, v.natural_tag());
        crate::ber::object::decode_seqof_content(&mut v, Reader::new(tlv.value)).unwrap();
        v
    }

    #[test]
    fn set_tag_is_seventeen_constructed() {
        assert_eq!(SET_TAG, Tag::universal(17, true));
        assert_ne!(SET_TAG, SEQUENCE_TAG);
    }

    #[test]
    fn seq_of_ber_round_trips_reflectively() {
        let v = SeqOf(vec![Integer(1), Integer(2), Integer(3)]);
        let out = ber_encode_seqof(&v);
        assert_eq!(out, vec![0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03]);

        let got: SeqOf<Integer> = ber_decode_seqof(&out);
        assert_eq!(got, v);
    }

    #[test]
    fn nested_seq_of_seq_of_ber_round_trips_reflectively() {
        // SeqOf<SeqOf<Integer>> — mirrors an unnamed `SEQUENCE OF SEQUENCE OF
        // INTEGER` element (RustBackend's ElemShape/rust_wrap_elem_shape,
        // Backend.hpp/RustBackend.cpp) at the runtime layer directly, since
        // this crate has no codegen wired in. Confirms `SeqOf<T>`'s own
        // `AsMemberRef` impl lets it be an element of another `SeqOf`, at
        // any nesting depth, with no special-casing.
        let v = SeqOf(vec![SeqOf(vec![Integer(1), Integer(2)]), SeqOf(vec![Integer(3)])]);
        let out = ber_encode_seqof(&v);

        let got: SeqOf<SeqOf<Integer>> = ber_decode_seqof(&out);
        assert_eq!(got, v);
    }

    #[test]
    fn nested_seq_of_set_of_ber_round_trips_with_the_correct_wire_tags() {
        // SeqOf<SetOf<Integer>> — mixed nesting (outer SEQUENCE OF, inner SET
        // OF): confirms each level gets its own distinct natural tag
        // (SEQUENCE_TAG outer, SET_TAG inner), not the same one forced at
        // every depth.
        let v = SeqOf(vec![SetOf(vec![Integer(1), Integer(2)])]);
        let out = ber_encode_seqof(&v);
        // Outer: SEQUENCE (0x30) wrapping one element.
        assert_eq!(out[0], 0x30);
        // Inner element TLV starts right after outer tag+length (2 bytes,
        // short-form): SET (0x31), not SEQUENCE.
        assert_eq!(out[2], 0x31);

        let got: SeqOf<SetOf<Integer>> = ber_decode_seqof(&out);
        assert_eq!(got, v);
    }

    #[test]
    fn seq_of_xer_round_trips_wrapped_by_hand() {
        let v = SeqOf(vec![Integer(1), Integer(2)]);
        let mut out = String::new();
        crate::xer::writer::write_open_tag(&mut out, "items");
        crate::xer::object::encode_seqof_content(&v, &mut out, 0, None).unwrap();
        crate::xer::writer::write_close_tag(&mut out, "items");
        assert_eq!(out, "<items>\n    <INTEGER>1</INTEGER>\n    <INTEGER>2</INTEGER>\n</items>");

        let mut r = crate::xer::reader::XerReader::new(&out);
        r.consume_open_tag("items").unwrap();
        let mut got = SeqOf::<Integer>::default();
        crate::xer::object::decode_seqof_content_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("items").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn seq_of_derefs_to_the_inner_vec() {
        let v = SeqOf(vec![Integer(1), Integer(2), Integer(3)]);
        assert_eq!(v.len(), 3);
        assert_eq!(&v[..], &[1, 2, 3]);
    }

    #[test]
    fn set_of_ber_round_trips_reflectively_with_its_own_natural_tag() {
        let v = SetOf(vec![Integer(1), Integer(2)]);
        let out = ber_encode_seqof(&v);
        // SET (0x31 — universal constructed 17), not SEQUENCE (0x30).
        assert_eq!(out, vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);

        let got: SetOf<Integer> = ber_decode_seqof(&out);
        assert_eq!(got, v);
    }

    #[test]
    fn set_of_xer_round_trips_wrapped_by_hand() {
        let v = SetOf(vec![Integer(1), Integer(2)]);
        let mut out = String::new();
        crate::xer::writer::write_open_tag(&mut out, "items");
        crate::xer::object::encode_seqof_content(&v, &mut out, 0, None).unwrap();
        crate::xer::writer::write_close_tag(&mut out, "items");
        assert_eq!(out, "<items>\n    <INTEGER>1</INTEGER>\n    <INTEGER>2</INTEGER>\n</items>");

        let mut r = crate::xer::reader::XerReader::new(&out);
        r.consume_open_tag("items").unwrap();
        let mut got = SetOf::<Integer>::default();
        crate::xer::object::decode_seqof_content_into(&mut got, &mut r).unwrap();
        r.consume_close_tag("items").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn set_of_derefs_to_the_inner_vec() {
        let v = SetOf(vec![Integer(1), Integer(2), Integer(3)]);
        assert_eq!(v.len(), 3);
        assert_eq!(&v[..], &[1, 2, 3]);
    }

    /// `NamedTags ::= SEQUENCE (SIZE(1..3)) OF INTEGER` — the shape
    /// `RustBackend::emit_seq_of_definition` emits for a named SEQUENCE OF:
    /// reflective `Asn1SeqOf`/`AsMemberRef` plus an `Asn1Pdu` root marker
    /// carrying the type's own SIZE table, which `ber::object::encode_pdu`
    /// validates against (X.680 §51.5).
    #[derive(Debug, Clone, Default, PartialEq)]
    struct NamedTags(Vec<Integer>);

    impl crate::spec::object::Asn1SeqOf for NamedTags {
        fn natural_tag(&self) -> Tag { SEQUENCE_TAG }
        fn own_xer_name(&self) -> &'static str { "NamedTags" }
        fn len(&self) -> usize { self.0.len() }
        fn get(&self, index: usize) -> crate::spec::object::MemberRef<'_> { self.0[index].as_member_ref() }
        fn push_default_mut(&mut self) -> crate::spec::object::MemberRefMut<'_> {
            self.0.push(Integer::default());
            self.0.last_mut().unwrap().as_member_ref_mut()
        }
        fn elem_natural_xer_name(&self, index: usize) -> &'static str { self.0[index].own_element_xer_name() }
        fn elem_xer_instruction(&self) -> crate::spec::object::XerInstruction { crate::spec::object::XerInstruction::Default }
    }

    impl crate::spec::object::AsMemberRef for NamedTags {
        fn as_member_ref(&self) -> crate::spec::object::MemberRef<'_> { crate::spec::object::MemberRef::SeqOf(self) }
        fn as_member_ref_mut(&mut self) -> crate::spec::object::MemberRefMut<'_> { crate::spec::object::MemberRefMut::SeqOf(self) }
        fn own_element_xer_name(&self) -> &'static str { "NamedTags" }
    }

    impl crate::spec::object::Asn1Pdu for NamedTags {
        const PDU_CONSTRAINTS: &'static crate::constraints::Constraints = &NAMED_TAGS_CONSTRAINTS;
    }

    static NAMED_TAGS_CONSTRAINTS: crate::constraints::Constraints = crate::constraints::Constraints {
        flags: crate::constraints::Constraints::SIZE_CONSTRAINED,
        range_bits: 0,
        lower_bound: 0,
        upper_bound: 0,
        lower_u64: 0,
        upper_u64: 0,
        size_range_bits: 0,
        size_lower: 1,
        size_upper: 3,
        encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None, real_lower: 0.0, real_upper: 0.0,
    };

    #[test]
    fn named_seqof_in_range_does_not_bump_the_validate_counter() {
        let _guard = crate::validate::tests::COUNTER_LOCK.lock().unwrap();
        crate::validate::reset_validate_fail_count();
        crate::ber::object::encode_pdu(&NamedTags(vec![Integer(1), Integer(2)])).unwrap();
        assert_eq!(crate::validate::validate_fail_count(), 0);
    }

    #[test]
    fn named_seqof_too_many_elements_bumps_the_validate_counter() {
        let _guard = crate::validate::tests::COUNTER_LOCK.lock().unwrap();
        crate::validate::reset_validate_fail_count();
        crate::ber::object::encode_pdu(&NamedTags(vec![Integer(1), Integer(2), Integer(3), Integer(4)])).unwrap();
        assert_eq!(crate::validate::validate_fail_count(), 1);
    }
}

impl<T> crate::type_tag::TypeTag for SeqOf<T> {
    const TAG: Option<Tag> = Some(SEQUENCE_TAG);
}

impl<T> crate::type_tag::TypeTag for SetOf<T> {
    const TAG: Option<Tag> = Some(SET_TAG);
}
