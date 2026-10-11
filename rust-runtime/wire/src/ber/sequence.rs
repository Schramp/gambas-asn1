//! SEQUENCE OF/SET OF shared wire logic — X.680 §25/§26, X.690 §8.9.
//!
//! `SeqOf<T>`/`SetOf<T>` are the generic wrapper types for an *inline*
//! (unnamed) SEQUENCE OF/SET OF member's field type — one blanket
//! `Asn1Value`/`Asn1SeqOf` impl per wrapper covers every element type,
//! no per-occurrence codegen needed (gambas-asn1#681 full migration).
//! A *named* top-level SEQUENCE OF/SET OF type gets its own real struct
//! (`RustBackend::emit_seq_of_definition`) with its own `Asn1Value` impl
//! that calls straight through to the free functions below
//! (`encode_seq_of_content`/`decode_seq_of_content`), never through
//! `SeqOf<T>` itself (see `NamedTags` in this module's own tests for the
//! exact shape codegen produces).
//!
//! SEQUENCE/SET (not SEQUENCE OF/SET OF) member access goes through
//! `Asn1Seq`/`MemberRef` (`spec::object`, `ber::object`) — purely
//! reflective, no generic per-type table here at all.

use crate::ber::reader::{DecodeError, Reader};
use crate::ber::tag::{universal, Tag};
use crate::value::Asn1Value;
use crate::ber::writer::write_tagged;
use crate::xer::reader::XerReader;
use crate::xer::seq_of::{decode_seq_of_xer, encode_seq_of_xer};

pub const SEQUENCE_TAG: Tag = Tag::universal(universal::SEQUENCE, true);

/// SET's own natural tag (X.680 §26, universal 17, constructed) — used by
/// `SetOf<T>::ber_natural_tag`/`Asn1SeqOf::natural_tag` and a named SET OF
/// type's own `ber_natural_tag` instead of `SEQUENCE_TAG`. X.690 §8.11/
/// §8.12 SET encoding is canonically member-tag-ordered on the wire,
/// which this crate doesn't enforce — same simplifying scope note
/// `decode_sequence`'s own doc used to make for member ordering generally.
pub const SET_TAG: Tag = Tag::universal(universal::SET, true);

/// Shared SEQUENCE-OF wire logic — one outer `SEQUENCE_TAG` TLV wrapping
/// zero or more inner element TLVs (X.690 §8.9); `SeqOf<T>::ber_encode_content`/
/// `ber_decode_content` (this module) delegate here, and `SetOf<T>`'s own
/// impl reuses the same content logic under its own `SET_TAG` (mirrors
/// `write_char_string`/`read_char_string` in `strings.rs` — one generic
/// function, many thin per-type call sites).
pub fn encode_seq_of<V: Asn1Value>(out: &mut Vec<u8>, items: &[V]) {
    encode_seq_of_tagged(out, SEQUENCE_TAG, items);
}

pub fn decode_seq_of<V: Asn1Value + Default>(r: &mut Reader) -> Result<Vec<V>, DecodeError> {
    decode_seq_of_tagged(r, SEQUENCE_TAG)
}

/// IMPLICIT tag override for a SEQUENCE OF/SET OF member,
/// same reasoning as `boolean::write_boolean_tagged`/`read_boolean_tagged`
/// — a member declared with its own `[n]` tag replaces the
/// natural `SEQUENCE_TAG`/`SET_TAG` on the *outer* TLV only; element
/// encoding/decoding is unaffected (elements keep their own natural tags).
pub fn encode_seq_of_tagged<V: Asn1Value>(out: &mut Vec<u8>, tag: Tag, items: &[V]) {
    write_tagged(out, tag, |out| encode_seq_of_content(out, items));
}

pub fn decode_seq_of_tagged<V: Asn1Value + Default>(
    r: &mut Reader,
    tag: Tag,
) -> Result<Vec<V>, DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(format!("expected SEQUENCE OF tag, got {:?}", tlv.tag), r.pos()));
    }
    decode_seq_of_content(tlv.value)
}

/// Content octets only (X.690 §8.9/§8.12) — the concatenation of each
/// element's own complete encoding, no outer TLV — for a named top-level
/// SEQUENCE OF/SET OF type's own `Asn1Value::ber_encode_content` (a real
/// newtype, not a plain alias, so it can implement the trait itself
/// exactly like SEQUENCE/CHOICE do — codegen wraps `Vec<V>` in
/// `pub struct X(pub Vec<V>);` for any *named* SEQUENCE OF/SET OF, since a
/// plain `pub type X = Vec<V>;` alias can't carry its own impl distinct
/// from whatever other ASN.1 type might also resolve to `Vec<V>`).
pub fn encode_seq_of_content<V: Asn1Value>(content: &mut Vec<u8>, items: &[V]) {
    for item in items {
        item.ber_encode(content);
    }
}

/// Mirrors `SeqOfBerHandler::decode_body`'s own grow/get_mut/decode shape
/// (`runtime/src/BerCodec.cpp`): `resize_with` default-constructs each new
/// element directly in `result`'s own backing storage (its std
/// implementation writes through a raw pointer into spare capacity, the
/// same technique C++'s `std::vector::resize` uses internally), and
/// `result[count]` decodes straight into that slot — no separate stack
/// temporary moved in afterward. A naive `let mut item = V::default();
/// item.ber_decode_into(..)?; result.push(item)` pays one extra
/// `memcpy(sizeof(V))` per element to move `item` into the `Vec`; profiled
/// via `valgrind --tool=callgrind` on a deeply nested real schema, that
/// move was the single largest cost in BER decode (`memcpy` at 57% of all
/// decode-phase instructions, concentrated in exactly this loop for
/// SEQUENCE OF-heavy types). `truncate` at the end mirrors C++'s trailing
/// `seq.resize(count)` shrink for a decode that ends early (error, or a
/// final empty-looking element) — a no-op whenever the loop ran to
/// completion normally.
pub fn decode_seq_of_content<V: Asn1Value + Default>(content: &[u8]) -> Result<Vec<V>, DecodeError> {
    let mut inner = Reader::new(content);
    let mut result: Vec<V> = Vec::with_capacity(count_top_level_tlvs(content));
    let mut count = 0;
    while !inner.at_end() {
        if count >= result.len() {
            result.resize_with(count + 1, V::default);
        }
        result[count].ber_decode_into(&mut inner)?;
        count += 1;
    }
    result.truncate(count);
    Ok(result)
}

/// Cheap element-count hint for `decode_seq_of_content`'s `Vec::with_capacity`
/// reservation — walks top-level TLVs via `read_tlv` (zero-copy, no
/// allocation) without decoding any of them, so one `SEQUENCE OF`/`SET OF`
/// member's `Vec` grows exactly once instead of geometrically (profiled via
/// `valgrind --massif`: this loop's absent reservation was ~97% of all
/// decode-phase allocation bytes for a deeply nested schema). Stops early on
/// any malformed TLV — correctness still comes entirely from the real decode
/// loop above; an undercount here only costs one extra reallocation, never a
/// wrong result.
fn count_top_level_tlvs(content: &[u8]) -> usize {
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
/// sibling) — gives a *named* SEQUENCE OF CHOICE alternative
/// (`RustBackend::rust_seqof_alt_mtype`) or SEQUENCE/SET *member*
/// (`RustBackend::emit_sequence_declaration`, both `compiler/src/codegen/
/// RustBackend.cpp`) a concrete `Asn1Value` impl without per-occurrence
/// codegen. `Vec<u8>` no longer carries a direct `Asn1Value` impl of its
/// own (OCTET STRING is `octet_string::OctetString`, a newtype), but a bare
/// `Vec<T>` still can't get one generically the same way: SEQUENCE OF and
/// SET OF need different natural tags (X.680 §26 vs §24 — universal 16 vs
/// 17), and a single blanket `impl<V: Asn1Value> Asn1Value for Vec<V>` can
/// only ever pick one. `SeqOf<T>`/`SetOf<T>` sidestep that by being
/// distinct types, so one blanket impl per wrapper covers every element
/// type — no per-occurrence synthesized wrapper struct needed the way a
/// top-level named `X ::= SEQUENCE OF Y`
/// still gets from `emit_seq_of_definition` (that one keeps its own real
/// ASN.1 name for XER wrapping when referenced elsewhere; a `SeqOf<T>`
/// alternative/member is wrapped by its own alternative/field name
/// instead, same as any other scalar member — never needs a name of its
/// own, hence `xer_element_name` below being a generic placeholder).
///
/// `ber_natural_tag` genuinely matters here, unlike a bare CHOICE
/// alternative (which always dispatches through its own resolved tag via
/// `ber_encode_tagged`/`ber_decode_into_tagged`, never this method): a
/// required SEQUENCE/SET *member* with no tag override reaches for
/// `self.ber_natural_tag()` directly via the `Asn1Value` trait's own
/// default methods — and an EXPLICIT-tagged member's inner TLV (X.690
/// §8.14.3: EXPLICIT wraps the value's own natural encoding unchanged)
/// reaches it exactly the same way through `value::encode_explicit`/
/// `decode_explicit`. `SeqOf<T>`/`SetOf<T>` being two distinct types with
/// two different `ber_natural_tag()` values is what makes both paths
/// correct automatically, with no separate SEQUENCE-vs-SET signal needed
/// anywhere in the generic walker — `RustBackend` only has to pick which
/// of the two type names to put in the struct field declaration.
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

impl<T: Asn1Value + Default> Asn1Value for SeqOf<T> {
    fn ber_natural_tag(&self) -> Tag {
        SEQUENCE_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "SEQUENCE-OF"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        encode_seq_of_content(out, &self.0);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = decode_seq_of_content(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String, depth: usize) {
        encode_seq_of_xer(out, &self.0, depth);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        self.0 = decode_seq_of_xer(r)?;
        Ok(())
    }

    fn jer_encode(&self, out: &mut String) {
        crate::jer::seq_of::encode_seq_of_jer(out, &self.0);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        self.0 = crate::jer::seq_of::decode_seq_of_jer(r)?;
        Ok(())
    }

    /// An inline SEQUENCE OF/SET OF member has no constraint of its own
    /// (this generic wrapper is shared by every such member) — its SIZE
    /// constraint arrives as the row's `Constraints` (X.680 §51).
    fn validate(&self, c: &crate::constraints::Constraints) -> i64 {
        crate::constraints::validate_size(self.0.len(), c)
    }

    /// X.691 §19/§20: the collection's SIZE is `c`'s own `size_*` fields,
    /// each element is encoded against `c.element` (a shared native element
    /// type such as `i64` takes its range from there).
    fn per_encode(&self, w: &mut crate::per::writer::Writer, c: &crate::constraints::Constraints) {
        crate::per::seq_of::encode_seq_of_content(w, c, &self.0);
    }

    fn per_decode_into(
        &mut self,
        r: &mut crate::per::reader::Reader,
        c: &crate::constraints::Constraints,
    ) -> Result<(), crate::per::reader::DecodeError> {
        self.0 = crate::per::seq_of::decode_seq_of_content(r, c)?;
        Ok(())
    }
}

/// Reflective `Asn1SeqOf` impl (gambas-asn1#681 full migration) — shared
/// by every SEQUENCE OF element kind via `AsMemberRef`, never generated
/// per collection type.
impl<T: crate::spec::object::AsMemberRef + Asn1Value + Default> crate::spec::object::Asn1SeqOf for SeqOf<T> {
    fn natural_tag(&self) -> Tag {
        SEQUENCE_TAG
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
    fn elem_natural_xer_name(&self, index: usize) -> &'static str {
        self.0[index].xer_element_name()
    }
}

/// SET OF analogue of `SeqOf<T>` — identical shape, only `ber_natural_tag`
/// differs (X.680 §26: SET's own universal tag 17, not SEQUENCE's 16 —
/// see `SeqOf<T>`'s own doc for why that distinction genuinely matters
/// here, unlike a bare CHOICE alternative). A separate type, not a
/// generic parameter on `SeqOf<T>` itself, because `ber_natural_tag`
/// can't vary per-instantiation of the same type — Rust has no
/// compile-time value parameter to key it on here.
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

impl<T: Asn1Value + Default> Asn1Value for SetOf<T> {
    fn ber_natural_tag(&self) -> Tag {
        SET_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "SET-OF"
    }

    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        encode_seq_of_content(out, &self.0);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = decode_seq_of_content(content)?;
        Ok(())
    }

    fn xer_encode(&self, out: &mut String, depth: usize) {
        encode_seq_of_xer(out, &self.0, depth);
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
        self.0 = decode_seq_of_xer(r)?;
        Ok(())
    }

    fn jer_encode(&self, out: &mut String) {
        crate::jer::seq_of::encode_seq_of_jer(out, &self.0);
    }

    fn jer_decode_into(&mut self, r: &mut crate::jer::reader::Reader) -> Result<(), DecodeError> {
        self.0 = crate::jer::seq_of::decode_seq_of_jer(r)?;
        Ok(())
    }

    /// An inline SEQUENCE OF/SET OF member has no constraint of its own
    /// (this generic wrapper is shared by every such member) — its SIZE
    /// constraint arrives as the row's `Constraints` (X.680 §51).
    fn validate(&self, c: &crate::constraints::Constraints) -> i64 {
        crate::constraints::validate_size(self.0.len(), c)
    }

    /// X.691 §19/§20: the collection's SIZE is `c`'s own `size_*` fields,
    /// each element is encoded against `c.element` (a shared native element
    /// type such as `i64` takes its range from there).
    fn per_encode(&self, w: &mut crate::per::writer::Writer, c: &crate::constraints::Constraints) {
        crate::per::seq_of::encode_seq_of_content(w, c, &self.0);
    }

    fn per_decode_into(
        &mut self,
        r: &mut crate::per::reader::Reader,
        c: &crate::constraints::Constraints,
    ) -> Result<(), crate::per::reader::DecodeError> {
        self.0 = crate::per::seq_of::decode_seq_of_content(r, c)?;
        Ok(())
    }
}

impl<T: crate::spec::object::AsMemberRef + Asn1Value + Default> crate::spec::object::Asn1SeqOf for SetOf<T> {
    fn natural_tag(&self) -> Tag {
        SET_TAG
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
    fn elem_natural_xer_name(&self, index: usize) -> &'static str {
        self.0[index].xer_element_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integer::Integer;

    #[test]
    fn set_tag_is_seventeen_constructed() {
        assert_eq!(SET_TAG, Tag::universal(17, true));
        assert_ne!(SET_TAG, SEQUENCE_TAG);
    }

    // ---- SEQUENCE OF/SET OF IMPLICIT tag override -------

    #[test]
    fn tagged_seq_of_uses_the_given_tag_not_the_natural_one() {
        let context_3 = Tag::context(3, true);
        let mut buf = Vec::new();
        encode_seq_of_tagged(&mut buf, context_3, &[Integer(1), Integer(2)]);
        // context constructed 3 (0xA3), not 0x30 (universal SEQUENCE).
        assert_eq!(buf, vec![0xA3, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
        let mut r = Reader::new(&buf);
        let decoded: Vec<Integer> = decode_seq_of_tagged(&mut r, context_3).unwrap();
        assert_eq!(decoded, vec![1, 2]);
    }

    #[test]
    fn tagged_seq_of_rejects_the_natural_tag() {
        let mut buf = Vec::new();
        encode_seq_of(&mut buf, &[Integer(1)]); // natural SEQUENCE_TAG
        let mut r = Reader::new(&buf);
        let result: Result<Vec<Integer>, _> = decode_seq_of_tagged(&mut r, Tag::context(3, true));
        assert!(result.is_err());
    }

    #[test]
    fn seq_of_ber_round_trips_through_the_trait() {
        let v = SeqOf(vec![Integer(1), Integer(2), Integer(3)]);
        let mut out = Vec::new();
        v.ber_encode(&mut out);
        assert_eq!(out, vec![0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03]);

        let mut r = Reader::new(&out);
        let mut got = SeqOf::<Integer>::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn nested_seq_of_seq_of_ber_round_trips_through_the_trait() {
        // SeqOf<SeqOf<Integer>> — mirrors an unnamed `SEQUENCE OF SEQUENCE OF
        // INTEGER` element (RustBackend's ElemShape/rust_wrap_elem_shape,
        // Backend.hpp/RustBackend.cpp) at the runtime layer directly, since
        // this crate has no codegen wired in. Confirms the blanket
        // `impl<T: Asn1Value + Default> Asn1Value for SeqOf<T>` composes
        // with itself — SeqOf<Integer> is itself Asn1Value + Default, so
        // SeqOf<SeqOf<Integer>> just works, no special-casing needed at any
        // nesting depth.
        let v = SeqOf(vec![SeqOf(vec![Integer(1), Integer(2)]), SeqOf(vec![Integer(3)])]);
        let mut out = Vec::new();
        v.ber_encode(&mut out);

        let mut r = Reader::new(&out);
        let mut got = SeqOf::<SeqOf<Integer>>::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn nested_seq_of_set_of_ber_round_trips_with_the_correct_wire_tags() {
        // SeqOf<SetOf<Integer>> — mixed nesting (outer SEQUENCE OF, inner SET
        // OF): confirms each level gets its own distinct natural tag
        // (SEQUENCE_TAG outer, SET_TAG inner), not the same one forced at
        // every depth.
        let v = SeqOf(vec![SetOf(vec![Integer(1), Integer(2)])]);
        let mut out = Vec::new();
        v.ber_encode(&mut out);
        // Outer: SEQUENCE (0x30) wrapping one element.
        assert_eq!(out[0], 0x30);
        // Inner element TLV starts right after outer tag+length (2 bytes,
        // short-form): SET (0x31), not SEQUENCE.
        assert_eq!(out[2], 0x31);

        let mut r = Reader::new(&out);
        let mut got = SeqOf::<SetOf<Integer>>::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn seq_of_xer_round_trips_wrapped_by_hand() {
        let v = SeqOf(vec![Integer(1), Integer(2)]);
        let mut out = String::new();
        crate::xer::writer::write_open_tag(&mut out, "items");
        v.xer_encode(&mut out, 0);
        crate::xer::writer::write_close_tag(&mut out, "items");
        assert_eq!(out, "<items>\n    <INTEGER>1</INTEGER>\n    <INTEGER>2</INTEGER>\n</items>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("items").unwrap();
        let mut got = SeqOf::<Integer>::default();
        got.xer_decode_into(&mut r).unwrap();
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
    fn set_of_ber_round_trips_through_the_trait_with_its_own_natural_tag() {
        let v = SetOf(vec![Integer(1), Integer(2)]);
        let mut out = Vec::new();
        v.ber_encode(&mut out);
        // SET (0x31 — universal constructed 17), not SEQUENCE (0x30).
        assert_eq!(out, vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);

        let mut r = Reader::new(&out);
        let mut got = SetOf::<Integer>::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn set_of_xer_round_trips_wrapped_by_hand() {
        let v = SetOf(vec![Integer(1), Integer(2)]);
        let mut out = String::new();
        crate::xer::writer::write_open_tag(&mut out, "items");
        v.xer_encode(&mut out, 0);
        crate::xer::writer::write_close_tag(&mut out, "items");
        assert_eq!(out, "<items>\n    <INTEGER>1</INTEGER>\n    <INTEGER>2</INTEGER>\n</items>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("items").unwrap();
        let mut got = SetOf::<Integer>::default();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("items").unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn set_of_derefs_to_the_inner_vec() {
        let v = SetOf(vec![Integer(1), Integer(2), Integer(3)]);
        assert_eq!(v.len(), 3);
        assert_eq!(&v[..], &[1, 2, 3]);
    }

    /// `NamedTags ::= SEQUENCE (SIZE(1..3)) OF INTEGER` — dogfood for a
    /// *named* SEQUENCE OF type's own `Asn1Value` impl (gambas-asn1#467):
    /// every named collection type is its own distinct Rust struct that
    /// overrides `Asn1Value::validate()` directly (the funnel
    /// `ber_encode`/`ber_encode_tagged` already reach, `value.rs`) — the
    /// exact shape `RustBackend::emit_seq_of_definition` generates for a
    /// real named SEQUENCE OF/SET OF type.
    #[derive(Debug, Clone, Default, PartialEq)]
    struct NamedTags(Vec<Integer>);

    impl Asn1Value for NamedTags {
        fn ber_natural_tag(&self) -> Tag {
            SEQUENCE_TAG
        }
        fn ber_encode_content(&self, out: &mut Vec<u8>) {
            encode_seq_of_content(out, &self.0);
        }
        fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
            self.0 = decode_seq_of_content(content)?;
            Ok(())
        }
        fn validate(&self, _c: &crate::constraints::Constraints) -> i64 {
            crate::constraints::validate_size(self.0.len(), &NAMED_TAGS_CONSTRAINTS)
        }
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
        encode_table: None, alphabet_bits: 0, alphabet: None, alphabet_size: 0, element: None,
    };

    #[test]
    fn named_seqof_in_range_does_not_bump_the_validate_counter() {
        let _guard = crate::validate::tests::COUNTER_LOCK.lock().unwrap();
        crate::validate::reset_validate_fail_count();
        let mut out = Vec::new();
        NamedTags(vec![Integer(1), Integer(2)]).ber_encode(&mut out);
        assert_eq!(crate::validate::validate_fail_count(), 0);
    }

    #[test]
    fn named_seqof_too_many_elements_bumps_the_validate_counter() {
        let _guard = crate::validate::tests::COUNTER_LOCK.lock().unwrap();
        crate::validate::reset_validate_fail_count();
        let mut out = Vec::new();
        NamedTags(vec![Integer(1), Integer(2), Integer(3), Integer(4)]).ber_encode(&mut out);
        assert_eq!(crate::validate::validate_fail_count(), 1);
    }
}

impl<T> crate::type_tag::TypeTag for SeqOf<T> {
    const TAG: Option<Tag> = Some(SEQUENCE_TAG);
}

impl<T> crate::type_tag::TypeTag for SetOf<T> {
    const TAG: Option<Tag> = Some(SET_TAG);
}
