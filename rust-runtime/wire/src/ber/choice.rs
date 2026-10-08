//! CHOICE encode/decode — X.680 §29, X.690 §8.13.
//!
//! Table-driven, mirroring
//! `MemberDescriptor<T>`/`SequenceSpec<T>` (`sequence.rs`) and the C++
//! side's `ChoiceSpec`/`ChoiceBerHandler`/`ChoiceXerHandler`
//! (`runtime/src/BerCodec.cpp`/`XerCodec.cpp`): `encode_choice`/
//! `decode_choice`/`encode_choice_xer`/`decode_choice_xer` are generic,
//! driven entirely by an `AlternativeSpec<T>` table — no per-type codegen'd
//! `match`/`if` chain, for either wire format.
//!
//! `ChoiceSpec<T>::name`, unlike a member-position CHOICE, has exactly one
//! job: the X.680 §16.2/X.693 §8.3.1 document-root wrapper. A CHOICE has
//! no outer wrapper *as a SEQUENCE/SET/CHOICE member* — X.690 §8.13.1:
//! "the value is that of the chosen alternative", so the wire tag IS the
//! chosen alternative's own tag; `ChoiceXerHandler`
//! (`runtime/src/XerCodec.cpp`) confirms the same in XER for the member
//! case (encodes/decodes using the *alternative's* name, never the CHOICE
//! type's own name — no `<Choice>` wrapper the way `SequenceXerHandler`
//! wraps every member in `<Widget>`). But X.693 §8.3.1 requires the XML
//! *document element* — the outermost value in a standalone encoding —
//! to always be an "XMLTypedValue" (`<TypeName>...</TypeName>`),
//! CHOICE included (confirmed against real asn1c output: a root-level
//! `Alt4` value encodes as `<Alt4>\n<str>j</str>\n</Alt4>`, not bare
//! `<str>j</str>`). `encode_choice_xer`/`decode_choice_xer` (the
//! top-level, non-`_into`/`_from` entry points a generated CHOICE's own
//! `encode_xer()`/`decode_xer()` call) are the only place this wrapper
//! applies — the `_into`/`_from` variants used for nested/member CHOICE
//! stay wrapper-free. `own_tag` (below) is the unrelated BER-side
//! exception: a CHOICE *type assignment* can declare its own top-level
//! `[n]`, which — since CHOICE has no natural tag to substitute into
//! (X.680 §30.6) — always wraps the whole alternative-dispatch encoding
//! in an outer TLV.
//!
//! Each alternative's own `ber_encode`/`ber_decode`/etc. (`spec::choice`,
//! gambas-asn1#675) performs its one variant's complete operation inline
//! — no `&dyn Asn1Value` accessor anywhere, `is_active`/`ChoiceSpec::
//! active_index` identify which row is live without needing one either.
//! BER decode dispatch uses the precomputed `ChoiceSpec::ber_tags` table
//! (wire tag -> alternative index, X.690 §8.13); PER uses the alternative's
//! position (X.691 §23).
//!
//! `Choice` (in `tests` below) is both the worked example and this module's
//! own test subject (dogfooding, same role `Point` plays for `sequence.rs`)
//! — real table-driven code, generated for real ASN.1 schemas by
//! `RustBackend`. Test-only (`#[cfg(test)]`, not part of this crate's
//! public API) — a worked example doesn't need to be a permanent public
//! type just to be readable as one.

use crate::ber::reader::{read_explicit, DecodeError, Reader};
use crate::ber::tag::Tag;
use crate::spec::choice::{active_alt, AlternativeAccess, ChoiceSpec};
use crate::spec::primitive::{ber_decode_primitive, ber_encode_primitive};
use crate::ber::writer::{write_explicit, write_primitive, write_tagged};
// Only this file's own dogfood tests call the XER leg directly by name —
// real generated code reaches it via the full `xer::choice::`/`xer::reader::`
// path (RustBackend.cpp), so these would warn as unused outside test builds.
#[cfg(test)]
use crate::xer::choice::{decode_choice_xer, decode_choice_xer_into, encode_choice_xer, encode_choice_xer_into};
#[cfg(test)]
use crate::xer::reader::XerReader;

/// Generic CHOICE encoder — the Rust analogue of `ChoiceBerHandler::encode`.
/// Falls back to `unknown_extension` (if present) for a value holding
/// captured not-yet-defined-extension content, writing the raw captured
/// tag+bytes back out unchanged. Panics if neither matches: cannot happen
/// for a real generated `T`, so this is a codegen-bug backstop.
pub fn encode_choice<T>(spec: &ChoiceSpec<T>, value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    encode_choice_into(spec, value, &mut out);
    out
}

/// The alternative-dispatch encoding (X.680 §28 — no outer wrapper of its
/// own), before any `own_tag` wrap. Also the building block
/// `encode_choice_tagged` reuses for IMPLICIT retagging. Writes directly
/// into `out` (`write_tagged`'s in-place reserve-and-backfill, via each
/// alternative's own `ber_encode*` call) — no separate `Vec` per CHOICE
/// value encoded.
fn encode_choice_dispatch_into<T>(spec: &ChoiceSpec<T>, value: &T, out: &mut Vec<u8>) {
    if let Some((_, alt)) = active_alt(spec, value) {
        match &alt.access {
            AlternativeAccess::Primitive { ber, get, .. } => ber_encode_primitive(get(value), *ber, out),
            AlternativeAccess::Composite { ber_encode, .. } => ber_encode(value, out),
            AlternativeAccess::Unsupported { reason } => panic!("alternative '{}' not supported: {reason}", alt.name),
        }
        return;
    }
    if let Some(ops) = &spec.unknown_extension {
        if let Some((tag, bytes)) = (ops.extract)(value) {
            write_primitive(out, tag, bytes);
            return;
        }
    }
    panic!("encode_choice: no alternative matched — codegen/table mismatch");
}

/// Appends a CHOICE's encoding to an existing buffer — the shape
/// `Asn1Value::ber_encode` needs. In-place, no separate `Vec` copied in.
pub fn encode_choice_into<T>(spec: &ChoiceSpec<T>, value: &T, out: &mut Vec<u8>) {
    match spec.own_tag {
        Some(tag) => write_explicit(out, tag, |inner| encode_choice_dispatch_into(spec, value, inner)),
        None => encode_choice_dispatch_into(spec, value, out),
    }
}

/// IMPLICIT-retags a CHOICE-with-own_tag value under `tag` instead of its
/// own declared `[n]` (X.680 §22.5/§28.4): the content is the same raw
/// alternative-dispatch bytes `own_tag`'s EXPLICIT wrap would carry
/// (X.690 §8.14.2). A generated CHOICE-with-own_tag type's
/// `Asn1Value::ber_encode_tagged` is a one-line call to this.
pub fn encode_choice_tagged<T>(spec: &ChoiceSpec<T>, value: &T, tag: Tag, out: &mut Vec<u8>) {
    write_tagged(out, tag, |out| encode_choice_dispatch_into(spec, value, out));
}

/// Decode counterpart of `encode_choice_tagged`.
pub fn decode_choice_tagged_into<T>(spec: &ChoiceSpec<T>, value: &mut T, r: &mut Reader, tag: Tag) -> Result<(), DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag.class != tag.class || tlv.tag.number != tag.number {
        return Err(DecodeError::new(format!("expected tag {tag:?}, got {:?}", tlv.tag), r.pos()));
    }
    let mut inner = Reader::new(tlv.value);
    decode_choice_dispatch(spec, value, &mut inner)
}

/// Generic CHOICE decoder — the Rust analogue of `ChoiceBerHandler::decode`.
pub fn decode_choice<T: Default>(spec: &ChoiceSpec<T>, data: &[u8]) -> Result<T, DecodeError> {
    let mut r = Reader::new(data);
    let mut value = T::default();
    decode_choice_into(spec, &mut value, &mut r)?;
    Ok(value)
}

/// Reads a CHOICE from the caller's current stream position into `value` —
/// the shape `Asn1Value::ber_decode_into` needs.
pub fn decode_choice_into<T>(spec: &ChoiceSpec<T>, value: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
    match spec.own_tag {
        Some(tag) => read_explicit(r, tag, |inner| decode_choice_dispatch(spec, value, inner)),
        None => decode_choice_dispatch(spec, value, r),
    }
}

/// Peeks the wire tag, selects the alternative through `ber_tags` and
/// decodes its payload in place. Falls back to `unknown_extension` (if
/// present) by capturing the whole TLV instead of erroring, honoring the
/// schema's forward-compatibility promise.
fn decode_choice_dispatch<T>(spec: &ChoiceSpec<T>, value: &mut T, r: &mut Reader) -> Result<(), DecodeError> {
    let tag = r.peek_tag().ok_or_else(|| DecodeError::new("empty CHOICE input".to_string(), 0))?;
    debug_assert!(
        spec.ber_tags.windows(2).all(|w| w[0].tag.identifier_key() <= w[1].tag.identifier_key()),
        "ChoiceSpec::ber_tags must be sorted by Tag::identifier_key for binary_search_by_key (codegen bug)"
    );
    let found = spec
        .ber_tags
        .binary_search_by_key(&tag.identifier_key(), |d| d.tag.identifier_key())
        .ok()
        .map(|i| &spec.ber_tags[i]);
    if let Some(d) = found {
        let alt = &spec.alternatives[d.alt];
        return match &alt.access {
            AlternativeAccess::Primitive { ber, get_mut, .. } => ber_decode_primitive(get_mut(value), *ber, r),
            AlternativeAccess::Composite { ber_decode, .. } => ber_decode(value, r),
            AlternativeAccess::Unsupported { reason } => panic!("alternative '{}' not supported: {reason}", alt.name),
        };
    }
    if let Some(ops) = &spec.unknown_extension {
        let tlv = r.read_tlv()?;
        *value = (ops.construct)(tlv.tag, tlv.value.to_vec());
        return Ok(());
    }
    if crate::debug::debug_flags() & crate::debug::DBG_BER_CHOICE != 0 {
        let alt_tags: Vec<Tag> = spec.ber_tags.iter().map(|d| d.tag).collect();
        eprintln!(
            "[DBG_BER_CHOICE] {}: no alternative matches peek tag {tag:?} — known tags: {alt_tags:?}",
            std::any::type_name::<T>()
        );
    }
    Err(DecodeError::new(
        format!("unrecognized CHOICE alternative tag {tag:?} for {}", std::any::type_name::<T>()),
        0,
    ))
}

#[cfg(test)]
mod tests {
    use crate::integer::Integer;
    use super::*;
    use crate::spec::choice::{Alternative, BerDispatch, UnknownExtensionOps};
    use crate::value::Asn1Value;

/// `Choice ::= CHOICE { num INTEGER, data OCTET STRING }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Num(Integer),
    Data(crate::octet_string::OctetString),
}

impl Default for Choice {
    fn default() -> Self {
        Choice::Num(Integer(0))
    }
}

// Dogfood-fixture-only helpers (gambas-asn1#675): generates the full
// 10-field `Alternative` literal for the common "one-field enum variant,
// same BER framing kind" shape, so the fixtures below don't repeat the
// same match-and-call boilerplate per codec per alternative. Real codegen
// (RustBackend.cpp) emits the equivalent text directly, no macro there —
// this exists purely to keep this file's hand-written dogfood fixtures
// readable.
macro_rules! implicit_alt {
    ($name:expr, $tag:expr, $Enum:ident :: $Variant:ident) => {
        Alternative {
            name: $name,
            is_active: |x| matches!(x, $Enum::$Variant(_)),
            per_unsupported: None,
            access: AlternativeAccess::Composite {
                ber_encode: |x, out| match x { $Enum::$Variant(v) => v.ber_encode_tagged($tag, out), _ => unreachable!() },
                ber_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.ber_decode_into_tagged(r, $tag), _ => unreachable!() } },
                xer_encode: |x, out, depth| match x { $Enum::$Variant(v) => v.xer_encode(out, depth), _ => unreachable!() },
                xer_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.xer_decode_into(r), _ => unreachable!() } },
                jer_encode: |x, out| match x { $Enum::$Variant(v) => v.jer_encode(out), _ => unreachable!() },
                jer_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.jer_decode_into(r), _ => unreachable!() } },
                per_encode: |x, w| match x { $Enum::$Variant(v) => v.per_encode(w, &crate::constraints::UNCONSTRAINED), _ => unreachable!() },
                per_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.per_decode_into(r, &crate::constraints::UNCONSTRAINED), _ => unreachable!() } },
            },
        }
    };
}

macro_rules! explicit_alt {
    ($name:expr, $tag:expr, $Enum:ident :: $Variant:ident) => {
        Alternative {
            name: $name,
            is_active: |x| matches!(x, $Enum::$Variant(_)),
            per_unsupported: None,
            access: AlternativeAccess::Composite {
                ber_encode: |x, out| match x { $Enum::$Variant(v) => v.ber_encode_explicit(out, $tag), _ => unreachable!() },
                ber_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.ber_decode_into_explicit(r, $tag), _ => unreachable!() } },
                xer_encode: |x, out, depth| match x { $Enum::$Variant(v) => v.xer_encode(out, depth), _ => unreachable!() },
                xer_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.xer_decode_into(r), _ => unreachable!() } },
                jer_encode: |x, out| match x { $Enum::$Variant(v) => v.jer_encode(out), _ => unreachable!() },
                jer_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.jer_decode_into(r), _ => unreachable!() } },
                per_encode: |x, w| match x { $Enum::$Variant(v) => v.per_encode(w, &crate::constraints::UNCONSTRAINED), _ => unreachable!() },
                per_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.per_decode_into(r, &crate::constraints::UNCONSTRAINED), _ => unreachable!() } },
            },
        }
    };
}

macro_rules! delegate_alt {
    ($name:expr, $Enum:ident :: $Variant:ident) => {
        Alternative {
            name: $name,
            is_active: |x| matches!(x, $Enum::$Variant(_)),
            per_unsupported: None,
            access: AlternativeAccess::Composite {
                ber_encode: |x, out| match x { $Enum::$Variant(v) => v.ber_encode(out), _ => unreachable!() },
                ber_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.ber_decode_into(r), _ => unreachable!() } },
                xer_encode: |x, out, depth| match x { $Enum::$Variant(v) => v.xer_encode(out, depth), _ => unreachable!() },
                xer_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.xer_decode_into(r), _ => unreachable!() } },
                jer_encode: |x, out| match x { $Enum::$Variant(v) => v.jer_encode(out), _ => unreachable!() },
                jer_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.jer_decode_into(r), _ => unreachable!() } },
                per_encode: |x, w| match x { $Enum::$Variant(v) => v.per_encode(w, &crate::constraints::UNCONSTRAINED), _ => unreachable!() },
                per_decode: |x, r| { *x = $Enum::$Variant(Default::default()); match x { $Enum::$Variant(v) => v.per_decode_into(r, &crate::constraints::UNCONSTRAINED), _ => unreachable!() } },
            },
        }
    };
}

static CHOICE_ALTERNATIVES: [Alternative<Choice>; 2] = [
    implicit_alt!("num", crate::integer::INTEGER_TAG, Choice::Num),
    implicit_alt!("data", crate::octet_string::OCTET_STRING_TAG, Choice::Data),
];

static CHOICE_TAGS: [BerDispatch; 2] = [
    BerDispatch { tag: crate::integer::INTEGER_TAG, alt: 0 },
    BerDispatch { tag: crate::octet_string::OCTET_STRING_TAG, alt: 1 },
];

static CHOICE_SPEC: ChoiceSpec<Choice> = ChoiceSpec { name: "Choice", alternatives: &CHOICE_ALTERNATIVES, ber_tags: &CHOICE_TAGS, unknown_extension: None, own_tag: None, ext_at: -1, range_bits: 1,
    active_index: |x| match x { Choice::Num(_) => Some(0), Choice::Data(_) => Some(1) } };

impl Choice {
    pub fn encode(&self) -> Vec<u8> {
        encode_choice(&CHOICE_SPEC, self)
    }

    pub fn decode(data: &[u8]) -> Result<Choice, DecodeError> {
        decode_choice(&CHOICE_SPEC, data)
    }

    pub fn encode_xer(&self) -> String {
        encode_choice_xer(&CHOICE_SPEC, self)
    }

    pub fn decode_xer(xml: &str) -> Result<Choice, DecodeError> {
        decode_choice_xer(&CHOICE_SPEC, xml)
    }

    pub fn encode_jer(&self) -> String {
        crate::jer::choice::encode_choice_jer(&CHOICE_SPEC, self)
    }

    pub fn decode_jer(json: &str) -> Result<Choice, DecodeError> {
        crate::jer::choice::decode_choice_jer(&CHOICE_SPEC, json)
    }
}


    #[test]
    fn encodes_num_alternative() {
        assert_eq!(Choice::Num(Integer(5)).encode(), vec![0x02, 0x01, 0x05]);
    }

    #[test]
    fn encodes_data_alternative() {
        assert_eq!(Choice::Data(crate::octet_string::OctetString(vec![1, 2, 3])).encode(), vec![0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn round_trips_both_alternatives() {
        for c in [Choice::Num(Integer(-42)), Choice::Data(crate::octet_string::OctetString(vec![0xAA, 0xBB]))] {
            let bytes = c.encode();
            assert_eq!(Choice::decode(&bytes).unwrap(), c);
        }
    }

    #[test]
    fn unrecognized_tag_is_error() {
        let data = [0x30, 0x00]; // SEQUENCE tag — not a Choice alternative
        assert!(Choice::decode(&data).is_err());
    }

    // own_tag: a CHOICE type assignment's own declared [n] (X.680 §30.6,
    // always EXPLICIT) wraps the normal alternative-dispatch encoding in an
    // outer TLV. Byte-identical to the C++ side's MyExplicitChoice test
    // (tests/seq/test_toplevel_tag.cpp) and to real asn1c ground truth for
    // the same construct: a9 03 02 01 2a.
    #[test]
    fn own_tag_wraps_the_alternative_dispatch_encoding() {
        let tag = crate::ber::tag::Tag {
            class: crate::ber::tag::TagClass::Context,
            number: 9,
            constructed: true,
        };
        let spec = ChoiceSpec { name: "Choice", alternatives: &CHOICE_ALTERNATIVES, ber_tags: &CHOICE_TAGS, unknown_extension: None, own_tag: Some(tag), ext_at: -1, range_bits: 1,
            active_index: |x| match x { Choice::Num(_) => Some(0), Choice::Data(_) => Some(1) } };
        let enc = encode_choice(&spec, &Choice::Num(Integer(42)));
        assert_eq!(enc, vec![0xa9, 0x03, 0x02, 0x01, 0x2a]);

        let decoded = decode_choice(&spec, &enc).unwrap();
        assert_eq!(decoded, Choice::Num(Integer(42)));
    }

    #[test]
    fn empty_input_is_error() {
        assert!(Choice::decode(&[]).is_err());
    }

    #[test]
    fn xer_encodes_num_alternative() {
        // Ground truth from the real C++ runtime (XerCodec::encode): root
        // CHOICE gets the X.693 §8.3.1 document-element wrapper.
        assert_eq!(Choice::Num(Integer(7)).encode_xer(), "<Choice>\n    <num>7</num>\n</Choice>\n");
    }

    #[test]
    fn xer_encodes_data_alternative() {
        assert_eq!(Choice::Data(crate::octet_string::OctetString(vec![0x68, 0x69])).encode_xer(), "<Choice>\n    <data>6869</data>\n</Choice>\n");
    }

    #[test]
    fn xer_round_trips_both_alternatives() {
        for c in [Choice::Num(Integer(-42)), Choice::Data(crate::octet_string::OctetString(vec![0xAA, 0xBB]))] {
            let xml = c.encode_xer();
            assert_eq!(Choice::decode_xer(&xml).unwrap(), c);
        }
    }

    #[test]
    fn xer_unrecognized_element_is_error() {
        assert!(Choice::decode_xer("<nope>1</nope>").is_err());
    }

    #[test]
    fn xer_empty_input_is_error() {
        assert!(Choice::decode_xer("").is_err());
    }

    #[test]
    fn jer_encodes_num_alternative() {
        // Ground truth from the real C++ runtime (JerCodec.cpp): single-key
        // object, no outer document wrapper (JER has no X.693-§8.3.1-style
        // document-element ceremony to mirror).
        assert_eq!(Choice::Num(Integer(7)).encode_jer(), "{\"num\":7}");
    }

    #[test]
    fn jer_encodes_data_alternative() {
        assert_eq!(
            Choice::Data(crate::octet_string::OctetString(vec![0x68, 0x69])).encode_jer(),
            "{\"data\":\"6869\"}"
        );
    }

    #[test]
    fn jer_round_trips_both_alternatives() {
        for c in [Choice::Num(Integer(-42)), Choice::Data(crate::octet_string::OctetString(vec![0xAA, 0xBB]))] {
            let json = c.encode_jer();
            assert_eq!(Choice::decode_jer(&json).unwrap(), c);
        }
    }

    #[test]
    fn jer_unrecognized_key_is_error() {
        assert!(Choice::decode_jer("{\"nope\":1}").is_err());
    }

    #[test]
    fn jer_empty_object_decodes_to_default() {
        // No active alternative -> `{}`, not a panic (JER has no tag to be
        // "wrong" about, unlike BER/XER).
        assert_eq!(Choice::decode_jer("{}").unwrap(), Choice::default());
    }

    // ---- EXPLICIT tag disambiguation ---------------------

    /// Regression guard for the exact worst-case scenario #346 was filed
    /// for (mirrors `tests/asn1/choice_tagged_alt_test.asn1`'s
    /// `TwoOctetsExplicit`, exercised here at the runtime layer directly
    /// since this crate has no codegen wired in): two alternatives of the
    /// *same* builtin kind, disambiguated only by their EXPLICIT outer
    /// tags. Before #346's fix both would have used the natural
    /// `OCTET_STRING_TAG` and been wire-indistinguishable, so
    /// `decode_choice`'s linear tag scan would misdecode one into the
    /// other.
    enum TwoOctetsExplicit {
        First(crate::octet_string::OctetString),
        Second(crate::octet_string::OctetString),
    }

    impl Default for TwoOctetsExplicit {
        fn default() -> Self {
            TwoOctetsExplicit::First(Default::default())
        }
    }

    const TAG_1: Tag = Tag::context(1, true);
    const TAG_2: Tag = Tag::context(2, true);

    static TWO_OCTETS_EXPLICIT_ALTERNATIVES: [Alternative<TwoOctetsExplicit>; 2] = [
        explicit_alt!("first", TAG_1, TwoOctetsExplicit::First),
        explicit_alt!("second", TAG_2, TwoOctetsExplicit::Second),
    ];

    static TWO_OCTETS_EXPLICIT_TAGS: [BerDispatch; 2] = [BerDispatch { tag: TAG_1, alt: 0 }, BerDispatch { tag: TAG_2, alt: 1 }];

    static TWO_OCTETS_EXPLICIT_SPEC: ChoiceSpec<TwoOctetsExplicit> =
        ChoiceSpec { name: "TwoOctetsExplicit", alternatives: &TWO_OCTETS_EXPLICIT_ALTERNATIVES, ber_tags: &TWO_OCTETS_EXPLICIT_TAGS, unknown_extension: None, own_tag: None, ext_at: -1, range_bits: 1,
            active_index: |x| match x { TwoOctetsExplicit::First(_) => Some(0), TwoOctetsExplicit::Second(_) => Some(1) } };

    #[test]
    fn explicit_disambiguates_two_alternatives_of_the_same_builtin_kind() {
        let first = TwoOctetsExplicit::First(crate::octet_string::OctetString(vec![0xAA]));
        let second = TwoOctetsExplicit::Second(crate::octet_string::OctetString(vec![0xAA])); // same content, different alternative

        let enc_first = encode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &first);
        let enc_second = encode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &second);

        // [1]/[2] EXPLICIT (0xA1/0xA2) wrapping OCTET STRING 0xAA (0x04 0x01 0xAA) —
        // must be wire-distinguishable, unlike the pre-fix natural-tag collision.
        assert_eq!(enc_first, vec![0xA1, 0x03, 0x04, 0x01, 0xAA]);
        assert_eq!(enc_second, vec![0xA2, 0x03, 0x04, 0x01, 0xAA]);
        assert_ne!(enc_first, enc_second);

        match decode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &enc_first).unwrap() {
            TwoOctetsExplicit::First(v) => assert_eq!(v.0, vec![0xAA]),
            TwoOctetsExplicit::Second(_) => panic!("misdecoded First as Second"),
        }
        match decode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &enc_second).unwrap() {
            TwoOctetsExplicit::Second(v) => assert_eq!(v.0, vec![0xAA]),
            TwoOctetsExplicit::First(_) => panic!("misdecoded Second as First"),
        }
    }

    // ---- unknown_extension ---------------------------------------------

    /// `ExtChoice ::= CHOICE { num INTEGER, ... }` — mirrors a real schema
    /// pattern (e.g. the ETSI LI PS-PDU schema's `AdditionalSignalling`/
    /// `PstnIsdnIRIContents`, both `CHOICE { <one alternative>, ... }` with
    /// nothing declared after the marker yet): today's compiler run only
    /// knows about `Num`, but the `...` promises a future revision may add
    /// more.
    #[derive(Debug, Clone, PartialEq)]
    enum ExtChoice {
        Num(Integer),
        UnknownExtension(Tag, Vec<u8>),
    }

    impl Default for ExtChoice {
        fn default() -> Self {
            ExtChoice::Num(Integer(0))
        }
    }

    const NUM_TAG: Tag = Tag::context(0, false);

    static EXT_CHOICE_ALTERNATIVES: [Alternative<ExtChoice>; 1] = [
        implicit_alt!("num", NUM_TAG, ExtChoice::Num),
    ];

    static EXT_CHOICE_TAGS: [BerDispatch; 1] = [BerDispatch { tag: NUM_TAG, alt: 0 }];

    static EXT_CHOICE_SPEC: ChoiceSpec<ExtChoice> = ChoiceSpec {
        name: "ExtChoice",
        alternatives: &EXT_CHOICE_ALTERNATIVES,
        ber_tags: &EXT_CHOICE_TAGS,
        unknown_extension: Some(UnknownExtensionOps {
            construct: |tag, bytes| ExtChoice::UnknownExtension(tag, bytes),
            extract: |x| match x {
                ExtChoice::UnknownExtension(tag, bytes) => Some((*tag, bytes.as_slice())),
                _ => None,
            },
        }),
        own_tag: None,
        ext_at: 1,
        range_bits: 0,
        active_index: |x| match x { ExtChoice::Num(_) => Some(0), ExtChoice::UnknownExtension(..) => None },
    };

    #[test]
    fn known_alternative_still_decodes_normally() {
        let v = ExtChoice::Num(Integer(42));
        let enc = encode_choice(&EXT_CHOICE_SPEC, &v);
        assert_eq!(decode_choice(&EXT_CHOICE_SPEC, &enc).unwrap(), v);
    }

    #[test]
    fn unrecognized_tag_captured_instead_of_erroring() {
        // A hypothetical future alternative, tag [1], that EXT_CHOICE_SPEC's
        // table has never heard of.
        let future_tag = Tag::context(1, false);
        let mut wire = Vec::new();
        write_primitive(&mut wire, future_tag, &[0xDE, 0xAD, 0xBE, 0xEF]);

        let decoded = decode_choice(&EXT_CHOICE_SPEC, &wire).unwrap();
        assert_eq!(decoded, ExtChoice::UnknownExtension(future_tag, vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn unrecognized_tag_round_trips_byte_identically() {
        let future_tag = Tag::context(5, true); // constructed, to prove the tag's own bit round-trips too
        let mut wire = Vec::new();
        write_primitive(&mut wire, future_tag, &[0x01, 0x02, 0x03]);

        let decoded = decode_choice(&EXT_CHOICE_SPEC, &wire).unwrap();
        let re_encoded = encode_choice(&EXT_CHOICE_SPEC, &decoded);
        assert_eq!(re_encoded, wire);
    }

    #[test]
    fn closed_choice_without_unknown_extension_still_errors_on_unrecognized_tag() {
        // TWO_OCTETS_EXPLICIT_SPEC has unknown_extension: None — confirms the
        // fallback is opt-in, not a silent behavior change for every CHOICE.
        let data = [0x85, 0x01, 0x00]; // context primitive 5, matches neither TAG_1 nor TAG_2
        assert!(decode_choice(&TWO_OCTETS_EXPLICIT_SPEC, &data).is_err());
    }

    // ---- untagged CHOICE-of-CHOICE alternative (flattened dispatch) ------

    /// `Inner ::= CHOICE { a [1] INTEGER, b [2] INTEGER }` — the type an
    /// untagged CHOICE-of-CHOICE alternative (`Outer::Wrapped` below)
    /// delegates to.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Inner {
        A(Integer),
        B(Integer),
    }

    impl Default for Inner {
        fn default() -> Self { Inner::A(Integer(0)) }
    }

    const INNER_A_TAG: Tag = Tag::context(1, false);
    const INNER_B_TAG: Tag = Tag::context(2, false);

    static INNER_ALTERNATIVES: [Alternative<Inner>; 2] = [
        implicit_alt!("a", INNER_A_TAG, Inner::A),
        implicit_alt!("b", INNER_B_TAG, Inner::B),
    ];

    static INNER_TAGS: [BerDispatch; 2] = [BerDispatch { tag: INNER_A_TAG, alt: 0 }, BerDispatch { tag: INNER_B_TAG, alt: 1 }];

    static INNER_SPEC: ChoiceSpec<Inner> = ChoiceSpec { name: "Inner", alternatives: &INNER_ALTERNATIVES, ber_tags: &INNER_TAGS, unknown_extension: None, own_tag: None, ext_at: -1, range_bits: 1,
        active_index: |x| match x { Inner::A(_) => Some(0), Inner::B(_) => Some(1) } };

    impl Asn1Value for Inner {
        fn ber_natural_tag(&self) -> Tag { unreachable!("CHOICE has no natural tag") }
        fn xer_element_name(&self) -> &'static str { "Inner" }
        fn ber_encode_content(&self, _out: &mut Vec<u8>) { unreachable!() }
        fn ber_decode_content(&mut self, _content: &[u8]) -> Result<(), DecodeError> { unreachable!() }
        fn ber_encode(&self, out: &mut Vec<u8>) { encode_choice_into(&INNER_SPEC, self, out); }
        fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
            decode_choice_into(&INNER_SPEC, self, r)
        }
        fn xer_encode(&self, out: &mut String, depth: usize) {
            encode_choice_xer_into(&INNER_SPEC, self, out, depth);
            out.push('\n');
            out.push_str(&crate::xer::writer::indent(depth));
        }
        fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
            decode_choice_xer_into(&INNER_SPEC, self, r)
        }
    }

    /// `Outer ::= CHOICE { inner Inner, direct [9] OCTET STRING }` — `inner`
    /// carries no tag of its own and resolves to a CHOICE (`Inner`), so its
    /// real BER dispatch tags are the union of `Inner`'s own alternative
    /// tags (X.680 §28 — CHOICE has no universal tag; X.690 §8.13
    /// dispatches straight through to whichever alternative the value
    /// actually is). Mirrors the real gap found on the ETSI LI PS-PDU
    /// schema (`GcseIRIsContent`, whose `gcseiRIContent` alternative
    /// resolves to a 4-alternative CHOICE the same way): `RustBackend`
    /// emits one `AlternativeSpec` row per flattened inner tag, both
    /// delegating to the same `Outer::Wrapped` variant via `Inner`'s own
    /// (non-tag-substituting) `Asn1Value::ber_encode`/`ber_decode_into` —
    /// the value already carries its own real tag, whichever of `Inner`'s
    /// alternatives it turns out to be.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Outer {
        Wrapped(Inner),
        Direct(crate::octet_string::OctetString),
    }

    impl Default for Outer {
        fn default() -> Self { Outer::Wrapped(Inner::default()) }
    }

    const OUTER_DIRECT_TAG: Tag = Tag::context(9, false);

    static OUTER_ALTERNATIVES: [Alternative<Outer>; 2] = [
        delegate_alt!("inner", Outer::Wrapped),
        implicit_alt!("direct", OUTER_DIRECT_TAG, Outer::Direct),
    ];

    // The untagged CHOICE alternative contributes one dispatch entry per
    // tag of the inner CHOICE (X.690 §8.13).
    static OUTER_TAGS: [BerDispatch; 3] = [
        BerDispatch { tag: INNER_A_TAG, alt: 0 },
        BerDispatch { tag: INNER_B_TAG, alt: 0 },
        BerDispatch { tag: OUTER_DIRECT_TAG, alt: 1 },
    ];

    static OUTER_SPEC: ChoiceSpec<Outer> = ChoiceSpec { name: "Outer", alternatives: &OUTER_ALTERNATIVES, ber_tags: &OUTER_TAGS, unknown_extension: None, own_tag: None, ext_at: -1, range_bits: 1,
        active_index: |x| match x { Outer::Wrapped(_) => Some(0), Outer::Direct(_) => Some(1) } };

    impl Outer {
        fn encode(&self) -> Vec<u8> { encode_choice(&OUTER_SPEC, self) }
        fn decode(data: &[u8]) -> Result<Outer, DecodeError> { decode_choice(&OUTER_SPEC, data) }
    }

    #[test]
    fn untagged_choice_of_choice_alternative_round_trips_every_flattened_tag() {
        for v in [Outer::Wrapped(Inner::A(Integer(5))), Outer::Wrapped(Inner::B(Integer(-3))), Outer::Direct(crate::octet_string::OctetString(vec![1, 2, 3]))] {
            let bytes = v.encode();
            assert_eq!(Outer::decode(&bytes).unwrap(), v);
        }
    }

    #[test]
    fn untagged_choice_of_choice_alternative_wire_tag_is_the_inner_alternatives_own_tag() {
        // No extra wrapper is written for the untagged `inner` alternative —
        // the wire tag is directly Inner::A's own tag (context, primitive,
        // number 1 = 0x81), not some synthetic outer tag.
        let bytes = Outer::Wrapped(Inner::A(Integer(5))).encode();
        assert_eq!(bytes[0], 0x81);
    }

    #[test]
    fn decode_choice_from_matches_a_row_even_when_its_stored_constructed_bit_is_wrong() {
        // Isolates exactly what `Tag::matches_identifier` (vs plain `==`)
        // buys `decode_choice_from`: a row's table tag disagreeing with the
        // wire's real constructed bit still dispatches correctly. This is
        // the real shape of the bug found on the ETSI LI PS-PDU schema — a
        // flattened dispatch entry (`Generator::collect_ber_tags_for`,
        // reached through a `TypeRef`) can't always resolve the correct
        // constructed bit, but C++'s own `BerCodec.cpp` dispatch never
        // checks it either (every site there compares `cls`/`number` only).
        // Payload that frames itself, so the wire tag is never checked
        // against the table's stored constructed bit.
        #[derive(Default)]
        struct Raw(u8);
        impl Asn1Value for Raw {
            fn ber_natural_tag(&self) -> Tag { unreachable!() }
            fn ber_encode_content(&self, _out: &mut Vec<u8>) { unreachable!() }
            fn ber_decode_content(&mut self, _content: &[u8]) -> Result<(), DecodeError> { unreachable!() }
            fn ber_encode(&self, out: &mut Vec<u8>) { write_primitive(out, Tag::context(1, false), &[self.0]); }
            fn ber_decode_into(&mut self, r: &mut Reader) -> Result<(), DecodeError> {
                self.0 = r.read_tlv()?.value[0];
                Ok(())
            }
        }
        enum Solo {
            V(Raw),
        }
        impl Default for Solo {
            fn default() -> Self { Solo::V(Raw(0)) }
        }
        static ROW: [Alternative<Solo>; 1] = [Alternative {
            name: "v",
            is_active: |_| true,
            per_unsupported: None,
            access: AlternativeAccess::Composite {
                ber_encode: |x, out| { let Solo::V(v) = x; v.ber_encode(out); },
                ber_decode: |x, r| { *x = Solo::V(Raw(0)); let Solo::V(v) = x; v.ber_decode_into(r) },
                xer_encode: |x, out, depth| { let Solo::V(v) = x; v.xer_encode(out, depth); },
                xer_decode: |x, r| { *x = Solo::V(Raw(0)); let Solo::V(v) = x; v.xer_decode_into(r) },
                jer_encode: |x, out| { let Solo::V(v) = x; v.jer_encode(out); },
                jer_decode: |x, r| { *x = Solo::V(Raw(0)); let Solo::V(v) = x; v.jer_decode_into(r) },
                per_encode: |x, w| { let Solo::V(v) = x; v.per_encode(w, &crate::constraints::UNCONSTRAINED); },
                per_decode: |x, r| { *x = Solo::V(Raw(0)); let Solo::V(v) = x; v.per_decode_into(r, &crate::constraints::UNCONSTRAINED) },
            },
        }];
        // Deliberately the wrong constructed bit in the dispatch tag.
        static TAGS: [BerDispatch; 1] = [BerDispatch { tag: Tag::context(1, false), alt: 0 }];
        static SPEC: ChoiceSpec<Solo> = ChoiceSpec { name: "Solo", alternatives: &ROW, ber_tags: &TAGS, unknown_extension: None, own_tag: None, ext_at: -1, range_bits: 0,
            active_index: |_| Some(0) };

        let mut wire = Vec::new();
        write_primitive(&mut wire, Tag::context(1, true), &[0x05]); // constructed=true on the wire
        match decode_choice(&SPEC, &wire).unwrap() {
            Solo::V(v) => assert_eq!(v.0, 5),
        }
    }
}
