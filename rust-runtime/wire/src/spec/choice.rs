//! CHOICE spec — X.680 §29. Walked by BER (`choice.rs`), XER (`choice.rs`)
//! and PER (`per::choice`).

use crate::constraints::Constraints;
use crate::ber::tag::Tag;
use crate::value::Asn1Value;

/// How BER frames an alternative's payload (X.690 §8.13/§8.14).
#[derive(Clone, Copy)]
pub enum BerTagging {
    /// The alternative's tag replaces the payload's natural tag (IMPLICIT,
    /// or the natural tag itself when they coincide).
    Implicit(Tag),
    /// The payload is wrapped in an outer TLV carrying this tag (EXPLICIT).
    Explicit(Tag),
    /// The payload frames itself: an untagged CHOICE payload (X.680 §28) or
    /// a reference to an already-tagged type.
    Delegate,
    /// No BER/XER support for this alternative yet; panics with the reason
    /// if actually reached. Other alternatives are unaffected.
    Unsupported(&'static str),
}

/// One CHOICE alternative — shared by BER, XER and PER (see module doc).
pub struct Alternative<T: 'static> {
    pub name: &'static str,
    pub ber: BerTagging,
    pub active: fn(&T) -> Option<&dyn Asn1Value>,
    pub emplace: fn(&mut T) -> &mut dyn Asn1Value,
    /// The declaration's `Constraints` for the payload, handed to its
    /// `Asn1Value::per_encode`/`per_decode_into` (UNCONSTRAINED when the
    /// payload's own type carries its constraint).
    pub constraints: &'static Constraints,
    /// `Some(reason)` when PER cannot encode this alternative yet; panics
    /// with the reason only if reached.
    pub per_unsupported: Option<&'static str>,
}

/// One BER dispatch entry: a wire tag that selects `alternatives[alt]`.
/// A CHOICE-typed alternative without a tag of its own contributes one
/// entry per tag of the inner CHOICE (X.690 §8.13).
#[derive(Clone, Copy)]
pub struct BerDispatch {
    pub tag: Tag,
    pub alt: usize,
}

/// Construct/extract a value for the not-yet-defined "unknown extension"
/// case (X.680 §29.6 extensibility — a `...`-marked CHOICE promises a
/// *future* schema revision may add alternatives this compiler run never
/// saw). Captures the raw tag and value bytes of whatever TLV didn't match
/// any known `AlternativeSpec`, so decode->re-encode round-trips
/// byte-identically even for content this crate can't interpret — `Tag`
/// alone already carries the primitive/constructed bit `write_primitive`
/// needs, so one write path covers both encoding forms (see
/// `writer::write_primitive`'s own body: primitive and constructed TLVs
/// are written identically, the distinction is purely which helper the
/// *caller* reaches for elsewhere).
///
/// BER/decode-side only. XER has no raw-bytes escape hatch the way BER's
/// self-delimiting TLV framing does (X.693 needs to know an element's
/// structure to parse it at all) — `encode_choice_xer`/`decode_choice_xer`
/// don't consult this; a value holding captured unknown-extension content
/// can't be XER-encoded (panics, same as the "no alternative matched"
/// codegen-bug backstop, since from XER's perspective there genuinely is
/// no matching alternative).
pub struct UnknownExtensionOps<T: 'static> {
    pub construct: fn(Tag, Vec<u8>) -> T,
    pub extract: fn(&T) -> Option<(Tag, &[u8])>,
}

/// CHOICE table shared by every codec.
pub struct ChoiceSpec<T: 'static> {
    /// The CHOICE type's own ASN.1 name — used only for the X.693 §8.3.1
    /// document-root wrapper (`encode_choice_xer`/`decode_choice_xer`).
    pub name: &'static str,
    /// Alternatives in declaration (PER index) order.
    pub alternatives: &'static [Alternative<T>],
    /// BER decode dispatch, precomputed by codegen.
    pub ber_tags: &'static [BerDispatch],
    /// `Some` when the schema has a `...` extension marker (X.680 §29.6);
    /// `None` for a fully closed CHOICE, where an unrecognized tag is a
    /// genuine decode error.
    pub unknown_extension: Option<UnknownExtensionOps<T>>,
    /// `Some(tag)` when the CHOICE type assignment itself declares a
    /// top-level `[n]`, always EXPLICIT (X.680 §30.6): the whole
    /// alternative-dispatch encoding is wrapped in an outer TLV.
    pub own_tag: Option<Tag>,
    /// Index of the first extension alternative (X.680 §29.6); `< 0` when
    /// the CHOICE is not extensible. Read by PER only.
    pub ext_at: i32,
}

/// The alternative `value` currently holds, with its payload.
pub(crate) fn active_alt<'a, T>(spec: &'a ChoiceSpec<T>, value: &'a T) -> Option<(usize, &'a Alternative<T>, &'a dyn Asn1Value)> {
    spec.alternatives
        .iter()
        .enumerate()
        .find_map(|(i, alt)| (alt.active)(value).map(|payload| (i, alt, payload)))
}

