//! CHOICE spec — X.680 §29. Walked by BER (`ber::choice`), XER
//! (`xer::choice`), JER (`jer::choice`) and PER (`per::choice`).
//!
//! **gambas-asn1#674/#675**: same zero-trait-object design as
//! `sequence.rs` — see that module's doc for the rationale. Each
//! `Alternative<T>`'s codec fields perform the complete operation for
//! that one alternative's payload inline; nothing here ever coerces a
//! payload to `&dyn Trait`.

use crate::ber::reader::{DecodeError, Reader};
use crate::ber::tag::Tag;
use crate::jer::reader::Reader as JerReader;
use crate::per::reader::{DecodeError as PerDecodeError, Reader as PerReader};
use crate::per::writer::Writer as PerWriter;
use crate::xer::reader::XerReader;

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

/// One CHOICE alternative — shared by BER, XER, JER and PER (see module
/// doc). `ber_encode`/`ber_decode` etc. each perform this *one*
/// alternative's complete payload operation — `ber_decode` also emplaces
/// the variant (`*x = MyEnum::ThisAlt(Default::default())`) before
/// decoding into it, fusing what used to be two steps (`emplace` +
/// `.xer_decode_into`) into one closure, same reasoning as
/// `sequence.rs::MemberDescriptor`'s fused accessors.
pub struct Alternative<T: 'static> {
    pub name: &'static str,
    pub ber: BerTagging,
    /// `true` iff `value` currently holds this alternative. Used by the
    /// encode-side walkers to find which row to call; `ChoiceSpec::
    /// active_index` (below) is the preferred, O(1) way to do the same
    /// thing via one match on `T`'s own discriminant — this field stays
    /// for call sites that need a single alternative's status without
    /// walking the whole table (BER tag validation, mainly).
    pub is_active: fn(&T) -> bool,
    /// `Some(reason)` when PER cannot encode this alternative yet; panics
    /// with the reason only if reached.
    pub per_unsupported: Option<&'static str>,

    pub ber_encode: fn(&T, &mut Vec<u8>),
    pub ber_decode: fn(&mut T, &mut Reader) -> Result<(), DecodeError>,
    pub xer_encode: fn(&T, &mut String, usize),
    pub xer_decode: fn(&mut T, &mut XerReader) -> Result<(), DecodeError>,
    pub jer_encode: fn(&T, &mut String),
    pub jer_decode: fn(&mut T, &mut JerReader) -> Result<(), DecodeError>,
    pub per_encode: fn(&T, &mut PerWriter),
    pub per_decode: fn(&mut T, &mut PerReader) -> Result<(), PerDecodeError>,
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
/// byte-identically even for content this crate can't interpret.
///
/// BER/decode-side only. XER has no raw-bytes escape hatch the way BER's
/// self-delimiting TLV framing does (X.693 needs to know an element's
/// structure to parse it at all) — a value holding captured unknown-
/// extension content can't be XER-encoded (panics, same as the "no
/// alternative matched" codegen-bug backstop, since from XER's
/// perspective there genuinely is no matching alternative).
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
    /// X.691 §22.6: bit width of the root-alternative index. PER-only;
    /// BER/XER ignore it.
    pub range_bits: u32,
    /// Which `alternatives[]` entry `value` currently holds, computed via
    /// one match on `T`'s own discriminant (codegen emits
    /// `|x| match x { MyEnum::A(_) => Some(0), MyEnum::B(_) => Some(1), ... }`)
    /// — O(1), and the reason `active_alt` below no longer needs to
    /// linear-scan `alternatives` checking each `is_active` in turn.
    pub active_index: fn(&T) -> Option<usize>,
}

/// The alternative `value` currently holds, if any.
pub(crate) fn active_alt<'a, T>(spec: &'a ChoiceSpec<T>, value: &'a T) -> Option<(usize, &'a Alternative<T>)> {
    let i = (spec.active_index)(value)?;
    Some((i, &spec.alternatives[i]))
}
