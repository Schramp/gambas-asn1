//! CHOICE wire-framing facts — X.680 §29. The reflective `Asn1Choice`
//! trait and the generic BER/XER/JER/PER walkers live in `spec::object`/
//! `ber::object`/`xer::object`/`jer::object`/`per::object`; this module
//! holds only the two plain-data types every one of those needs.

use crate::ber::tag::Tag;

/// How BER frames an alternative's payload (X.690 §8.13/§8.14) — also
/// reused for a SEQUENCE/SET member's own BER framing (`spec::object::
/// MemberMeta::ber`), same facts either way.
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
    /// `Delegate` for an OPTIONAL member whose type is an untagged CHOICE.
    /// The function returns that CHOICE's dispatch tags
    /// (`TypeTag::choice_ber_tags`): the member is present when the peeked
    /// tag matches one of them (X.690 §8.13).
    DelegateChoice(fn() -> &'static [BerDispatch]),
    /// No BER/XER support for this alternative yet; the codec reports an
    /// encode/decode error with the reason if actually reached. Other
    /// alternatives are unaffected.
    Unsupported(&'static str),
}

impl BerTagging {
    /// Whether a member with this framing and table tag `tag` starts with
    /// wire tag `t`: any of the CHOICE's alternative tags for
    /// `DelegateChoice` (by class and number, as CHOICE dispatch matches),
    /// otherwise `tag` itself.
    pub fn starts_with(self, tag: Tag, t: Tag) -> bool {
        match self {
            BerTagging::DelegateChoice(tags) => tags().iter().any(|d| d.tag.matches_identifier(&t)),
            _ => tag == t,
        }
    }
}

/// One BER dispatch entry: a wire tag that selects `alternatives[alt]`.
/// A CHOICE-typed alternative without a tag of its own contributes one
/// entry per tag of the inner CHOICE (X.690 §8.13).
#[derive(Clone, Copy)]
pub struct BerDispatch {
    pub tag: Tag,
    pub alt: usize,
}
