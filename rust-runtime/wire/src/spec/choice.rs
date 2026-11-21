//! CHOICE wire-framing facts — X.680 §29. The reflective `Asn1Choice`
//! trait and the generic BER/XER/JER/PER walkers live in `spec::object`/
//! `ber::object`/`xer::object`/`jer::object`/`per::object`; this module
//! holds only the plain-data types every one of those needs.

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
    /// The referenced type's own framing (`AsMemberRef::BER_FRAMING`): a
    /// member with no tag of its own whose type assignment carries one
    /// (X.680 §31.2, `T ::= [APPLICATION 6] EXPLICIT OCTET STRING`). The
    /// framing belongs to the type; the row only points at it, the way a
    /// C++ member row points at its type's descriptor. The BER walker
    /// resolves it ([`BerTagging::resolve`]) before dispatching.
    OfType(&'static BerTagging),
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
    /// The framing the BER walker applies: `OfType` replaced by the
    /// referenced type's own framing, every other variant unchanged.
    pub fn resolve(self) -> BerTagging {
        match self {
            BerTagging::OfType(f) => f.resolve(),
            other => other,
        }
    }

    /// Whether a member with this framing and table tag `tag` starts with
    /// wire tag `t`: any of the CHOICE's alternative tags for
    /// `DelegateChoice`, otherwise `tag` itself. Both compare class and
    /// number only: a string member may arrive in primitive or constructed
    /// form (X.690 §8.6.1, §8.7.1, §8.23.6), and the members a decoder
    /// tells apart by tag have distinct class and number (X.680 §25.6.1,
    /// §25.7, §27.3). The member's decoder then checks the form: a
    /// SEQUENCE, SET, SEQUENCE OF or EXPLICIT tag sent primitive is an
    /// error (X.690 §8.9.1-§8.12.1, §8.14), as in C++.
    pub fn starts_with(self, tag: Tag, t: Tag) -> bool {
        match self {
            BerTagging::DelegateChoice(tags) => tags().iter().any(|d| d.tag.matches_identifier(&t)),
            _ => tag.matches_identifier(&t),
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

/// @brief Codec an unknown CHOICE extension alternative was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownOrigin {
    Ber,
    Per,
}

/// @brief An alternative of an extensible CHOICE that this schema version
///        does not define, kept as its codec carried it so it can be
///        relayed (X.680 §52.1: extension additions are not a decoding
///        error).
///
/// BER carries the alternative's TLV: `tag` (constructed bit included) and
/// `bytes`, its contents octets. PER carries the extension index past the
/// known alternatives (X.691 §23) and the open-type octets (§11.2). It
/// encodes again only in the codec it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownExtension {
    /// Codec it was read from.
    pub origin: UnknownOrigin,
    /// BER: the TLV's tag.
    pub tag: Tag,
    /// PER: extension index past the known alternatives.
    pub index: i64,
    /// BER contents octets / PER open-type octets.
    pub bytes: Vec<u8>,
}

impl UnknownExtension {
    /// @brief A BER alternative: its TLV's tag and contents octets.
    pub fn ber(tag: Tag, bytes: Vec<u8>) -> Self {
        UnknownExtension { origin: UnknownOrigin::Ber, tag, index: 0, bytes }
    }
    /// @brief A PER alternative: its extension index and open-type octets.
    pub fn per(index: i64, bytes: Vec<u8>) -> Self {
        UnknownExtension { origin: UnknownOrigin::Per, tag: Tag::context(0, false), index, bytes }
    }
    /// @brief Name of the codec it was read from, for messages.
    pub fn origin_name(&self) -> &'static str {
        match self.origin {
            UnknownOrigin::Ber => "BER",
            UnknownOrigin::Per => "PER",
        }
    }
}
