//! SEQUENCE/SET spec — X.680 §25/§26. Walked by BER (`sequence.rs`), XER
//! (`xer.rs`) and PER (`per::sequence`).

use crate::constraints::Constraints;
use crate::ber::tag::{universal, Tag};
use crate::value::Asn1Value;

pub const SEQUENCE_TAG: Tag = Tag::universal(universal::SEQUENCE, true);

/// SET's own natural tag (X.680 §26, universal 17,
/// constructed) — a SET-typed `SequenceSpec<T>` must use this instead of
/// `SEQUENCE_TAG`. `encode_sequence`/`decode_sequence` don't otherwise
/// distinguish SET from SEQUENCE (same TLV shape, same member walk; X.690
/// §8.11/§8.12 SET encoding is canonically member-tag-ordered on the wire,
/// which this crate doesn't enforce — same simplifying scope note
/// `decode_sequence`'s own doc already makes for member ordering generally).
pub const SET_TAG: Tag = Tag::universal(universal::SET, true);

/// One row in a `SequenceSpec<T>` table — mirrors `MemberDescriptor`
/// (`TypeDescriptor.hpp`), minus everything not yet needed by this crate's
/// scope (EXPLICIT/IMPLICIT tagging beyond the member's own natural tag,
/// CHOICE alternative dispatch — real gaps, not silently dropped:
/// `Backend`/codegen simply doesn't emit members needing them yet).
pub struct MemberDescriptor<T: 'static> {
    pub name: &'static str,
    pub tag: Tag,
    pub optional: bool,
    pub access: MemberAccess<T>,
    /// `Some` for a DEFAULT-valued member (X.680 §25.1) whose default value
    /// this crate can represent — mirrors `MemberDescriptor::set_default`
    /// (`TypeDescriptor.hpp`)/`SequenceBerHandler::decode_body`'s own
    /// `if (mbr.set_default) mbr.set_default(dest);` (`BerCodec.cpp`):
    /// `decode_sequence_content` calls this when the member's tag is absent
    /// from the wire, filling the schema default instead of leaving the
    /// field however `T::default()` left it. `None` for every other
    /// member, DEFAULT-valued or not — same "optional discriminant" shape
    /// `access`'s own variants use.
    pub set_default: Option<fn(&mut T)>,
    /// BER encode gate (X.690 §11.5 — a member whose value equals the
    /// schema DEFAULT must not be encoded): `Some`, returning `true`, for
    /// exactly the members `set_default` is `Some` for — mirrors
    /// `MemberDescriptor::is_default_equal` (`TypeDescriptor.hpp`)/
    /// `SequenceBerHandler::encode`'s own `if (mbr.is_default_equal &&
    /// mbr.is_default_equal(src)) { continue; }` (`BerCodec.cpp`) exactly.
    /// `encode_sequence_content` skips the member entirely when this
    /// returns `true`, same as a genuinely absent OPTIONAL member.
    pub is_default_equal: Option<fn(&T) -> bool>,
    /// `Some` for a member with its own X.680 §51 SubtypeConstraint table
    /// (INTEGER range, OCTET/BIT STRING and character string SIZE/FROM,
    /// SEQUENCE OF/SET OF SIZE) — the declaration's own `Constraints`,
    /// handed to the member's `Asn1Value::validate` through the same
    /// `get` accessor the encode/decode paths use (a shared native type
    /// like a bare `i64` has no constraint of its own, so the row carries
    /// it). Returns the delta convention `Asn1Value::validate()` itself
    /// documents: `0` valid, positive = below lower bound, negative =
    /// above upper bound. Checked by `encode_sequence_content`/
    /// `decode_sequence_content` via `validate::check_delta` whenever the
    /// member actually has a value (present on the wire, or filled by
    /// `set_default`) — not for a genuinely absent OPTIONAL member.
    /// `None` for a member whose type owns its constraint (a named
    /// generated type, checked through `ber_encode_tagged`'s own
    /// `validate::check`) or has none.
    pub constraints: Option<&'static Constraints>,
    /// `Some(reason)` for a member PER cannot encode/decode yet (a FROM-
    /// alphabet or wide-char string, ANY, ...): the PER walker panics with
    /// `reason` only if this member is actually reached, every other member
    /// of the SEQUENCE is unaffected. `None` for every PER-covered member.
    /// BER/XER ignore it; PER ignores `tag` and the retag flavour of
    /// `access` (X.691 has no tags) and reads the member through
    /// [`MemberAccess::accessors`] with `constraints` (UNCONSTRAINED when
    /// `None`).
    pub per_unsupported: Option<&'static str>,
}

impl<T: 'static> MemberDescriptor<T> {
    /// Runs this member's declared-constraint check against its current
    /// value in `value` (see `constraints`). `None` when the row carries no
    /// constraint or its access shape has no `Asn1Value` accessor
    /// (`Unsupported`).
    pub(crate) fn validate_delta(&self, value: &T) -> Option<i64> {
        let c = self.constraints?;
        match &self.access {
            MemberAccess::Scalar { get, .. }
            | MemberAccess::TaggedScalar { get, .. }
            | MemberAccess::ExplicitScalar { get, .. } => Some(get(value).validate(c)),
            MemberAccess::Unsupported { .. } => None,
        }
    }
}

/// How a member's value is reached and (de)serialized.
///
/// `Scalar` is the most common shape: the member is one field whose own
/// concrete type already implements `Asn1Value` (`i64`, `bool`,
/// `octet_string::OctetString`, `String`, an `Option<V>`/newtype-string,
/// `SeqOf<T>`/`SetOf<T>` for a
/// SEQUENCE OF/SET OF member — every kind `rust_member_ber_tag` currently
/// covers), reached via the same accessor-function pair the crate has
/// always used (`value.rs`'s module doc explains why a function, not an
/// `offsetof`-equivalent). A SEQUENCE OF/SET OF member's field type is
/// `SeqOf<T>`/`SetOf<T>` rather than a raw `Vec<ElementType>` precisely so
/// it has a real `Asn1Value` impl and folds into this ordinary
/// `Scalar`/`TaggedScalar`/`ExplicitScalar` dispatch, with no special-casing
/// needed anywhere here.
pub enum MemberAccess<T: 'static> {
    Scalar {
        get: fn(&T) -> &dyn Asn1Value,
        get_mut: fn(&mut T) -> &mut dyn Asn1Value,
    },
    /// IMPLICIT tag override (X.690 §8.14). A member
    /// declared with its own `[n]` tag (explicit-in-the-schema, or an
    /// AUTOMATIC TAGS-assigned one) has that tag *replace* its type's
    /// natural one on the wire. Same shape as `Scalar` (`get`/`get_mut`,
    /// no closures) — the walker (`encode_sequence_content`/
    /// `decode_sequence_content` below) calls `Asn1Value::
    /// ber_encode_tagged`/`ber_decode_into_tagged` with the member's own
    /// `tag` field instead of the plain `ber_encode`/`ber_decode_into`
    /// `Scalar` uses; one generic trait method (`value.rs`) covers every
    /// kind, so no per-kind `*_tagged` primitive selection is needed here
    /// (or in codegen) at all. XER is unaffected either way — XER element
    /// tags are always field-name-derived, never type-derived (`xer.rs`'s
    /// module doc), so `get`/`get_mut` alone are already correct for that leg.
    TaggedScalar {
        get: fn(&T) -> &dyn Asn1Value,
        get_mut: fn(&mut T) -> &mut dyn Asn1Value,
    },
    /// EXPLICIT tagging (X.690 §8.14.3) — wraps the member's natural
    /// encoding in an outer TLV, rather than substituting the tag like
    /// `TaggedScalar`. Same shape as `TaggedScalar` (`get`/`get_mut` only)
    /// via `Asn1Value::ber_encode_explicit`/`ber_decode_into_explicit`
    /// (`value.rs`) — the object-safe methods that let this member's own
    /// EXPLICIT wrap/unwrap happen through the same trait-object accessor
    /// `TaggedScalar` uses for its IMPLICIT retag, instead of a per-member
    /// closure re-deriving `v.{field}` a second time.
    ExplicitScalar {
        get: fn(&T) -> &dyn Asn1Value,
        get_mut: fn(&mut T) -> &mut dyn Asn1Value,
    },
    /// A member whose type/tag/optionality combination genuinely has no
    /// `Asn1Value` coverage yet in this crate. Every generated SEQUENCE/SET
    /// always gets a real table and `Asn1Value` impl now — nothing gates
    /// emission on every member being individually wire-representable
    /// first — so a member that isn't (a builtin storage/tag combination
    /// not yet implemented, or a member whose presence can't be safely
    /// detected at all, e.g. OPTIONAL typed by an untagged CHOICE with no
    /// tag to peek for) gets this instead: a struct containing one simply
    /// can't be successfully encoded/decoded via the generated methods
    /// yet, but every *other* member is unaffected, and — the actual
    /// point — any type that merely *references* this one as a composite
    /// member gets real coverage of its own regardless, since `Asn1Value`
    /// is always implemented, just not always successfully callable. No
    /// presence-detection is attempted (there's nothing safe to peek for
    /// in the cases that reach here) — reaching this row during either
    /// encode or decode panics unconditionally.
    Unsupported {
        reason: &'static str,
        /// The field is still reachable for the codecs that do not depend
        /// on BER's tag/presence shape (PER reads it through
        /// [`MemberAccess::accessors`]).
        get: fn(&T) -> &dyn Asn1Value,
        get_mut: fn(&mut T) -> &mut dyn Asn1Value,
    },
}

impl<T: 'static> MemberAccess<T> {
    /// The plain field accessors, for a codec (PER) that reads a member
    /// through the `Asn1Value` trait regardless of how BER tags it. Every
    /// variant carries one now (ANY reaches the wire through
    /// `ExplicitScalar` like any other EXPLICIT-tagged member).
    pub fn accessors(&self) -> (fn(&T) -> &dyn Asn1Value, fn(&mut T) -> &mut dyn Asn1Value) {
        match self {
            MemberAccess::Scalar { get, get_mut }
            | MemberAccess::TaggedScalar { get, get_mut }
            | MemberAccess::ExplicitScalar { get, get_mut }
            | MemberAccess::Unsupported { get, get_mut, .. } => (*get, *get_mut),
        }
    }
}


/// SEQUENCE/SET member table — mirrors `SequenceSpec` (`TypeDescriptor.hpp`).
///
/// `name` is the XER element tag for the whole SEQUENCE (mirrors
/// `TypeDescriptor::name`, used by `SequenceXerHandler` — X.693's outer
/// element is the *type* name, unlike each member's own tag which is
/// *field*-name-derived). BER doesn't need it (BER dispatch is by `tag`
/// alone), but one table drives both encodings (see `lib.rs`'s XER module
/// doc), so it lives here rather than in a second, XER-only struct.
///
/// **Deliberate layering divergence from both C++ codebases**: in
/// `runtime/include/asn1cpp/TypeDescriptor.hpp`
/// `name` lives on the outer `TypeDescriptor`, a sibling to
/// `sequence_spec`/`choice_spec`/`enum_spec` — never inside `SequenceSpec`
/// itself. Same split in asn1c (`asn_TYPE_descriptor_s::name` vs.
/// `asn_SEQUENCE_specifics_s`, which carries no name at all). That layer
/// exists in both C++ codebases because their dispatch is runtime
/// polymorphic — one `TypeDescriptor*`/`asn_TYPE_descriptor_t*` has to
/// carry `name` regardless of *which* construct (`SEQUENCE`/`CHOICE`/
/// `ENUMERATED`) it points at, since the codec picks the handler at
/// runtime via `TypeKind`/`tag2el`. Rust's design has no such layer:
/// dispatch is by generic parameter (`SequenceSpec<T>`) resolved at compile
/// time, so there is no shared runtime "type descriptor" object for `name`
/// to live on once, and introducing one here would only exist to satisfy
/// field-sharing, not to do anything. Each construct-specific spec (this
/// one, and `ChoiceSpec<T>` in `choice.rs`) carries its own
/// `name` — cheap (`&'static str`, one word, no allocation), and avoids
/// inventing indirection with no other purpose. Documented here so the
/// repetition in `ChoiceSpec<T>` reads as intentional, not a
/// copy-paste that forgot to deduplicate.
pub struct SequenceSpec<T: 'static> {
    pub name: &'static str,
    pub tag: Tag,
    pub members: &'static [MemberDescriptor<T>],
    /// Index of the first extension-addition member (X.680 §25.4's `...`);
    /// `< 0` for none. Read by PER only, matching `SequenceSpec::ext_at`
    /// (`TypeDescriptor.hpp`).
    pub ext_at: i32,
}
