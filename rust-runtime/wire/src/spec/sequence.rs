//! SEQUENCE/SET spec — X.680 §25/§26. Walked by BER (`ber::sequence`), XER
//! (`xer::sequence`), JER (`jer::sequence`) and PER (`per::sequence`).
//!
//! **gambas-asn1#674/#675/#681**: "codec uses type", not "type has a
//! codec" — a member row never embeds `&dyn Asn1Value`, but a *flat*
//! per-codec-closure row (#675/#677/#678's first pass) isn't enough on
//! its own: building a `static` table that holds a closure's address at
//! all is enough to keep that closure (and everything it calls) linked,
//! whether or not any codec the application actually uses ever calls it
//! through that pointer. The fix is [`MemberAccess`]: a primitive member
//! (the closed, ~26-strong builtin set, `spec::primitive`) stores *one*
//! accessor returning a [`primitive::PrimitiveRef`]/`PrimitiveRefMut` —
//! each codec's own small, hand-written, non-generated `match` over that
//! enum (`ber::sequence::encode_sequence_content` and friends) is the
//! only thing that ever calls a primitive type's per-codec method, so an
//! application that never calls XER/JER/PER never pulls `xer_encode_primitive`
//! et al. in, and nothing downstream of them either. A composite member
//! (SEQUENCE/SET/CHOICE/SEQUENCE OF/SET OF/ENUMERATED — unbounded, no
//! shared handler is possible) keeps the per-codec-closure shape, each
//! closure naming that one inner type's own static table directly
//! (`|v, out| ber::sequence::encode_sequence_content(&COORDS_SPEC, &v.y, out)`,
//! never a method call on the field) — this was already correct under
//! #675, and stays exactly as it was. Mirrors `TypeDescriptor.hpp`'s
//! split between the codec-owned dispatch LUTs (`JerCodec.cpp`'s
//! `prim_dispatch_[32]`, one shared array read by every type) and
//! per-member recursion into a nested `TypeDescriptor` (`comp_dispatch_[6]`).

use crate::ber::reader::{DecodeError, Reader};
use crate::ber::tag::{universal, Tag};
use crate::jer::reader::Reader as JerReader;
use crate::per::reader::{DecodeError as PerDecodeError, Reader as PerReader};
use crate::per::writer::Writer as PerWriter;
use crate::spec::choice::BerTagging;
use crate::spec::primitive::{PrimitiveRef, PrimitiveRefMut};
use crate::xer::reader::XerReader;

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
/// (`TypeDescriptor.hpp`'s offset + `type_descriptor` pointer shape, not
/// Rust's old trait-object accessor). Every field below is a plain
/// function pointer performing one codec's complete operation for this
/// exact member — see the module doc for why this needs no trait object.
pub struct MemberDescriptor<T: 'static> {
    pub name: &'static str,
    pub tag: Tag,
    pub optional: bool,
    /// Whether this member currently has a value to encode (checked
    /// before BER/XER/JER/PER all alike skip a genuinely absent OPTIONAL
    /// member). For a required member, always `true` — codegen emits
    /// `|_| true`. For an `Option<V>` member, `|v| v.field.is_some()` —
    /// a plain method call on the concrete `Option<V>`, not a trait call.
    pub is_present: fn(&T) -> bool,
    /// `Some` for a DEFAULT-valued member (X.680 §25.1) whose default value
    /// this crate can represent — mirrors `MemberDescriptor::set_default`
    /// (`TypeDescriptor.hpp`)/`SequenceBerHandler::decode_body`'s own
    /// `if (mbr.set_default) mbr.set_default(dest);` (`BerCodec.cpp`):
    /// `decode_sequence_content` calls this when the member's tag is absent
    /// from the wire, filling the schema default instead of leaving the
    /// field however `T::default()` left it. `None` for every other
    /// member, DEFAULT-valued or not.
    pub set_default: Option<fn(&mut T)>,
    /// BER encode gate (X.690 §11.5 — a member whose value equals the
    /// schema DEFAULT must not be encoded): `Some`, returning `true`, for
    /// exactly the members `set_default` is `Some` for — mirrors
    /// `MemberDescriptor::is_default_equal` (`TypeDescriptor.hpp`)/
    /// `SequenceBerHandler::encode`'s own `if (mbr.is_default_equal &&
    /// mbr.is_default_equal(src)) { continue; }` (`BerCodec.cpp`) exactly.
    pub is_default_equal: Option<fn(&T) -> bool>,
    /// `Some` for a member with its own X.680 §51 SubtypeConstraint table
    /// — bakes in both the field access *and* the constraints table at
    /// codegen time (`|v| asn1cpp_wire::constraints::validate_s64(v.x, &X_CONSTRAINTS)`),
    /// so there's no separate `constraints` field to look up generically.
    /// Returns the delta convention `validate_size`/`validate_s64`/etc.
    /// already document: `0` valid, positive = below lower bound,
    /// negative = above upper bound. `None` for a member whose type owns
    /// its own constraint internally, or has none.
    pub validate: Option<fn(&T) -> i64>,
    /// `Some(reason)` for a member PER cannot encode/decode yet (a FROM-
    /// alphabet or wide-char string, ANY, ...): the PER walker panics with
    /// `reason` only if this member is actually reached. `None` for every
    /// PER-covered member.
    pub per_unsupported: Option<&'static str>,

    pub access: MemberAccess<T>,
}

/// How a row reaches its field's value — see the module doc for why this
/// split exists (it's the whole point of #681).
pub enum MemberAccess<T: 'static> {
    /// One of the closed set of builtin leaf types (`spec::primitive`).
    /// `get`/`get_mut` return a reference tagged by kind; every codec's
    /// own shared `match` over that enum decides what to do with it.
    /// `ber` carries this member's own BER tag framing (X.690 §8.14) —
    /// a codegen-time fact about *this row*, not about the builtin kind,
    /// so it can't live in the enum itself.
    Primitive {
        ber: BerTagging,
        /// This member's own PER `Constraints` table (the inline SIZE/
        /// range table when one was declared, `&constraints::UNCONSTRAINED`
        /// otherwise) — a plain data field here rather than baked into a
        /// closure, since there's no longer a per-member `per_encode`
        /// closure to bake it into (`primitive::per_encode_primitive`
        /// takes it as a parameter instead).
        constraints: &'static crate::constraints::Constraints,
        get: fn(&T) -> PrimitiveRef,
        get_mut: fn(&mut T) -> PrimitiveRefMut,
    },
    /// An unbounded-set generated type (SEQUENCE/SET/CHOICE/SEQUENCE OF/
    /// SET OF/ENUMERATED) — no shared handler is possible, so each
    /// closure names that one inner type's own static table/trait method
    /// directly, same shape #675/#677/#678 already established.
    Composite {
        ber_encode: fn(&T, &mut Vec<u8>),
        ber_decode: fn(&mut T, &mut Reader) -> Result<(), DecodeError>,
        xer_encode: fn(&T, &mut String, usize),
        xer_decode: fn(&mut T, &mut XerReader) -> Result<(), DecodeError>,
        jer_encode: fn(&T, &mut String),
        jer_decode: fn(&mut T, &mut JerReader) -> Result<(), DecodeError>,
        per_encode: fn(&T, &mut PerWriter),
        per_decode: fn(&mut T, &mut PerReader) -> Result<(), PerDecodeError>,
    },
    /// A member whose type/tag/optionality combination genuinely has no
    /// representable shape at all (not merely a gap in one codec leg) —
    /// reaching this row during any codec's encode or decode panics
    /// unconditionally.
    Unsupported { reason: &'static str },
}

impl<T: 'static> MemberDescriptor<T> {
    /// Runs this member's declared-constraint check against its current
    /// value in `value` (see `validate`'s own doc). `None` when the row
    /// carries no constraint.
    pub(crate) fn validate_delta(&self, value: &T) -> Option<i64> {
        self.validate.map(|f| f(value))
    }
}

/// SEQUENCE/SET member table — mirrors `SequenceSpec` (`TypeDescriptor.hpp`).
///
/// `name` is the XER element tag for the whole SEQUENCE (mirrors
/// `TypeDescriptor::name`, used by `SequenceXerHandler` — X.693's outer
/// element is the *type* name, unlike each member's own tag which is
/// *field*-name-derived). BER doesn't need it (BER dispatch is by `tag`
/// alone), but one table drives every encoding (see `lib.rs`'s module
/// doc), so it lives here rather than in a second, XER-only struct.
pub struct SequenceSpec<T: 'static> {
    pub name: &'static str,
    pub tag: Tag,
    pub members: &'static [MemberDescriptor<T>],
    /// Index of the first extension-addition member (X.680 §25.4's `...`);
    /// `< 0` for none. Read by PER only, matching `SequenceSpec::ext_at`
    /// (`TypeDescriptor.hpp`).
    pub ext_at: i32,
    /// Root OPTIONAL/DEFAULT member count — the width of the PER preamble
    /// bitmap (X.691 §18.1). Extension members have their own bitmap,
    /// sized off the wire, not counted here. Precomputed by codegen
    /// (matching `SequenceSpec::roms_count`, `TypeDescriptor.hpp`) so
    /// `per::sequence::decode_sequence_content` reads it instead of
    /// recounting `members` on every call. PER-only; BER/XER ignore it.
    pub roms_count: usize,
}
