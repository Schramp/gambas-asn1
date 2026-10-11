//! Reflective, non-generic member access for every construct kind.
//! "Codec uses the type," not "type has a codec": none of the traits
//! here — `Asn1Seq`, `Asn1Choice`,
//! `Asn1SeqOf`, `EnumSlot` — carry a single codec-specific method, not
//! `ber_encode`, not `xer_encode`, nothing. Each one only answers
//! structural questions ("how many members", "give me member `i`", "which
//! alternative is active") by index, never by type. Every per-codec
//! walker (`ber::object::encode_seq`, `ber::object::encode_choice`, ...)
//! is a single **non-generic** function, shared by every type of that
//! kind in the program, driving any `&dyn Asn1Seq`/`&dyn Asn1Choice`/
//! `&dyn Asn1SeqOf` the same way — calling it never needs a fresh
//! monomorphization per concrete type, and building a type's vtable for
//! one of these traits never requires any other codec's logic to exist
//! for that type, since the vtable itself holds nothing codec-specific.
//!
//! Member access is deliberately plain-data reflection, not stored
//! per-member codec closures: storing a closure as data — even one
//! nobody calls at runtime — is enough to keep it, and everything it
//! calls, linked into the binary. A purely reflective vtable has no
//! such closures to store. Every generated type implements exactly
//! one of `Asn1Seq`
//! (SEQUENCE/SET), `Asn1Choice` (CHOICE), or is a leaf (a builtin
//! primitive via `PrimitiveRef`/`PrimitiveRefMut`, or ENUMERATED via
//! `EnumSlot`); `Asn1SeqOf` is implemented generically once, by `SeqOf<V>`/
//! `SetOf<V>`, for any element kind via `AsMemberRef`.

use crate::ber::tag::Tag;
use crate::spec::choice::{BerDispatch, BerTagging};
use crate::spec::enumerated::EnumSpec;
use crate::spec::primitive::{PrimitiveRef, PrimitiveRefMut};

/// X.693 §21 ENCODING-CONTROL XER override for an OCTET STRING member —
/// table data, read directly by `xer::object`'s walker rather than a
/// separate `MemberRef` shape. Applies equally whether the
/// instruction landed on the member's own inline type or on a named
/// alias it merely references (`AsMemberRef` for either unwraps to the
/// same plain `OctetString`, so the instruction has to come from the
/// row, not from the unwrapped value — see `MemberMeta::xer_instruction`'s
/// own doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XerInstruction {
    #[default]
    Default,
    Base64,
    Utf8,
}

/// One member's wire-framing + validation facts — plain data, no
/// closures, so it can be a single non-generic type shared by every
/// SEQUENCE/SET.
pub struct MemberMeta {
    pub name: &'static str,
    pub tag: Tag,
    pub optional: bool,
    pub ber: BerTagging,
    pub constraints: &'static crate::constraints::Constraints,
    /// `XerInstruction::Default` for every kind but a BASE64/UTF8-marked
    /// OCTET STRING member (`RustBackend`'s `xer_instruction` lambda) —
    /// `xer::object::encode_seq_content`/`decode_seq_content_into` read
    /// this directly instead of matching a `MemberRef::Base64`/`Utf8`
    /// variant (there isn't one; `MemberRef::Primitive(PrimitiveRef::
    /// OctetString(..))` covers this member the same as any other OCTET
    /// STRING).
    pub xer_instruction: XerInstruction,
    pub per_unsupported: Option<&'static str>,
}

pub struct SequenceSpec {
    pub name: &'static str,
    pub tag: Tag,
    pub members: &'static [MemberMeta],
    pub ext_at: i32,
    pub roms_count: usize,
}

/// One alternative's wire-framing + validation facts (X.690 §8.13/§8.14)
/// — the `Asn1Choice` counterpart of `MemberMeta`.
pub struct AltMeta {
    pub name: &'static str,
    pub ber: BerTagging,
    pub constraints: &'static crate::constraints::Constraints,
    pub per_unsupported: Option<&'static str>,
}

pub struct ChoiceSpec {
    pub name: &'static str,
    pub alternatives: &'static [AltMeta],
    pub ber_tags: &'static [BerDispatch],
    pub own_tag: Option<Tag>,
    pub ext_at: i32,
    pub range_bits: u32,
}

/// A borrowed member/alternative/element value, tagged by shape.
/// `Absent` covers a genuinely-missing OPTIONAL member (a `PrimitiveRef`
/// can't represent that itself).
pub enum MemberRef<'a> {
    Absent,
    Primitive(PrimitiveRef<'a>),
    Composite(&'a dyn Asn1Seq),
    Choice(&'a dyn Asn1Choice),
    SeqOf(&'a dyn Asn1SeqOf),
    Enumerated(&'a dyn EnumSlot, &'static EnumSpec),
}

pub enum MemberRefMut<'a> {
    Absent,
    Primitive(PrimitiveRefMut<'a>),
    Composite(&'a mut dyn Asn1Seq),
    Choice(&'a mut dyn Asn1Choice),
    SeqOf(&'a mut dyn Asn1SeqOf),
    Enumerated(&'a mut dyn EnumSlot, &'static EnumSpec),
}

/// Purely reflective SEQUENCE/SET interface — see module doc. Every
/// method answers a structural question by index; none of them encode or
/// decode anything.
pub trait Asn1Seq {
    fn spec(&self) -> &'static SequenceSpec;
    fn get_member(&self, index: usize) -> MemberRef<'_>;
    fn get_member_mut(&mut self, index: usize) -> MemberRefMut<'_>;
    /// Fills in member `index`'s schema DEFAULT (X.680 §25.1) when the
    /// wire omitted it; a no-op for a member with no default.
    fn set_default(&mut self, index: usize);
    /// `true` when member `index`'s current value equals its schema
    /// DEFAULT (X.690 §11.5 — suppress encoding it); `false` for a
    /// member with no default.
    fn is_default_equal(&self, index: usize) -> bool;
    /// X.680 §51 constraint check delta (`0` valid); `0` for a member
    /// with no inline constraint.
    fn validate(&self, index: usize) -> i64;
}

/// Purely reflective CHOICE interface (X.680 §29). `select_mut` emplaces
/// alternative `index` (constructing it with its `Default` value if some
/// other alternative is currently active) before handing back a mutable
/// reference — fuses what used to be "emplace" + "decode into" into one
/// call, same reasoning `Alternative<T>`'s old fused closures had.
pub trait Asn1Choice {
    fn spec(&self) -> &'static ChoiceSpec;
    fn active_index(&self) -> Option<usize>;
    fn get_active(&self) -> MemberRef<'_>;
    fn select_mut(&mut self, index: usize) -> MemberRefMut<'_>;
    /// X.680 §29.6 extensibility — captures an unrecognized-tag TLV
    /// (BER-only; see `spec::choice::UnknownExtensionOps`'s own doc for
    /// why XER has no equivalent escape hatch). A no-op for a
    /// non-extensible CHOICE.
    fn construct_unknown_extension(&mut self, tag: Tag, bytes: Vec<u8>);
    fn extract_unknown_extension(&self) -> Option<(Tag, &[u8])>;
}

/// Purely reflective SEQUENCE OF/SET OF interface (X.680 §25/§26 applied
/// to a homogeneous element list) — implemented generically, once, by
/// `SeqOf<V>`/`SetOf<V>` for any element kind via `AsMemberRef`, never
/// per generated collection type. Elements carry no name/tag/optional
/// metadata of their own (unlike `Asn1Seq` members) — X.690 §8.9.2: a
/// SEQUENCE OF/SET OF element is always its own natural tag, repeated.
pub trait Asn1SeqOf {
    /// SEQUENCE's universal tag 16 for `SeqOf<T>`, SET's 17 for
    /// `SetOf<T>` (X.680 §25/§26) — a static fact about the wrapper
    /// type, not the element, so each wrapper answers it directly rather
    /// than needing a `MemberMeta`-style per-instance field.
    fn natural_tag(&self) -> Tag;
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> MemberRef<'_>;
    /// Appends one new default-valued element (for decode) and returns a
    /// mutable reference to it.
    fn push_default_mut(&mut self) -> MemberRefMut<'_>;
    /// Upfront backing-store reservation hint for a decode that already
    /// knows the element count (`ber::object::decode_seqof_content`'s own
    /// zero-copy top-level-TLV pre-count, mirroring
    /// `ber::sequence::decode_seq_of_content`'s `count_top_level_tlvs`
    /// use) — avoids `push_default_mut`'s otherwise-geometric `Vec`
    /// regrowth. Every real implementor backs onto a `Vec`, so this has
    /// one obvious correct override (`self.0.reserve(additional)`); the
    /// default no-op only matters if a future implementor can't honor it.
    fn reserve(&mut self, additional: usize) {
        let _ = additional;
    }
    /// Element `index`'s own natural X.693 §12 XER element name — e.g.
    /// `"TimeslotISCP"` for a named INTEGER-alias element, not generic
    /// `"INTEGER"`. Deliberately *not* derivable from `get(index)`:
    /// `MemberRef::Primitive`/`Base64`/`Utf8` have already unwrapped to
    /// the element's native field by the time `get` returns (same
    /// `AsMemberRef` unwrap `AccessKind::Primitive`'s `is_explicit`
    /// branch and `MemberRef::Base64`'s own doc describe for a SEQUENCE
    /// member), which is exactly why `xer::object::encode_seqof_content`
    /// can't just call `value::Asn1Value::xer_element_name()` on
    /// whatever `get(index)` handed back — it needs the *un*-unwrapped
    /// element's own override, straight from its own `Asn1Value` impl.
    fn elem_natural_xer_name(&self, index: usize) -> &'static str;
    /// X.693 §12 element identifier (e.g. `xxx SEQUENCE OF id INTEGER`) —
    /// `Some` only for a named top-level SEQUENCE OF/SET OF type that
    /// declared one (`SeqOfSpec::elem_xer_name`, `emit_seq_of_definition`);
    /// an inline member's `SeqOf<T>`/`SetOf<T>` (this trait's one
    /// blanket impl, `ber::sequence`) never has one to carry, so it keeps
    /// the default. Used only by a Primitive/Composite/Base64 element's
    /// own XER wrapper tag — ENUMERATED/CHOICE always use their own
    /// self-delimiting form regardless (X.693; `xer::object`'s own doc).
    fn elem_xer_name(&self) -> Option<&'static str> {
        None
    }
}

/// Lets a builtin leaf type or a generated composite type (SEQUENCE/SET
/// or CHOICE) appear as a SEQUENCE OF/SET OF element uniformly —
/// `SeqOf<V>`'s own `Asn1SeqOf` impl needs this to turn `&V`/`&mut V`
/// into a `MemberRef`/`MemberRefMut` without knowing which kind `V` is.
pub trait AsMemberRef {
    fn as_member_ref(&self) -> MemberRef<'_>;
    fn as_member_ref_mut(&mut self) -> MemberRefMut<'_>;
}

/// Purely reflective ENUMERATED interface (X.680 §20) — `enum_get`/
/// `enum_set` convert to/from the X.690 §8.4/X.691 ordinal `i64`
/// representation; `enum_set` returns `false` for a value with no
/// matching named entry (mirrors the C++ `EnumSpec::validate` contract,
/// `spec::enumerated`'s own doc) rather than panicking, so the walker can
/// report a decode error instead.
pub trait EnumSlot {
    fn enum_get(&self) -> i64;
    fn enum_set(&mut self, v: i64) -> bool;
}

/// Lets codegen write `&v.field`/`&mut v.field` uniformly whether a
/// composite member's field type is `T` or `Box<T>` (boxed for a
/// self-referential cycle or to avoid `Option<T>` size inflation) — both
/// coerce to `&dyn Asn1Seq`/`&dyn Asn1Choice` the same way once `Box<T>`
/// itself implements the trait.
impl<T: Asn1Seq + ?Sized> Asn1Seq for Box<T> {
    fn spec(&self) -> &'static SequenceSpec {
        (**self).spec()
    }
    fn get_member(&self, index: usize) -> MemberRef<'_> {
        (**self).get_member(index)
    }
    fn get_member_mut(&mut self, index: usize) -> MemberRefMut<'_> {
        (**self).get_member_mut(index)
    }
    fn set_default(&mut self, index: usize) {
        (**self).set_default(index)
    }
    fn is_default_equal(&self, index: usize) -> bool {
        (**self).is_default_equal(index)
    }
    fn validate(&self, index: usize) -> i64 {
        (**self).validate(index)
    }
}

impl<T: Asn1Choice + ?Sized> Asn1Choice for Box<T> {
    fn spec(&self) -> &'static ChoiceSpec {
        (**self).spec()
    }
    fn active_index(&self) -> Option<usize> {
        (**self).active_index()
    }
    fn get_active(&self) -> MemberRef<'_> {
        (**self).get_active()
    }
    fn select_mut(&mut self, index: usize) -> MemberRefMut<'_> {
        (**self).select_mut(index)
    }
    fn construct_unknown_extension(&mut self, tag: Tag, bytes: Vec<u8>) {
        (**self).construct_unknown_extension(tag, bytes)
    }
    fn extract_unknown_extension(&self) -> Option<(Tag, &[u8])> {
        (**self).extract_unknown_extension()
    }
}
