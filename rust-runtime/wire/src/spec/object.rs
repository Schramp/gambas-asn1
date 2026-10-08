//! Reflective, non-generic SEQUENCE/SET access (gambas-asn1#681, second
//! pass). "Codec uses `Asn1Object`" taken to its conclusion: `Asn1Seq` has
//! no codec-specific method at all — not `ber_encode`, not `xer_encode`,
//! nothing. It only answers structural questions ("how many members",
//! "give me member `i`") by index, never by type. Every per-codec walker
//! (`ber::object::encode_seq`, `xer::object::encode_seq`, ...) is a single
//! **non-generic** function, shared by every SEQUENCE/SET type in the
//! program, that drives any `&dyn Asn1Seq` the same way — so calling it
//! never requires a fresh monomorphization per concrete type the way
//! `encode_sequence_content::<T>` used to.
//!
//! Why this (and not `MemberAccess::Composite`'s 8 per-member closures,
//! #675's original shape): building a `Composite` row's struct literal
//! writes all 8 closures as data in one shot — even the ones for codecs
//! the program never calls — and writing a closure as data is enough to
//! keep it, and everything it calls, linked. `Asn1Seq`'s vtable, by
//! contrast, holds only reflective methods; none of them name a BER/XER/
//! JER/PER function, so building `PhoneNumber`'s `Asn1Seq` vtable (needed
//! for ANY codec to recurse into it) pulls in nothing codec-specific at
//! all. The actual codec logic lives entirely in `ber::object`/`xer::
//! object`/etc., called *by* the generic walker, never *by* the type.
//!
//! Scope (gambas-asn1#681 follow-up note): this covers SEQUENCE/SET
//! members only. CHOICE and SEQUENCE OF/SET OF members still go through
//! `MemberAccess::Composite` (the flat-closure shape) for now — a
//! SEQUENCE/SET type therefore implements both `Asn1Value` (so a CHOICE
//! alternative or SEQUENCE OF element naming it still compiles) and
//! `Asn1Seq` (so a SEQUENCE/SET member of *another* SEQUENCE/SET recurses
//! force-link-free). Migrating CHOICE/SEQUENCE OF onto the same reflective
//! shape is tracked separately.

use crate::ber::tag::Tag;
use crate::spec::choice::BerTagging;
use crate::spec::primitive::{PrimitiveRef, PrimitiveRefMut};

/// One member's wire-framing + validation facts — plain data, no
/// closures, so it can be a single non-generic type shared by every
/// SEQUENCE/SET (unlike the old `MemberDescriptor<T>`, which needed a
/// type parameter only because its *closures* captured `T`).
pub struct MemberMeta {
    pub name: &'static str,
    pub tag: Tag,
    pub optional: bool,
    pub ber: BerTagging,
    pub constraints: &'static crate::constraints::Constraints,
    pub per_unsupported: Option<&'static str>,
}

pub struct SequenceSpec {
    pub name: &'static str,
    pub tag: Tag,
    pub members: &'static [MemberMeta],
    pub ext_at: i32,
    pub roms_count: usize,
}

/// A borrowed member value, tagged by shape — exactly as wide as needed
/// for this pass's scope (primitives, plus one recursion case for a
/// nested SEQUENCE/SET). `Absent` covers a genuinely-missing OPTIONAL
/// member (a `PrimitiveRef` can't represent that itself).
pub enum MemberRef<'a> {
    Absent,
    Primitive(PrimitiveRef<'a>),
    Composite(&'a dyn Asn1Seq),
}

pub enum MemberRefMut<'a> {
    Absent,
    Primitive(PrimitiveRefMut<'a>),
    Composite(&'a mut dyn Asn1Seq),
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
    /// X.680 §51 constraint check delta (`0` valid, see `constraints.rs`'s
    /// own convention); `0` for a member with no inline constraint.
    fn validate(&self, index: usize) -> i64;
}

/// Lets codegen write `&v.field`/`&mut v.field` uniformly whether a
/// composite member's field type is `T` or `Box<T>` (boxed for a
/// self-referential cycle or to avoid `Option<T>` size inflation — see
/// `SequenceMemberSpec::member_type_in_cycle`/`box_optional_member`,
/// Backend.hpp) — both coerce to `&dyn Asn1Seq` the same way once `Box<T>`
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
