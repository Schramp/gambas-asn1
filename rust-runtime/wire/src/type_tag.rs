//! Compile-time BER tag lookup, kept off `value::Asn1Value` itself. An
//! associated const makes a trait non-object-safe — moot for
//! `Asn1Value`'s *own* object-safety now (gambas-asn1#675 removed every
//! `&dyn Asn1Value` accessor it used to need to stay object-safe for),
//! but still a separate trait here since codegen names a member's own
//! concrete Rust type directly to ask `<Type as TypeTag>::TAG`, replacing
//! the C++-side per-builtin-kind tag switch (`RustBackend::
//! builtin_ber_tag`) with one generic lookup that works for every
//! builtin wrapper and every generated SEQUENCE/CHOICE/ENUMERATED/
//! named-INTEGER type alike.

use crate::ber::tag::Tag;

/// `None` for a type with no fixed natural tag: CHOICE (X.680 §28, always
/// EXPLICIT-wrapped when tagged, X.680 §30.6) and ANY (X.208 legacy, no
/// tag of its own). A generic wrapper forwards its payload's `TAG`
/// unchanged — the tag depends only on the payload's type.
pub trait TypeTag {
    const TAG: Option<Tag>;
}

impl<V: TypeTag> TypeTag for Option<V> {
    const TAG: Option<Tag> = V::TAG;
}

impl<T: TypeTag> TypeTag for Box<T> {
    const TAG: Option<Tag> = T::TAG;
}
