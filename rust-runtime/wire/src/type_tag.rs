//! Compile-time BER tag lookup, kept off the object-safe `value::Asn1Value`
//! trait itself. An associated const makes a trait non-object-safe (Rust
//! has no exception for a defaulted const — `dyn Asn1Value` is load-bearing
//! throughout this crate, via `MemberDescriptor`/`Alternative`'s accessor
//! closures), so `TypeTag` is a separate trait: codegen names a member's
//! own concrete Rust type directly (never through a trait object) to ask
//! `<Type as TypeTag>::TAG`, replacing the C++-side per-builtin-kind tag
//! switch (`RustBackend::builtin_ber_tag`) with one generic lookup that
//! works for every builtin wrapper and every generated SEQUENCE/CHOICE/
//! ENUMERATED/named-INTEGER type alike.

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
