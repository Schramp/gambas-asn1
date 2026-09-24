//! Thin re-export shim over `asn1cpp_wire` — kept as a separate crate name
//! purely so every existing external path (`asn1cpp_per::sequence::...`,
//! generated code, `RustBackend.cpp`'s emitted paths) keeps working
//! unchanged. All actual PER code lives in `asn1cpp_wire::per` now, merged
//! there with BER/XER (`asn1cpp_ber`, same shim treatment) around one
//! shared `Asn1Value` trait (gambas-asn1#537) — see that crate's own
//! top-level doc for why a shared trait needed a shared crate. `PerValue`
//! is kept as an alias for `Asn1Value` (the same trait, not a distinct
//! one) purely so a stray external reference to the old name doesn't break;
//! new code should just use `Asn1Value`.

pub use asn1cpp_wire::constraints;
pub use asn1cpp_wire::per::{
    bit_string, choice, enumerated, integer, length, octet_string, reader, seq_of, sequence, strings, uinteger,
    writer,
};
pub use asn1cpp_wire::value;

pub use asn1cpp_wire::constraints::Constraints;
pub use asn1cpp_wire::per::reader::{DecodeError, Reader};
pub use asn1cpp_wire::per::writer::Writer;
pub use asn1cpp_wire::value::Asn1Value as PerValue;
