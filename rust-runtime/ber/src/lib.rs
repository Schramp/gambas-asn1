//! Thin re-export shim over `asn1cpp_wire` — kept as a separate crate name
//! purely so every existing external path (`asn1cpp_ber::sequence::...`,
//! generated code, `RustBackend.cpp`'s emitted paths) keeps working
//! unchanged. All actual BER/XER code lives in `asn1cpp_wire` now, merged
//! there with PER (`asn1cpp_per`, same shim treatment) around one shared
//! `Asn1Value` trait (gambas-asn1#537) — see that crate's own top-level
//! doc for why a shared trait needed a shared crate.

pub use asn1cpp_wire::{
    bit_string, boolean, choice, constraints, debug, enumerated, integer, null, octet_string, oid, reader, real,
    relative_oid, sequence, strings, tag, validate, value, writer, xer,
};

pub use asn1cpp_wire::reader::{DecodeError, Reader, Tlv};
pub use asn1cpp_wire::tag::{Tag, TagClass};
