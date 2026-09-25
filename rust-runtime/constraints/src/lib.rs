//! Thin re-export shim over `asn1cpp_wire::constraints` — kept as a
//! separate crate name purely for external path compatibility
//! (gambas-asn1#537 merged the actual `Constraints` data into
//! `asn1cpp_wire`, alongside BER/XER/PER once they shared one crate).

pub use asn1cpp_wire::constraints::*;
