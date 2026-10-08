//! BER (X.690) — TLV stream primitives and the SEQUENCE/CHOICE/ENUMERATED
//! walkers that drive the shared `spec::` tables (X.690 §8.9/§8.12/§8.13).
//! Each per-type wrapper module at the crate root (`integer`, `boolean`,
//! `octet_string`, ...) implements `value::Asn1Value` directly against
//! these primitives — one `impl` block per type covers BER, XER and PER
//! together (see `value` module doc), so this module holds the shared
//! machinery, not per-type BER logic.

pub mod choice;
pub mod enumerated;
pub mod object;
pub mod reader;
pub mod sequence;
pub mod tag;
pub mod writer;
