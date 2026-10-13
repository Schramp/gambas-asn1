//! BER (X.690) — TLV stream primitives and the SEQUENCE/CHOICE/ENUMERATED
//! walkers that drive the shared `spec::` tables (X.690 §8.9/§8.12/§8.13).
//! Per-type BER content logic lives in the wrapper modules at the crate
//! root (`integer`, `boolean`, `octet_string`, ...) as free functions,
//! reached through `spec::primitive`'s dispatch; this module holds the
//! shared machinery.

pub mod enumerated;
pub mod object;
pub mod reader;
pub mod sequence;
pub mod tag;
pub mod writer;
