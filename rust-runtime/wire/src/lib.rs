//! Native Rust wire-encoding runtime — BER, XER, and PER share one crate
//! (and one `Asn1Value` trait, `value` module) so a generated type
//! implements it exactly once, mirroring the C++ runtime's own single
//! `Asn1Object`/`TypeDescriptor` model serving every codec (`ICodec`
//! dispatches BER/XER/JER/PER off the same table).
//!
//! Merged from what were three separate crates (`asn1cpp-ber`,
//! `asn1cpp-per`, `asn1cpp-constraints`) once unifying `Asn1Value`/
//! `PerValue` (gambas-asn1#537) made keeping BER/XER and PER's runtime
//! logic in separate crates untenable: `Asn1Value`'s BER-only convenience
//! defaults (`ber_encode_tagged`, `ber_decode_into_explicit`, ...) are
//! genuinely overridden per-type (`Option<V>`'s own impl, `value.rs`) —
//! Rust has no specialization, so a trait method that needs per-type
//! override capability must live on the *same* trait as the type's other
//! methods, not a separate blanket-default extension trait. Since those
//! defaults need BER's TLV `Reader`/`Writer`/`validate::check`/tag
//! machinery, and PER's own methods need PER's bit-level `Reader`/`Writer`,
//! the trait itself needs both — which only works cleanly with both
//! implementations in one crate. `asn1cpp-ber`/`asn1cpp-per`/
//! `asn1cpp-constraints` still exist as thin re-export crates (unchanged
//! external paths, so generated code and `RustBackend.cpp`'s emitted paths
//! needed zero changes beyond merging each type's two `impl` blocks into
//! one).
//!
//! ## Layout
//!
//! Root-level modules are BER/XER (formerly `asn1cpp-ber`): TLV primitives
//! (`reader`, `writer`, `tag`), XER (`xer`), and encode/decode for every
//! builtin kind plus SEQUENCE/CHOICE (`sequence`, `choice`, `enumerated`,
//! `integer`, `oid`, `relative_oid`, `octet_string`, `bit_string`,
//! `strings`, `null`, `boolean`, `real`). `per` is PER (X.691 unaligned,
//! formerly `asn1cpp-per`) — its own bit-level `reader`/`writer` and
//! per-construct encode/decode, module-nested to avoid name collisions
//! with the (unrelated, TLV-shaped) root-level modules of the same name.
//! `constraints` (X.680 §51 SubtypeConstraint data) is shared at the root —
//! plain data both BER/XER and PER read, computed once at codegen time.
//!
//! Definite-length BER only; indefinite-length (X.690 §8.1.3.2) isn't
//! implemented (see `reader` module docs).

pub mod any;
pub mod bit_string;
pub mod boolean;
pub mod choice;
pub mod constraints;
pub mod debug;
pub mod enumerated;
pub mod integer;
pub mod null;
pub mod octet_string;
pub mod oid;
pub mod per;
pub mod reader;
pub mod real;
pub mod relative_oid;
pub mod sequence;
pub mod strings;
pub mod tag;
pub mod validate;
pub mod value;
pub mod writer;
pub mod xer;

pub use reader::{DecodeError, Reader, Tlv};
pub use tag::{Tag, TagClass};
