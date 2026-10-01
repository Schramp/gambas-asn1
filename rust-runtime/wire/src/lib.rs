//! Native Rust wire-encoding runtime — BER, XER, and PER share one crate
//! (and one `Asn1Value` trait, `value` module) so a generated type
//! implements it exactly once, mirroring the C++ runtime's own single
//! `Asn1Object`/`TypeDescriptor` model serving every codec (`ICodec`
//! dispatches BER/XER/JER/PER off the same table).
//!
//! ## Layout
//!
//! `spec` holds the codec-agnostic tables codegen emits
//! (`SequenceSpec`/`ChoiceSpec`/`EnumSpec`), `value` the shared
//! `Asn1Value` trait, `constraints` the shared X.680 §51 SubtypeConstraint
//! data — all three read by every codec. `ber` is BER's TLV stream
//! primitives (`reader`, `writer`, `tag`) plus the SEQUENCE/CHOICE/
//! ENUMERATED walkers that drive the shared tables for BER. `xer` is XER's
//! own stream primitives and walkers. `per` is PER (X.691 unaligned) —
//! its own bit-level `reader`/`writer` and per-construct encode/decode,
//! module-nested to avoid name collisions with `ber`'s TLV-shaped modules
//! of the same name. Every per-type wrapper module at the root (`integer`,
//! `boolean`, `octet_string`, ...) implements `Asn1Value` once against
//! all three — one `impl` block per type covers BER, XER and PER together
//! (`value` module doc explains why Rust's lack of specialization forces
//! this).
//!
//! Definite-length BER only; indefinite-length (X.690 §8.1.3.2) isn't
//! implemented (see `ber::reader` module docs).

pub mod any;
pub mod ber;
pub mod bit_string;
pub mod boolean;
pub mod constraints;
pub mod debug;
pub mod integer;
pub mod null;
pub mod octet_string;
pub mod oid;
pub mod per;
pub mod real;
pub mod relative_oid;
pub mod spec;
pub mod type_tag;
pub mod strings;
pub mod validate;
pub mod value;
pub mod xer;

pub use ber::reader::{DecodeError, Reader, Tlv};
pub use ber::tag::{Tag, TagClass};
