//! Native Rust wire-encoding runtime — BER, XER, JER, and PER share one
//! crate and one set of codec-agnostic tables, mirroring the C++ runtime's
//! single `TypeDescriptor` model serving every codec (`ICodec` dispatches
//! BER/XER/JER/PER off the same table).
//!
//! ## Layout
//!
//! `spec` holds the codec-agnostic tables and reflective traits codegen
//! emits against (`SequenceSpec`/`ChoiceSpec`/`EnumSpec`, `Asn1Seq`/
//! `Asn1Choice`/`Asn1SeqOf`/`AsMemberRef`/`Asn1Pdu`, and `PrimitiveRef`
//! dispatch for the builtin leaf types); `constraints` holds the shared
//! X.680 §51 SubtypeConstraint data. Each codec is its own module — `ber`
//! (TLV `reader`/`writer`/`tag`), `xer`, `jer`, `per` (X.691 unaligned,
//! bit-level `reader`/`writer`) — with one reflective walker in its
//! `object.rs` that matches on `MemberRef`. Every per-type wrapper module
//! at the root (`integer`, `boolean`, `octet_string`, ...) defines its
//! newtype and wire-level helper functions; no codec trait is implemented
//! per type.
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
pub mod jer;
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
