//! Native Rust BER codec primitives.
//!
//! Standalone — no FFI to the C++ runtime (`runtime/` at the repo root).
//! Ground truth for wire semantics is `runtime/src/BerCodec.cpp` and
//! `runtime/include/asn1cpp/codec/{BerWriter,BerReader}.hpp`, cross-checked
//! against X.690 (`asn1-docs/`) — same references the C++ runtime was built
//! against, not a port of the C++ code itself.
//!
//! Scope: TLV primitives, plus encode/decode for INTEGER, OCTET STRING,
//! SEQUENCE, and CHOICE. Both SEQUENCE and CHOICE are
//! table-driven — see `sequence`/`choice`/`value` module docs.
//!
//! Definite-length only; indefinite-length (X.690 §8.1.3.2) isn't
//! implemented (see `reader` module docs).
//!
//! ## XER lives in this crate too
//!
//! Originally this crate was meant to be BER-only, with a future XER runtime
//! as a sibling crate (mirroring the C++ side's separate `BerCodec`/
//! `XerCodec` classes). Revised once the table-driven direction was
//! set: the whole point of `SequenceSpec<T>`/`MemberDescriptor<T>` is that
//! *one* table drives every wire encoding of a type, same as the C++ side's
//! `TypeDescriptor` — `BerCodec`/`XerCodec` there are separate *codec
//! classes* that both read the *same* generated table, not separate
//! generated tables. Splitting XER into a sibling crate would force either
//! duplicating the table types or a cross-crate dependency for no benefit;
//! `xer.rs` lives alongside `sequence.rs`/`value.rs` instead, and
//! `Asn1Value` carries both a BER leg and an XER leg per type (see `value`
//! module doc). A future PER runtime is still expected to be a genuinely
//! separate sibling crate at `rust-runtime/per/` (`asn1cpp-per`) — PER's
//! bit-level, non-self-delimiting framing needs different stream primitives
//! entirely (`get_bits`/`align`, no TLV), unlike XER which only needed new
//! tag-parsing/escaping primitives (`xer.rs`) while reusing the exact same
//! member tables.

pub mod bit_string;
pub mod boolean;
pub mod choice;
pub mod debug;
pub mod enumerated;
pub mod integer;
pub mod null;
pub mod octet_string;
pub mod oid;
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
