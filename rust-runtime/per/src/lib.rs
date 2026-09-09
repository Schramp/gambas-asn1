//! Native Rust PER (Packed Encoding Rules, X.691) codec primitives —
//! unaligned variant (UPER) only, matching the C++ runtime's own scope.
//!
//! Standalone — no FFI to the C++ runtime (`runtime/` at the repo root),
//! and no dependency on the sibling `asn1cpp_ber` crate: PER's bit-level,
//! non-self-delimiting framing needs different stream primitives entirely
//! (`get_bits`/`put_bits`, no TLV, no byte alignment — UPER never aligns to
//! a byte boundary except implicitly at the end of an encoding), so there
//! is nothing to share with the BER crate's TLV-oriented `Reader`/`Writer`.
//! Ground truth for wire semantics is `runtime/src/PerCodec.cpp` and
//! `runtime/include/asn1cpp/codec/PerCodec.hpp`, cross-checked against
//! X.691 (`asn1-docs/`) — same references the C++ runtime was built
//! against, not a port of the C++ code itself.
//!
//! Scope so far: bit-level `Reader`/`Writer` only (this crate's foundation).
//! Table-driven SEQUENCE/CHOICE/INTEGER/string encode-decode, mirroring
//! `rust-runtime/ber`'s `SequenceSpec<T>`/`MemberDescriptor<T>` shape, is
//! built on top of this in a later pass — see the crate's own issue tracker
//! entry for the phased plan.

pub mod choice;
pub mod constraints;
pub mod integer;
pub mod length;
pub mod reader;
pub mod sequence;
pub mod strings;
pub mod uinteger;
pub mod value;
pub mod writer;

pub use constraints::Constraints;
pub use reader::{DecodeError, Reader};
pub use value::PerValue;
pub use writer::Writer;
