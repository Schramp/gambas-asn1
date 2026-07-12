//! Native Rust BER codec primitives (gambas-asn1#218).
//!
//! Standalone — no FFI to the C++ runtime (`runtime/` at the repo root).
//! Ground truth for wire semantics is `runtime/src/BerCodec.cpp` and
//! `runtime/include/asn1cpp/codec/{BerWriter,BerReader}.hpp`, cross-checked
//! against X.690 (`asn1-docs/`) — same references the C++ runtime was built
//! against, not a port of the C++ code itself.
//!
//! Scope (per gambas-asn1#218): TLV primitives, plus encode/decode for
//! INTEGER, OCTET STRING, SEQUENCE, and CHOICE — the four constructs the
//! issue named. SEQUENCE and CHOICE are one hand-written example type each
//! (`Point`, `Choice`), not table-driven — wiring real generated types to
//! this runtime is gambas-asn1#219's job, not this crate's.
//!
//! Definite-length only; indefinite-length (X.690 §8.1.3.2) isn't
//! implemented (see `reader` module docs).

pub mod choice;
pub mod integer;
pub mod octet_string;
pub mod reader;
pub mod sequence;
pub mod tag;
pub mod writer;

pub use choice::Choice;
pub use reader::{DecodeError, Reader, Tlv};
pub use sequence::Point;
pub use tag::{Tag, TagClass};
