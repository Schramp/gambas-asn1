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
//! issue named. SEQUENCE is table-driven (gambas-asn1#278, see
//! `sequence`/`value` module docs); CHOICE is still one hand-written example
//! (`Choice`) — table-driving it is real follow-on scope, not done here.
//!
//! Definite-length only; indefinite-length (X.690 §8.1.3.2) isn't
//! implemented (see `reader` module docs).
//!
//! ## This crate is BER-only, by design and by location
//!
//! The C++ runtime keeps each wire encoding as its own codec class —
//! `BerCodec`, `PerCodec`, `XerCodec`, `JerCodec` — deliberately separate
//! (see `CLAUDE.md`'s PER architecture section: "`PerCodec` ... completely
//! separate from `BerCodec`"). This crate mirrors that separation at the
//! *crate* boundary instead of the class boundary: `rust-runtime/ber/` (this
//! crate, package name `asn1cpp-ber`) covers BER only. A future PER runtime
//! is a sibling crate at `rust-runtime/per/` (`asn1cpp-per`), not a module
//! added in here — so a construct's BER logic (`src/choice.rs`,
//! `src/sequence.rs`, ...) never has to share a file, or a name, with that
//! same construct's PER logic. Each encoding gets its own crate, its own
//! module tree, its own `Cargo.toml`, under the shared `rust-runtime/`
//! umbrella directory (a Cargo workspace once there's more than one).

pub mod choice;
pub mod integer;
pub mod octet_string;
pub mod reader;
pub mod sequence;
pub mod tag;
pub mod value;
pub mod writer;

pub use choice::Choice;
pub use reader::{DecodeError, Reader, Tlv};
pub use sequence::Point;
pub use tag::{Tag, TagClass};
