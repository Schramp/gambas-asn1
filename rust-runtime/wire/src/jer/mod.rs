//! X.697 JER (JSON Encoding Rules) — text-based reader/writer and
//! per-construct encode/decode. Nested under the crate root (like
//! `per::` — not flat like BER/XER's own modules) to keep every
//! JER-specific construct-walking function out of `ber/sequence.rs`/
//! `ber/choice.rs`, confirmed as the actually-consistent precedent by
//! reading `per::sequence`/`per::choice` directly: PER's construct
//! walkers live entirely under `per/`, not mixed into `ber/*.rs`. (XER
//! does mix its own CHOICE/SEQUENCE-OF walkers into `ber/choice.rs`/
//! `ber/sequence.rs` — a historical inconsistency this crate doesn't
//! repeat for JER; see gambas-asn1#666 for the follow-up to bring XER
//! in line.)
//!
//! Ported from `runtime/src/JerCodec.cpp`'s handler classes (itself
//! ported from asn1c's `jer_support.c` for the low-level scanner shape).
//! `reader.rs`/`writer.rs` hold the hand-rolled recursive-descent JSON
//! scanner/escaper (not a full tokenizer — C++'s own `jer_detail::parse`
//! state machine is present there for completeness but its handlers use
//! the simpler helpers this module also uses).

pub mod bit_string;
pub mod choice;
pub mod enumerated;
pub mod object;
pub mod octet_string;
pub mod reader;
pub mod real;
pub mod seq_of;
pub mod sequence;
pub mod strings;
pub mod writer;
