//! X.697 JER (JSON Encoding Rules) — text-based reader/writer and
//! per-construct encode/decode (`object.rs`'s non-generic reflective
//! walker, gambas-asn1#681 full migration — every construct kind lives
//! there now, not split across per-kind files the way an earlier
//! generic-table design once needed).
//!
//! Ported from `runtime/src/JerCodec.cpp`'s handler classes (itself
//! ported from asn1c's `jer_support.c` for the low-level scanner shape).
//! `reader.rs`/`writer.rs` hold the hand-rolled recursive-descent JSON
//! scanner/escaper (not a full tokenizer — C++'s own `jer_detail::parse`
//! state machine is present there for completeness but its handlers use
//! the simpler helpers this module also uses).

pub mod bit_string;
pub mod enumerated;
pub mod object;
pub mod octet_string;
pub mod reader;
pub mod real;
pub mod seq_of;
pub mod strings;
pub mod writer;
