//! XER (X.693 BASIC-XER) — own subdirectory, matching `per/`'s precedent
//! (and now `jer/`'s): construct-walking logic (`sequence`/`choice`/
//! `seq_of`) lives fully alongside its own stream primitives
//! (`reader`/`writer`), not split across this module and `ber/*.rs` the
//! way it used to be (gambas-asn1#666 — a known inconsistency flagged
//! while porting JER, #661/#662, which deliberately copied PER's clean
//! layout from day one instead of repeating this one). `reader` holds the
//! decode-side primitives (`XerReader`, tag parsing, unescape), `writer`
//! the encode-side ones (escape, indent, tag writing) — same split
//! `jer::reader`/`jer::writer` use.

pub mod choice;
pub mod object;
pub mod reader;
pub mod sequence;
pub mod seq_of;
pub mod writer;
