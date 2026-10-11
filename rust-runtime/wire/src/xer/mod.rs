//! XER (X.693 BASIC-XER) — own subdirectory, matching `per/`'s/`jer/`'s
//! precedent: construct-walking logic (`object.rs`'s non-generic
//! reflective walker) lives fully alongside its own stream primitives
//! (`reader`/`writer`). `reader`
//! holds the decode-side primitives (`XerReader`, tag parsing,
//! unescape), `writer` the encode-side ones (escape, indent, tag
//! writing) — same split `jer::reader`/`jer::writer` use.

pub mod object;
pub mod reader;
pub mod seq_of;
pub mod writer;
