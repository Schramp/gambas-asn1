//! XER (X.693 BASIC-XER) — own subdirectory, matching `per/`'s/`jer/`'s
//! precedent: construct-walking logic (`object.rs`'s non-generic
//! reflective walker) lives fully alongside its own stream primitives
//! (`reader`/`writer`). `reader`
//! holds the decode-side primitives (`XerReader`, tag parsing,
//! unescape), `writer` the encode-side ones (escape, indent, tag
//! writing) — same split `jer::reader`/`jer::writer` use.

pub mod bit_string;
pub mod boolean;
pub mod integer;
pub mod object;
pub mod octet_string;
pub mod oid;
pub mod reader;
pub mod real;
pub mod relative_oid;
pub mod writer;
