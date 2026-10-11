//! XER INTEGER encode/decode — X.680 §18, X.693 §15. Plain decimal text,
//! no special values (unlike REAL) — generic over any fixed-width signed
//! or unsigned integer storage (`i64`/`u64`/`i128`), since the text
//! format is identical regardless of width. Shared by `Integer`/
//! `UInteger`/`BigInteger` rather than one file per width: the previous
//! per-width duplication (`fixed_width_integer!`'s own BigInteger
//! sibling hand-copied the same two lines for `i128`) is exactly the
//! kind of near-identical-logic drift this crate's leaf-type codec
//! split is meant to avoid, not reproduce three times over.

use crate::ber::reader::DecodeError;
use crate::xer::reader::XerReader;
use std::fmt::Display;
use std::str::FromStr;

pub fn encode<T: Display>(value: T, out: &mut String) {
    out.push_str(&value.to_string());
}

pub fn decode<T: FromStr>(r: &mut XerReader) -> Result<T, DecodeError> {
    let text = r.read_text_content();
    text.trim()
        .parse::<T>()
        .map_err(|_| DecodeError::new(format!("XER: invalid INTEGER value: {text}"), 0))
}
