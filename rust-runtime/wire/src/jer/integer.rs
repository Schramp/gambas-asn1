//! X.697 §8.3: a JSON number literal, same text `Display`/`FromStr`
//! already produce for every signed/unsigned fixed-width integer storage
//! kind — one shared module instead of a near-duplicate copy per kind
//! (`Integer`/`UInteger`/`BigInteger`), same reasoning `xer::integer`
//! documents for its own XER twin.

use crate::ber::reader::DecodeError;
use std::fmt::Display;
use std::str::FromStr;

pub fn encode<T: Display>(value: T, out: &mut String) {
    out.push_str(&value.to_string());
}

pub fn decode<T: FromStr>(r: &mut super::reader::Reader<'_>) -> Result<T, DecodeError> {
    let tok = r.read_json_token()?;
    tok.parse::<T>()
        .map_err(|_| DecodeError::new(format!("JER: invalid INTEGER: {tok}"), r.pos()))
}
