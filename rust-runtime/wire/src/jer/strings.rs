//! Character-string types -- X.697 §8.19-§8.24. Three representations,
//! mirroring `StringJerHandler`/`HexStringJerHandler`/
//! `BmpStringJerHandler`/`UniversalStringJerHandler`/`TimeJerHandler`
//! (`runtime/src/JerCodec.cpp`):
//!
//! - **Plain** (UTF8String, VisibleString, IA5String, PrintableString,
//!   NumericString, UTCTime, GeneralizedTime): quoted UTF-8, JSON-escaped.
//! - **Hex** (T61String, VideotexString, GraphicString, GeneralString):
//!   quoted uppercase hex of the raw storage bytes.
//! - **Wide** (BMPString bpc=2, UniversalString bpc=4): quoted UTF-8 --
//!   unlike the C++ reference, which cheats by round-tripping through
//!   `XerCodec` internally to get UTF-8 text, this decodes the
//!   big-endian codepoint groups directly (same technique this crate's
//!   own XER wide-string support already uses in `strings.rs`'s
//!   `encode_wide_string_xer`/`decode_wide_string_xer`, just emitting
//!   JSON escapes instead of XML entity escapes).

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::jer::writer::{json_escape, parse_hex_str, to_hex_upper};

pub fn encode_plain(s: &str, out: &mut String) {
    out.push('"');
    json_escape(s, out);
    out.push('"');
}

pub fn decode_plain(r: &mut Reader) -> Result<String, DecodeError> {
    r.read_json_string()
}

pub fn encode_hex(bytes: &[u8], out: &mut String) {
    out.push('"');
    to_hex_upper(bytes, out);
    out.push('"');
}

pub fn decode_hex(r: &mut Reader) -> Result<Vec<u8>, DecodeError> {
    let hex = r.read_json_string()?;
    Ok(parse_hex_str(&hex))
}

/// Wide-char (BMPString/UniversalString) raw `bpc`-byte-per-codepoint
/// storage -> JSON quoted UTF-8 string.
pub fn encode_wide(bytes: &[u8], bpc: usize, out: &mut String) {
    let mut text = String::with_capacity(bytes.len() / bpc.max(1));
    for chunk in bytes.chunks_exact(bpc) {
        let mut cp: u32 = 0;
        for &b in chunk {
            cp = (cp << 8) | b as u32;
        }
        text.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
    }
    out.push('"');
    json_escape(&text, out);
    out.push('"');
}

/// Reverse of `encode_wide`: JSON quoted UTF-8 string -> raw
/// `bpc`-byte-per-codepoint storage bytes.
pub fn decode_wide(r: &mut Reader, bpc: usize) -> Result<Vec<u8>, DecodeError> {
    let text = r.read_json_string()?;
    let mut out = Vec::with_capacity(text.chars().count() * bpc);
    for c in text.chars() {
        let cp = c as u32;
        for i in (0..bpc).rev() {
            out.push(((cp >> (8 * i)) & 0xFF) as u8);
        }
    }
    Ok(out)
}
