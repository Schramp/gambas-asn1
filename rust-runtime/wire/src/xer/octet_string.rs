//! XER OCTET STRING encode/decode — X.680 §22. Mirrors
//! `OctetStringXerHandler`'s default (non-Base64) encoding: unspaced
//! uppercase hex pairs (`write_hex_bytes`, `runtime/src/HexEncoder.hpp`)
//! — distinct from BIT STRING/hex-string types' *spaced* hex
//! (`format_hex_bytes`), not implemented here. Also carries the BASE64
//! and utf8 ENCODING-CONTROL (X.693 §21) alternative encodings: a
//! generated builtin-alias type's own `Asn1Value` impl
//! (`RustBackend::emit_builtin_alias_definition`) calls `base64_encode`/
//! `base64_decode`/`utf8_encode`/`utf8_decode` directly instead of
//! going through `OctetString`'s own hex `xer_encode`/`xer_decode_into`
//! when `BuiltinAliasSpec::xer_encoding` says so — there's no
//! per-instance flag on `OctetString` itself to branch on (Rust's
//! `Asn1Value` is a compile-time trait impl, not a runtime-descriptor-
//! driven dispatch the way C++'s `TypeDescriptor::xer_encoding` field
//! is), so the choice is baked into the generated type's own method
//! bodies at codegen time. `octet_string::base64_encode`/`base64_decode`/
//! `utf8_encode`/`utf8_decode` re-export these at their original path
//! so that generated code (which names them by that path) keeps
//! compiling unchanged.

use crate::ber::reader::DecodeError;
use crate::xer::reader::XerReader;

pub fn encode(bytes: &[u8], out: &mut String) {
    for b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
}

pub fn decode(r: &mut XerReader) -> Result<Vec<u8>, DecodeError> {
    let text = r.read_text_content();
    // Mirrors parse_hex_bytes (runtime/src/XerCodec.cpp): skip
    // whitespace between pairs, stop silently (not an error) at the
    // first non-hex-pair remainder — lenient by design on the C++ side,
    // matched here rather than diverging into stricter validation.
    let mut bytes = Vec::new();
    let trimmed = text.trim();
    let mut chars = trimmed.chars().filter(|c| !c.is_whitespace()).peekable();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let byte_str: String = [hi, lo].iter().collect();
        match u8::from_str_radix(&byte_str, 16) {
            Ok(b) => bytes.push(b),
            Err(_) => break,
        }
    }
    Ok(bytes)
}

/// Mirrors `base64_encode`/`base64_decode` in `runtime/src/XerCodec.cpp`
/// byte-for-byte (same alphabet, same '='-padding).
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((input.len() + 2) / 3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied();
        let b2 = chunk.get(2).copied();
        let v = (b0 as u32) << 16 | (b1.unwrap_or(0) as u32) << 8 | (b2.unwrap_or(0) as u32);
        out.push(TABLE[((v >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((v >> 12) & 0x3F) as usize] as char);
        out.push(if b1.is_some() { TABLE[((v >> 6) & 0x3F) as usize] as char } else { '=' });
        out.push(if b2.is_some() { TABLE[(v & 0x3F) as usize] as char } else { '=' });
    }
    out
}

pub fn base64_decode(input: &str) -> Vec<u8> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in input.bytes() {
        let Some(v) = val(c) else { continue };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    out
}

// X.680 §11.15.5 Table 3 — escape sequences for control characters in an
// "xmlcstring", used by the utf8 ENCODING-CONTROL XER instruction.
// Codes 9 (tab), 10 (LF), 13 (CR) are excluded per the
// table's own NOTE — those pass through literally. Mirrors
// `control_char_tag_name`/`control_char_from_tag_name` in `runtime/src/XerCodec.cpp`.
fn control_char_tag_name(c: u8) -> Option<&'static str> {
    Some(match c {
        0 => "nul", 1 => "soh", 2 => "stx", 3 => "etx", 4 => "eot", 5 => "enq", 6 => "ack", 7 => "bel",
        8 => "bs",
        11 => "vt", 12 => "ff",
        14 => "so", 15 => "si", 16 => "dle",
        17 => "dc1", 18 => "dc2", 19 => "dc3", 20 => "dc4", 21 => "nak", 22 => "syn", 23 => "etb", 24 => "can",
        25 => "em", 26 => "sub", 27 => "esc", 28 => "is4", 29 => "is3", 30 => "is2", 31 => "is1",
        _ => return None,
    })
}

fn control_char_from_tag_name(name: &str) -> Option<u8> {
    Some(match name {
        "nul" => 0, "soh" => 1, "stx" => 2, "etx" => 3, "eot" => 4, "enq" => 5, "ack" => 6, "bel" => 7,
        "bs" => 8,
        "vt" => 11, "ff" => 12,
        "so" => 14, "si" => 15, "dle" => 16,
        "dc1" => 17, "dc2" => 18, "dc3" => 19, "dc4" => 20, "nak" => 21, "syn" => 22, "etb" => 23, "can" => 24,
        "em" => 25, "sub" => 26, "esc" => 27, "is4" => 28, "is3" => 29, "is2" => 30, "is1" => 31,
        _ => return None,
    })
}

/// utf8 ENCODING-CONTROL instruction (X.693 §21): content
/// octets are raw UTF-8 text, written directly as XML character data
/// except for `&`/`<`/`>` (standard XML entities) and the Table 3 control
/// characters (empty-element tags). Mirrors `write_utf8_text` in
/// `runtime/src/XerCodec.cpp`.
///
/// Byte-batches runs of plain content instead of pushing byte-by-byte:
/// `byte as char` on a raw `u8` is a *Latin-1* cast, not "reinterpret this
/// byte as UTF-8" — pushing e.g. `0xC3u8 as char` into a `String` writes
/// the *codepoint* U+00C3 (which Rust then re-encodes as the two bytes
/// `0xC3 0x83`), silently corrupting any multi-byte UTF-8 sequence in the
/// input. Passthrough runs only ever break on ASCII byte values (`&`/`<`/
/// `>`/C0 controls), and UTF-8 continuation/lead bytes are always ≥ 0x80,
/// so a run boundary can never land mid-codepoint — `str::from_utf8` on
/// each run is always valid for a genuinely well-formed UTF-8 input.
pub fn utf8_encode(input: &[u8], out: &mut String) {
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        let escape: Option<String> = match b {
            b'&' => Some("&amp;".to_string()),
            b'<' => Some("&lt;".to_string()),
            b'>' => Some("&gt;".to_string()),
            9 | 10 | 13 => None,
            0..=31 => control_char_tag_name(b).map(|n| format!("<{n}/>")),
            _ => None,
        };
        if let Some(esc) = escape {
            out.push_str(&esc);
            i += 1;
            continue;
        }
        let start = i;
        while i < input.len() {
            let c = input[i];
            let needs_escape = c == b'&' || c == b'<' || c == b'>'
                || (c < 32 && c != 9 && c != 10 && c != 13);
            if needs_escape { break; }
            i += 1;
        }
        match std::str::from_utf8(&input[start..i]) {
            Ok(s) => out.push_str(s),
            // Not well-formed UTF-8 (a schema/value mismatch, not something
            // this function can fix) — lossy fallback rather than a panic.
            Err(_) => out.push_str(&String::from_utf8_lossy(&input[start..i])),
        }
    }
}

/// Reads utf8-instruction mixed content: text runs (unescaped via
/// `crate::xer::reader::unescape`) interleaved with Table 3 empty-element tags.
/// Mirrors `decode_utf8_text` in `runtime/src/XerCodec.cpp`, but — unlike
/// that C++ function — does not consume the element's own open/close
/// tags: matches this crate's existing `Asn1Value::xer_decode_into`
/// convention, where the generic walker owns tag consumption, not the
/// per-type decode logic. Stops (without consuming) at the first tag
/// that isn't a recognized control-character empty-element tag — that's
/// the caller's own closing tag.
pub fn utf8_decode(r: &mut XerReader) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    loop {
        out.extend_from_slice(crate::xer::reader::unescape(r.read_text_content()).as_bytes());
        let peek = r.peek_tag();
        if peek.self_closing {
            if let Some(b) = control_char_from_tag_name(&peek.name) {
                r.consume_tag();
                out.push(b);
                continue;
            }
        }
        break;
    }
    Ok(out)
}
