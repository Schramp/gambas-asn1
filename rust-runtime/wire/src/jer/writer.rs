//! JSON output helpers — escaping and hex formatting, shared by every
//! JER leaf encoder. Mirrors `json_escape`/`to_hex_upper`/`from_hex`/
//! `parse_hex_str` in `runtime/src/JerCodec.cpp`.

/// Escape a string for JSON output (X.697's JSON string syntax —
/// RFC 8259 §7). Only the escapes C++'s own `json_escape` emits: `"`,
/// `\`, and control characters below 0x20 as `\u00XX`. Everything else
/// (including non-ASCII UTF-8) passes through unescaped, same as the
/// C++ reference.
pub fn json_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// Uppercase hex, no spaces (X.697 §8.8/§8.9) — OCTET STRING's default
/// JER representation and the hex-encoded string types' own.
pub fn to_hex_upper(bytes: &[u8], out: &mut String) {
    for b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
}

/// Parse a hex string (either case) into bytes — mirrors
/// `jer_detail::parse_hex_str`'s lenient truncation (an odd trailing
/// nibble is silently dropped, not an error).
pub fn parse_hex_str(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        match (hex_val(pair[0]), hex_val(pair[1])) {
            (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
            _ => break,
        }
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}
