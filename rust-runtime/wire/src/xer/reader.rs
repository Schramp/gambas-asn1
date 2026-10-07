//! XER decode-side primitives — element-tag parsing and unescape.
//!
//! Ports `xer_detail::xer_unescape`/`parse_tag`/`consume_tag`/
//! `consume_open_tag`/`consume_close_tag`/`read_text_content`
//! (`runtime/include/asn1cpp/codec/XerCodec.hpp`) — same whitespace-
//! tolerant tag grammar, same named/numeric entity decoding (`&lt;`/
//! `&gt;`/`&amp;`/`&quot;`/`&apos;`, `&#NN;`/`&#xNN;`).
//!
//! Definite in-memory document only (mirrors `XerDecodeStream`, no
//! streaming parser) — matches the C++ side's own scope note.

use crate::ber::reader::DecodeError;

/// Reverse of [`crate::xer::writer::escape`], plus the additional named/
/// numeric entities XER input may contain (`&quot;`, `&apos;`, `&#NN;`,
/// `&#xNN;`). Mirrors `xer_detail::xer_unescape` — unrecognized `&...;`
/// sequences pass through literally rather than erroring, same as the
/// C++ side.
///
/// Batches runs of non-`&` bytes instead of pushing byte-by-byte: `byte as
/// char` on a raw `u8` is a *Latin-1* cast, not "reinterpret this byte as
/// UTF-8" — for any byte ≥ 0x80 (a UTF-8 continuation/lead byte) it pushes
/// the wrong codepoint, which Rust then re-encodes as a *different*,
/// wrong multi-byte sequence, corrupting any non-ASCII character in the
/// input (silently, since the result is still "valid" UTF-8 — just not
/// the same bytes). `s: &str` is already guaranteed valid UTF-8 at the
/// type level, and `&` (0x26) can only ever appear as a genuine standalone
/// ASCII character in valid UTF-8, never as a continuation byte — so
/// slicing `s` at any byte offset landing on a literal `&` is always a
/// valid char boundary, making the batched slice trivially safe.
pub fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            let start = i;
            while i < bytes.len() && bytes[i] != b'&' {
                i += 1;
            }
            out.push_str(&s[start..i]);
            continue;
        }
        let mut end = i + 1;
        while end < bytes.len() && end - i < 12 && bytes[end] != b';' {
            end += 1;
        }
        if end >= bytes.len() || bytes[end] != b';' {
            out.push('&');
            i += 1;
            continue;
        }
        let ent = &s[i + 1..end];
        match decode_entity(ent) {
            Some(ch) => {
                out.push(ch);
                i = end + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    out
}

fn decode_entity(ent: &str) -> Option<char> {
    match ent {
        "lt" => return Some('<'),
        "gt" => return Some('>'),
        "amp" => return Some('&'),
        "quot" => return Some('"'),
        "apos" => return Some('\''),
        _ => {}
    }
    let num = ent.strip_prefix('#')?;
    let (digits, radix) = match num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
        Some(hex) => (hex, 16),
        None => (num, 10),
    };
    let cp = u32::from_str_radix(digits, radix).ok()?;
    char::from_u32(cp)
}

/// One parsed element tag: `name`, whether it's a closing tag (`</name>`),
/// and whether it's self-closing (`<name/>`). Mirrors `xer_detail::TagInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagInfo {
    pub name: String,
    pub closing: bool,
    pub self_closing: bool,
}

fn is_xer_ws(c: u8) -> bool {
    matches!(c, b'\t' | b'\n' | b'\r' | b' ')
}

/// In-memory XER document cursor. Mirrors `XerDecodeStream` plus the
/// `xer_detail` free functions that operate on it.
pub struct XerReader<'a> {
    buf: &'a str,
    pos: usize,
    lenient: bool,
}

impl<'a> XerReader<'a> {
    pub fn new(buf: &'a str) -> XerReader<'a> {
        XerReader { buf, pos: 0, lenient: false }
    }

    /// Accepts the non-standard asn1c XER extensions `XerDecodeStream`'s
    /// `XerDecodeMode::Lenient` does (`runtime/include/asn1cpp/codec/XerCodec.hpp`):
    /// BOOLEAN as text content `"true"`/`"false"` (EXTENDED-XER §10) in
    /// addition to the standard empty-element form, and BIT STRING as hex
    /// pairs in addition to the standard '0'/'1' xmlbstring form.
    pub fn new_lenient(buf: &'a str) -> XerReader<'a> {
        XerReader { buf, pos: 0, lenient: true }
    }

    pub fn lenient(&self) -> bool {
        self.lenient
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn remaining(&self) -> &'a [u8] {
        &self.buf.as_bytes()[self.pos..]
    }

    fn skip_ws(&self, mut p: usize) -> usize {
        let rem = self.remaining();
        while p < rem.len() && is_xer_ws(rem[p]) {
            p += 1;
        }
        p
    }

    /// Parse (without consuming) the tag at `self.pos + start`, mirrors
    /// `xer_detail::parse_tag`. Returns `(TagInfo, bytes_consumed)`; an empty
    /// `name` with `bytes_consumed == 0` means "no tag here" (matches the
    /// C++ side's empty-`TagInfo` sentinel).
    fn parse_tag_at(&self, start: usize) -> (TagInfo, usize) {
        let rem = self.remaining();
        let mut p = self.skip_ws(start);
        if p >= rem.len() || rem[p] != b'<' {
            return (TagInfo { name: String::new(), closing: false, self_closing: false }, p);
        }
        p += 1;
        let closing = p < rem.len() && rem[p] == b'/';
        if closing {
            p += 1;
        }
        let name_start = p;
        while p < rem.len() && rem[p] != b'>' && rem[p] != b'/' && !is_xer_ws(rem[p]) {
            p += 1;
        }
        let name = std::str::from_utf8(&rem[name_start..p]).unwrap_or("").to_string();
        p = self.skip_ws(p);
        let self_closing = p < rem.len() && rem[p] == b'/';
        if self_closing {
            p += 1;
        }
        if p < rem.len() && rem[p] == b'>' {
            p += 1;
        }
        (TagInfo { name, closing, self_closing }, p)
    }

    /// Consume and return the next tag. Mirrors `xer_detail::consume_tag`.
    pub fn consume_tag(&mut self) -> TagInfo {
        let (ti, consumed) = self.parse_tag_at(0);
        self.pos += consumed;
        ti
    }

    /// Peek the next tag without consuming it. Mirrors `xer_detail::peek_tag`.
    pub fn peek_tag(&self) -> TagInfo {
        self.parse_tag_at(0).0
    }

    /// Consume and return raw (still-escaped) text up to the next `<`.
    /// Mirrors `xer_detail::read_text_content`.
    pub fn read_text_content(&mut self) -> &'a str {
        let rem = self.remaining();
        let mut p = 0;
        while p < rem.len() && rem[p] != b'<' {
            p += 1;
        }
        let text = std::str::from_utf8(&rem[..p]).unwrap_or("");
        self.pos += p;
        text
    }

    /// Consume an opening tag `<name>`, erroring if it's absent, a closing
    /// tag, or self-closing. Mirrors `xer_detail::consume_open_tag`.
    pub fn consume_open_tag(&mut self, name: &str) -> Result<(), DecodeError> {
        let ti = self.consume_tag();
        if ti.name != name || ti.closing || ti.self_closing {
            return Err(DecodeError::new(format!("XER: expected <{name}>"), self.pos));
        }
        Ok(())
    }

    /// Consume a closing tag `</name>`, erroring if absent or mismatched.
    /// Mirrors `xer_detail::consume_close_tag`.
    pub fn consume_close_tag(&mut self, name: &str) -> Result<(), DecodeError> {
        let ti = self.consume_tag();
        if !ti.closing || ti.name != name {
            return Err(DecodeError::new(format!("XER: expected </{name}>"), self.pos));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_named_entities() {
        assert_eq!(unescape("a&lt;b&gt;c&amp;d&quot;e&apos;f"), "a<b>c&d\"e'f");
    }

    #[test]
    fn unescape_numeric_entities() {
        assert_eq!(unescape("&#65;&#x42;"), "AB");
    }

    #[test]
    fn unescape_unknown_entity_passes_through() {
        assert_eq!(unescape("a&nbsp;b"), "a&nbsp;b");
    }

    #[test]
    fn unescape_preserves_multi_byte_utf8() {
        // Regression test: byte-by-byte `bytes[i] as char` corrupts any
        // byte >= 0x80 (a Latin-1 cast, not a UTF-8 reinterpretation) —
        // caught via gambas-asn1#443's utf8 XER instruction work, but this
        // bug predates it and affects every Rust-decoded XER string field
        // with non-ASCII content (strings.rs calls unescape too).
        assert_eq!(unescape("caf\u{00e9}"), "caf\u{00e9}"); // 2-byte (é)
        assert_eq!(unescape("\u{4e2d}\u{6587}"), "\u{4e2d}\u{6587}"); // 3-byte (中文)
        assert_eq!(unescape("\u{1f600}"), "\u{1f600}"); // 4-byte emoji (😀)
        assert_eq!(unescape("a\u{1f600}&amp;\u{00e9}b"), "a\u{1f600}&\u{00e9}b");
    }

    #[test]
    fn round_trip_escape_unescape() {
        let original = "<tag> & \"quoted\"";
        let mut escaped = String::new();
        crate::xer::writer::escape(original, &mut escaped);
        assert_eq!(unescape(&escaped), original);
    }

    #[test]
    fn open_close_tag_round_trip() {
        let mut out = String::new();
        crate::xer::writer::write_open_tag(&mut out, "x");
        out.push('1');
        crate::xer::writer::write_close_tag(&mut out, "x");
        assert_eq!(out, "<x>1</x>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("x").unwrap();
        let text = r.read_text_content();
        assert_eq!(text, "1");
        r.consume_close_tag("x").unwrap();
        assert!(r.at_end());
    }

    #[test]
    fn consume_open_tag_wrong_name_is_error() {
        let mut r = XerReader::new("<y>1</y>");
        assert!(r.consume_open_tag("x").is_err());
    }

    #[test]
    fn peek_tag_does_not_advance() {
        let r = XerReader::new("<x>1</x>");
        let ti = r.peek_tag();
        assert_eq!(ti.name, "x");
        assert!(!ti.closing);
        assert!(!ti.self_closing);
        assert!(!r.at_end());
    }

    #[test]
    fn self_closing_tag_is_detected() {
        let mut r = XerReader::new("<flag/>");
        let ti = r.consume_tag();
        assert_eq!(ti.name, "flag");
        assert!(ti.self_closing);
        assert!(!ti.closing);
    }
}
