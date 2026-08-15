//! XER (X.693 BASIC-XER) element-tag primitives — escape/unescape and
//! open/close/self-closing element-tag parse+write.
//!
//! Ports `xer_detail::xer_escape`/`xer_unescape`/`parse_tag`/`consume_tag`/
//! `consume_open_tag`/`consume_close_tag`/`read_text_content`
//! (`runtime/include/asn1cpp/codec/XerCodec.hpp`) — same escaping rules
//! (only `<`/`>`/`&` on encode; `&lt;`/`&gt;`/`&amp;`/`&quot;`/`&apos;` plus
//! numeric character references `&#NN;`/`&#xNN;` on decode), same
//! whitespace-tolerant tag grammar. `encode_sequence_xer`/
//! `decode_sequence_xer` are the table-driven walker built
//! on top of these primitives, using each member's own `name` as the element
//! tag (BER's `Asn1Value::ber_encode` writes its own tag because BER tags
//! are type-derived; XER tags are *field*-derived, so the walker — not
//! `Asn1Value` — owns tag wrapping). `decode_sequence_xer` hands each
//! member's `Asn1Value::xer_decode_into` the `XerReader` directly — see
//! `value.rs`'s trait doc for why a pre-extracted
//! `&str` doesn't work for every BASIC-XER content shape, e.g. BOOLEAN.
//!
//! Definite in-memory document only (mirrors `XerDecodeStream`, no
//! streaming parser) — matches the C++ side's own scope note.

use crate::reader::DecodeError;
use crate::sequence::SequenceSpec;

/// Append `s` to `out` with XER's three encode-time escapes (X.693 §8.2).
/// Mirrors `xer_detail::xer_escape`.
pub fn escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            _ => out.push(c),
        }
    }
}

/// Reverse of [`escape`], plus the additional named/numeric entities XER
/// input may contain (`&quot;`, `&apos;`, `&#NN;`, `&#xNN;`). Mirrors
/// `xer_detail::xer_unescape` — unrecognized `&...;` sequences pass through
/// literally rather than erroring, same as the C++ side.
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

/// `depth * 4` spaces — the C++ runtime's own indent unit
/// (`XerEncodeStream::indent`, `runtime/include/asn1cpp/codec/XerCodec.hpp`:
/// `4 * (depth_ + offset)`). `depth` means "the level this value's own
/// wrapper tag sits at" throughout the XER encode call graph (`Asn1Value::
/// xer_encode`'s own `depth` parameter, `encode_sequence_xer_content`,
/// `encode_choice_xer_into`, `sequence::encode_seq_of_xer_named`) — a
/// composite's content is always written one level deeper than its own
/// `depth`, recursively, matching the C++ runtime's `s.depth() + 1`
/// convention exactly (`XerCodec.cpp`'s `SequenceXerHandler`/
/// `ChoiceXerHandler`/`SeqOfXerHandler`, all three).
pub fn indent(depth: usize) -> String {
    " ".repeat(4 * depth)
}

/// Append `<name>` to `out`. Field-name-derived — callers (the
/// table-driven walker, `encode_sequence_xer` below) supply `name` from
/// `MemberDescriptor::name`, not from the value's own type.
pub fn write_open_tag(out: &mut String, name: &str) {
    out.push('<');
    out.push_str(name);
    out.push('>');
}

/// Append `</name>` to `out`.
pub fn write_close_tag(out: &mut String, name: &str) {
    out.push_str("</");
    out.push_str(name);
    out.push('>');
}

/// Generic SEQUENCE XER encoder — the XER analogue of
/// `encode_sequence` (`sequence.rs`) and the Rust equivalent of
/// `SequenceXerHandler::encode` (`runtime/src/XerCodec.cpp`). Walks the
/// *same* `SequenceSpec<T>`/`MemberDescriptor<T>` table `encode_sequence`
/// already uses — one table drives both wire formats (see `lib.rs`'s
/// crate doc). OPTIONAL suppression: an absent member is skipped entirely
/// (no `<member></member>` pair), via `Asn1Value::is_present` — unlike
/// BER, XER's outer element tag is this walker's own responsibility, not
/// something `Option<V>::xer_encode` can suppress by itself.
///
/// `depth` is *this SEQUENCE's own* depth — the level its own wrapper tag
/// sits at (`Asn1Value::xer_encode`'s own "argument = my position"
/// convention, matching the C++ runtime's `XerEncodeStream::depth()`
/// exactly, `runtime/include/asn1cpp/codec/XerCodec.hpp`). Each present
/// member is written one level deeper (`depth + 1`, `xer::indent`), and if
/// that member's own value is itself composite (SEQUENCE/CHOICE/SeqOf/
/// SetOf), *its* content recurses at `depth + 1` too (the value passed to
/// `val.xer_encode` — the member's own wrapper tag and its content sit at
/// the same depth argument, since `xer_encode` internally goes one level
/// deeper again for its own children, same convention throughout). An
/// empty SEQUENCE (no present members) contributes nothing at all —
/// `<Name></Name>` results automatically once the caller's own open/close
/// tags are placed back to back, matching `SequenceXerHandler`'s own
/// `!any_present` early return with no special case needed here.
///
/// Member-loop content of a SEQUENCE's XER encoding, without the outer
/// `<name>`/`</name>` wrapper — shared by `encode_sequence_xer` (the type's
/// own name) and, once a generated SEQUENCE/SET type has its own
/// `Asn1Value` impl, by a *member*'s field-name-derived wrapper instead
/// (XER tags are always field-derived, never type-derived — see this
/// module's own doc — so a nested composite member's inner content is
/// exactly this loop, wrapped in the *member's* tag by the caller, same
/// contract `Asn1Value::xer_encode` already documents for every other type).
fn encode_sequence_xer_content<T>(spec: &SequenceSpec<T>, value: &T, out: &mut String, depth: usize) {
    use crate::sequence::MemberAccess;
    let mut any = false;
    for m in spec.members {
        match &m.access {
            // TaggedScalar reuses Scalar's get here: XER
            // element tags are always field-name-derived, never
            // type-derived, so the BER-only tag override doesn't apply.
            MemberAccess::Scalar { get, .. } | MemberAccess::TaggedScalar { get, .. } | MemberAccess::ExplicitScalar { get, .. } => {
                let val = get(value);
                if !val.is_present() {
                    continue;
                }
                any = true;
                out.push('\n');
                out.push_str(&indent(depth + 1));
                write_open_tag(out, m.name);
                val.xer_encode(out, depth + 1);
                write_close_tag(out, m.name);
            }
            // ANY has no defined XER form here. Every generated type now
            // always gets a real xer_encode override (RustBackend.cpp no
            // longer gates emission on every member being XER-ready first —
            // see MemberAccess::Unsupported's doc), so this genuinely is
            // reachable whenever a type has an ANY member — not dead code.
            MemberAccess::ExplicitAny { .. } => panic!("member '{}': ANY has no defined XER form", m.name),
            MemberAccess::Unsupported { reason } => panic!("member '{}' not supported: {}", m.name, reason),
        }
    }
    if any {
        out.push('\n');
        out.push_str(&indent(depth));
    }
}

pub fn encode_sequence_xer<T>(spec: &SequenceSpec<T>, value: &T) -> String {
    let mut out = String::new();
    write_open_tag(&mut out, spec.name);
    encode_sequence_xer_content(spec, value, &mut out, 0);
    write_close_tag(&mut out, spec.name);
    out.push('\n');
    out
}

/// Appends a SEQUENCE's XER content (no outer wrapper) to an existing
/// buffer — the shape `Asn1Value::xer_encode` needs (writes only inner
/// content, wrapper is the caller's job) so a generated SEQUENCE/SET type
/// can implement that trait leg and become usable as a nested composite
/// member, same role `sequence::encode_sequence_into` plays for the BER leg.
pub fn encode_sequence_xer_into<T>(spec: &SequenceSpec<T>, value: &T, out: &mut String, depth: usize) {
    encode_sequence_xer_content(spec, value, out, depth);
}

/// Generic SEQUENCE XER decoder — the XER analogue of `decode_sequence`
/// (`sequence.rs`) and the Rust equivalent of `SequenceXerHandler::decode`.
/// `T::default()` provides the initial value, each member is decoded in
/// table order directly into its field.
///
/// OPTIONAL members: peek the next open tag's name before
/// consuming it — if it doesn't match this member's own element name, the
/// member is absent (leave it at its `Default`, i.e. `None`) and nothing is
/// consumed, same linear-scan/canonical-order assumption `decode_sequence`'s
/// BER leg documents.
fn decode_sequence_xer_content<T: Default>(spec: &SequenceSpec<T>, r: &mut XerReader) -> Result<T, DecodeError> {
    use crate::sequence::MemberAccess;
    let mut result = T::default();
    for m in spec.members {
        if m.optional {
            let peeked = r.peek_tag();
            if peeked.closing || peeked.name != m.name {
                continue;
            }
        }
        r.consume_open_tag(m.name)?;
        match &m.access {
            MemberAccess::Scalar { get_mut, .. } | MemberAccess::TaggedScalar { get_mut, .. } | MemberAccess::ExplicitScalar { get_mut, .. } =>
                get_mut(&mut result).xer_decode_into(r)?,
            MemberAccess::ExplicitAny { .. } => panic!("member '{}': ANY has no defined XER form", m.name),
            MemberAccess::Unsupported { reason } => panic!("member '{}' not supported: {}", m.name, reason),
        }
        r.consume_close_tag(m.name)?;
    }
    Ok(result)
}

pub fn decode_sequence_xer<T: Default>(spec: &SequenceSpec<T>, xml: &str) -> Result<T, DecodeError> {
    let mut r = XerReader::new(xml);
    r.consume_open_tag(spec.name)?;
    let result = decode_sequence_xer_content(spec, &mut r)?;
    r.consume_close_tag(spec.name)?;
    Ok(result)
}

/// `decode_sequence_xer`, but accepting the non-standard asn1c extensions
/// `XerReader::new_lenient` does (hex BIT STRING, text BOOLEAN) — not
/// wired into any generated type's own `decode_xer` (codegen has no way to
/// know which callers need leniency), so callers that do reach for this
/// directly, spec in hand (e.g. cross-validating against an asn1c-authored
/// fixture that uses those extensions).
pub fn decode_sequence_xer_lenient<T: Default>(spec: &SequenceSpec<T>, xml: &str) -> Result<T, DecodeError> {
    let mut r = XerReader::new_lenient(xml);
    r.consume_open_tag(spec.name)?;
    let result = decode_sequence_xer_content(spec, &mut r)?;
    r.consume_close_tag(spec.name)?;
    Ok(result)
}

/// Reads a SEQUENCE's XER content (no outer wrapper — already consumed by
/// the caller, same contract `Asn1Value::xer_decode_into` documents) from
/// the caller's current reader position — the shape that trait leg needs
/// so a generated SEQUENCE/SET type can implement it and become usable as
/// a nested composite member, same role `sequence::decode_sequence_from`
/// plays for the BER leg.
pub fn decode_sequence_xer_from<T: Default>(spec: &SequenceSpec<T>, r: &mut XerReader) -> Result<T, DecodeError> {
    decode_sequence_xer_content(spec, r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_covers_lt_gt_amp_only() {
        let mut out = String::new();
        escape("a<b>c&d\"e'f", &mut out);
        assert_eq!(out, "a&lt;b&gt;c&amp;d\"e'f");
    }

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
    fn round_trip_escape_unescape() {
        let original = "<tag> & \"quoted\"";
        let mut escaped = String::new();
        escape(original, &mut escaped);
        assert_eq!(unescape(&escaped), original);
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
    fn open_close_tag_round_trip() {
        let mut out = String::new();
        write_open_tag(&mut out, "x");
        out.push('1');
        write_close_tag(&mut out, "x");
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
