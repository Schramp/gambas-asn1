//! OCTET STRING encode/decode — X.680 §22, X.690 §8.7.
//!
//! The value octets *are* the encoding — no length/sign massaging like
//! INTEGER needs.
//!
//! `OctetString` is its own newtype (`pub struct OctetString(pub Vec<u8>)`),
//! not a direct `Asn1Value` impl on bare `Vec<u8>` — mirrors the C++
//! runtime's own `asn1::OctetString` (never raw `std::string`/
//! `std::vector<uint8_t>`) and this crate's existing `BitString`/
//! `ObjectIdentifier`/`RelativeOid`/the 11 restricted-character-string
//! newtypes (`strings.rs`). A bare `Vec<u8>` impl would also permanently
//! block any generic `impl<V: Asn1Value> Asn1Value for Vec<V>` (Rust allows
//! only one trait impl per concrete type) — every SEQUENCE OF/SET OF
//! member needs its own `SeqOf<T>`/`SetOf<T>` wrapper type specifically
//! because of this (`rust-runtime/ber/src/sequence.rs`), and codegen has to
//! special-case "is this an unusable bare `Vec<T>`" at several call sites
//! (`RustBackend.cpp`'s `rust_mtype_is_unusable_vec`) as a direct
//! consequence.

use crate::reader::{DecodeError, Reader};
use crate::tag::{universal, Tag};
use crate::value::Asn1Value;
use crate::writer::write_primitive;
use crate::xer::XerReader;

pub const OCTET_STRING_TAG: Tag = Tag::universal(universal::OCTET_STRING, false);

/// An OCTET STRING value — X.680 §22. Plain byte payload, no framing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OctetString(pub Vec<u8>);

/// `Deref`/`DerefMut` to the underlying `Vec<u8>` — same ergonomic pattern
/// `RustBackend::emit_seq_of_declaration`'s generated wrapper structs
/// already use (`impl Deref for {SeqOfAlias} { type Target = Vec<T>; ... }`)
/// so `.len()`/slicing/iteration keep working transparently through the
/// newtype (e.g. a generated `*_size_ok` bounds-check function), without
/// every caller needing an explicit `.0`.
impl std::ops::Deref for OctetString {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl std::ops::DerefMut for OctetString {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

/// Mirrors `OctetStringXerHandler`'s default (non-Base64) encoding: unspaced
/// uppercase hex pairs (`write_hex_bytes`, `runtime/src/HexEncoder.hpp`) —
/// distinct from BIT STRING/hex-string types' *spaced* hex
/// (`format_hex_bytes`), not implemented by this crate.
impl Asn1Value for OctetString {
    fn ber_natural_tag(&self) -> Tag {
        OCTET_STRING_TAG
    }

    fn xer_element_name(&self) -> &'static str {
        "OCTET_STRING"
    }

    // OCTET STRING content octets *are* the value bytes — no encoding step.
    fn ber_encode_content(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn ber_decode_content(&mut self, content: &[u8]) -> Result<(), DecodeError> {
        self.0 = content.to_vec();
        Ok(())
    }

    fn xer_encode(&self, out: &mut String, _depth: usize) {
        for b in &self.0 {
            out.push_str(&format!("{b:02X}"));
        }
    }

    fn xer_decode_into(&mut self, r: &mut XerReader) -> Result<(), DecodeError> {
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
        self.0 = bytes;
        Ok(())
    }
}

/// BASE64 XER representation (X.693 §21) for an OCTET STRING-derived type
/// under an `ENCODING-CONTROL XER ... BASE64 <TypeName>` (or legacy
/// `<TypeName> OCTET STRING ::= base64`) instruction — the alternative to
/// this module's own default (unspaced uppercase hex, `xer_encode` above).
/// Mirrors `base64_encode`/`base64_decode` in `runtime/src/XerCodec.cpp`
/// byte-for-byte (same alphabet, same '='-padding), since a generated
/// alias type's own `Asn1Value` impl (`RustBackend::
/// emit_builtin_alias_definition`) calls these directly instead of
/// delegating to `OctetString`'s own hex `xer_encode`/`xer_decode_into`
/// when `BuiltinAliasSpec::xer_encoding` is `Base64` — there's no per-instance
/// flag on `OctetString` itself to branch on (Rust's `Asn1Value` is a
/// compile-time trait impl, not a runtime-descriptor-driven dispatch the
/// way C++'s `TypeDescriptor::xer_encoding` field is), so the choice is
/// baked into the generated type's own method bodies at codegen time.
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
// "xmlcstring", used by the utf8 ENCODING-CONTROL XER instruction
// (gambas-asn1#443). Codes 9 (tab), 10 (LF), 13 (CR) are excluded per the
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

/// utf8 ENCODING-CONTROL instruction (X.693 §21, gambas-asn1#443): content
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
/// `crate::xer::unescape`) interleaved with Table 3 empty-element tags.
/// Mirrors `decode_utf8_text` in `runtime/src/XerCodec.cpp`, but — unlike
/// that C++ function — does not consume the element's own open/close
/// tags: matches this crate's existing `Asn1Value::xer_decode_into`
/// convention (see `OctetString::xer_decode_into`'s own hex-decode leg,
/// or `base64_decode`'s call site in `RustBackend::
/// emit_builtin_alias_definition`), where the generic walker
/// (`decode_sequence_xer`/`decode_choice_xer`) owns tag consumption, not
/// the per-type decode logic. Stops (without consuming) at the first tag
/// that isn't a recognized control-character empty-element tag — that's
/// the caller's own closing tag.
pub fn utf8_decode(r: &mut crate::xer::XerReader) -> Result<Vec<u8>, crate::reader::DecodeError> {
    let mut out = Vec::new();
    loop {
        out.extend_from_slice(crate::xer::unescape(r.read_text_content()).as_bytes());
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

pub fn write_octet_string(out: &mut Vec<u8>, value: &[u8]) {
    write_octet_string_tagged(out, OCTET_STRING_TAG, value);
}

pub fn read_octet_string<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], DecodeError> {
    read_octet_string_tagged(r, OCTET_STRING_TAG)
}

/// IMPLICIT tag override — see `boolean::write_boolean_tagged`'s
/// doc for the general rationale (X.690 §8.14). Same raw value octets,
/// different tag octets.
pub fn write_octet_string_tagged(out: &mut Vec<u8>, tag: Tag, value: &[u8]) {
    write_primitive(out, tag, value);
}

pub fn read_octet_string_tagged<'a>(r: &mut Reader<'a>, tag: Tag) -> Result<&'a [u8], DecodeError> {
    let tlv = r.read_tlv()?;
    if tlv.tag != tag {
        return Err(DecodeError::new(
            format!("expected OCTET STRING tag, got {:?}", tlv.tag),
            r.pos(),
        ));
    }
    Ok(tlv.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value() {
        let mut buf = Vec::new();
        write_octet_string(&mut buf, &[]);
        assert_eq!(buf, vec![0x04, 0x00]);
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_octet_string(&mut buf, b"hi");
        assert_eq!(buf, vec![0x04, 0x02, 0x68, 0x69]);
        let mut r = Reader::new(&buf);
        assert_eq!(read_octet_string(&mut r).unwrap(), b"hi");
    }

    #[test]
    fn wrong_tag_is_error() {
        let data = [0x02, 0x01, 0x05]; // INTEGER tag, not OCTET STRING
        let mut r = Reader::new(&data);
        assert!(read_octet_string(&mut r).is_err());
    }

    #[test]
    fn tagged_uses_the_given_tag_not_the_natural_one() {
        let context_2 = Tag::context(2, false);
        let mut buf = Vec::new();
        write_octet_string_tagged(&mut buf, context_2, b"hi");
        assert_eq!(buf, vec![0x82, 0x02, 0x68, 0x69]); // context primitive 2, not 0x04
        let mut r = Reader::new(&buf);
        assert_eq!(read_octet_string_tagged(&mut r, context_2).unwrap(), b"hi");
    }

    // ---- Asn1Value trait leg (moved from value.rs's own test module —
    // was Vec<u8>-as-Asn1Value, now OctetString-as-Asn1Value) -------------

    #[test]
    fn ber_round_trips_through_the_trait() {
        let mut out = Vec::new();
        OctetString(vec![0x68, 0x69]).ber_encode(&mut out);
        assert_eq!(out, vec![0x04, 0x02, 0x68, 0x69]);

        let mut r = Reader::new(&out);
        let mut got = OctetString::default();
        got.ber_decode_into(&mut r).unwrap();
        assert_eq!(got.0, vec![0x68, 0x69]);
    }

    #[test]
    fn xer_encodes_unspaced_uppercase_hex() {
        let mut out = String::new();
        OctetString(vec![0x68, 0x69]).xer_encode(&mut out, 0);
        assert_eq!(out, "6869");
    }

    #[test]
    fn xer_round_trips_wrapped_by_hand() {
        use crate::xer::{write_close_tag, write_open_tag, XerReader};

        let mut out = String::new();
        write_open_tag(&mut out, "data");
        OctetString(vec![0x68, 0x69]).xer_encode(&mut out, 0);
        write_close_tag(&mut out, "data");
        assert_eq!(out, "<data>6869</data>");

        let mut r = XerReader::new(&out);
        r.consume_open_tag("data").unwrap();
        let mut got = OctetString::default();
        got.xer_decode_into(&mut r).unwrap();
        r.consume_close_tag("data").unwrap();
        assert_eq!(got.0, vec![0x68, 0x69]);
    }

    #[test]
    fn xer_empty_round_trips() {
        let mut r = XerReader::new("");
        let mut got = OctetString::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got.0, Vec::<u8>::new());
    }

    #[test]
    fn xer_odd_trailing_nibble_is_dropped_leniently() {
        // Matches parse_hex_bytes's lenient truncation, not an error.
        let mut r = XerReader::new("686");
        let mut got = OctetString::default();
        got.xer_decode_into(&mut r).unwrap();
        assert_eq!(got.0, vec![0x68]);
    }

    #[test]
    fn base64_round_trips() {
        assert_eq!(base64_encode(b"hi"), "aGk=");
        assert_eq!(base64_decode("aGk="), b"hi");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode(""), Vec::<u8>::new());
        assert_eq!(base64_encode(b"any carnal pleasure"), "YW55IGNhcm5hbCBwbGVhc3VyZQ==");
        assert_eq!(base64_decode("YW55IGNhcm5hbCBwbGVhc3VyZQ=="), b"any carnal pleasure");
    }
}
