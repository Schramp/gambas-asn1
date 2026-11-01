//! Low-level JSON scanner — hand-rolled recursive-descent, not a full
//! tokenizer (mirrors `JerDecodeStream` + the free functions in
//! `jer_detail::` used by every handler in `runtime/src/JerCodec.cpp`;
//! that file's own `jer_detail::parse` state machine, ported from
//! asn1c's `jer_support.c`, is present there for completeness/future
//! streaming use but its own handlers use these same simpler helpers,
//! so this module doesn't port that tokenizer at all).

use crate::ber::reader::DecodeError;
use crate::nesting::Depth;

/// Cursor over a JSON text buffer. Byte-indexed, like `XerReader` —
/// JER text is always ASCII-safe JSON syntax at the structural level
/// (string *content* may be arbitrary UTF-8/escaped, handled by
/// `read_json_string` below, not by cursor arithmetic).
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    pub(crate) depth: Depth,
    pub(crate) contained: Option<&'a crate::containing::ContainedOptions>,
}

impl<'a> Reader<'a> {
    pub fn new(text: &'a str) -> Self {
        Reader { data: text.as_bytes(), pos: 0, depth: Depth::default(), contained: None }
    }

    /// @brief Set the contained-value settings of this decode (decoder
    ///        registry, `off`).
    pub fn set_contained(&mut self, opts: &'a crate::containing::ContainedOptions) {
        self.contained = Some(opts);
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn peek_byte(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    pub fn skip_ws(&mut self) {
        while let Some(b) = self.peek_byte() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.advance(1);
            } else {
                break;
            }
        }
    }

    /// True when the next value is the JSON literal `null` (RFC 8259 §3),
    /// without consuming it.
    pub fn peek_null(&mut self) -> bool {
        self.skip_ws();
        let rest = &self.data[self.pos..];
        rest.starts_with(b"null")
            && rest.get(4).is_none_or(|&c| matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r'))
    }

    /// Peek the next non-whitespace byte without consuming it. `\0` at end.
    pub fn peek_char(&mut self) -> u8 {
        self.skip_ws();
        self.peek_byte().unwrap_or(0)
    }

    /// Consume a specific byte, skipping leading whitespace first.
    pub fn expect_char(&mut self, expected: u8) -> Result<(), DecodeError> {
        self.skip_ws();
        if self.peek_byte() != Some(expected) {
            return Err(DecodeError::new(format!("JER: expected '{}'", expected as char), self.pos));
        }
        self.advance(1);
        Ok(())
    }

    /// Read a JSON string (cursor must be at the opening `"`). Returns the
    /// unescaped content as an owned `String`: the full RFC 8259 §7 escape
    /// set, which X.697 §23.4 NOTE allows in every JER string, member names
    /// included. An unknown or malformed escape is a decode error. Invalid UTF-8 inside an
    /// escape-free run is rejected by `str::from_utf8` at the final
    /// assembly step (JER text is always real UTF-8 JSON, unlike BER
    /// payload bytes, so this is a real error, not a lossy-by-design path).
    pub fn read_json_string(&mut self) -> Result<String, DecodeError> {
        self.skip_ws();
        if self.peek_byte() != Some(b'"') {
            return Err(DecodeError::new("JER: expected '\"'".to_string(), self.pos));
        }
        self.advance(1);
        let mut out = Vec::new();
        let mut esc = false;
        loop {
            let Some(b) = self.peek_byte() else {
                return Err(DecodeError::new("JER: unterminated string".to_string(), self.pos));
            };
            self.advance(1);
            if esc {
                match b {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => {
                        let ch = self.read_unicode_escape()?;
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                    _ => return Err(DecodeError::new("JER: invalid escape in string".to_string(), self.pos)),
                }
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                return String::from_utf8(out)
                    .map_err(|_| DecodeError::new("JER: invalid UTF-8 in string".to_string(), self.pos));
            } else {
                out.push(b);
            }
        }
    }

    /// Read the code unit(s) of a JSON `\\u` escape (RFC 8259 §7), cursor
    /// just after the `\\u`. A high surrogate must be followed by a
    /// `\\u`-escaped low surrogate; the pair combines into one code point.
    /// A lone surrogate or fewer than four hex digits is a decode error.
    fn read_unicode_escape(&mut self) -> Result<char, DecodeError> {
        let hi = self.read_hex4()?;
        let cp = match hi {
            0xDC00..=0xDFFF => {
                return Err(DecodeError::new("JER: lone low surrogate in \\u escape".to_string(), self.pos));
            }
            0xD800..=0xDBFF => {
                if self.peek_byte() != Some(b'\\') || self.data.get(self.pos + 1) != Some(&b'u') {
                    return Err(DecodeError::new("JER: lone high surrogate in \\u escape".to_string(), self.pos));
                }
                self.advance(2);
                let lo = self.read_hex4()?;
                if !(0xDC00..=0xDFFF).contains(&lo) {
                    return Err(DecodeError::new("JER: lone high surrogate in \\u escape".to_string(), self.pos));
                }
                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
            }
            _ => hi,
        };
        char::from_u32(cp).ok_or_else(|| DecodeError::new("JER: malformed \\u escape".to_string(), self.pos))
    }

    /// Read four hex digits as one UTF-16 code unit.
    fn read_hex4(&mut self) -> Result<u32, DecodeError> {
        let mut cu = 0u32;
        for _ in 0..4 {
            let d = self
                .peek_byte()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or_else(|| DecodeError::new("JER: malformed \\u escape".to_string(), self.pos))?;
            cu = cu << 4 | d;
            self.advance(1);
        }
        Ok(cu)
    }

    /// Read a JSON non-string value (number, boolean, null) as a raw token
    /// — stops at the first comma/brace/bracket/whitespace.
    pub fn read_json_token(&mut self) -> Result<String, DecodeError> {
        self.skip_ws();
        let start = self.pos;
        while let Some(b) = self.peek_byte() {
            if b == b',' || b == b'}' || b == b']' || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                break;
            }
            self.advance(1);
        }
        if self.pos == start {
            return Err(DecodeError::new("JER: expected value token".to_string(), self.pos));
        }
        Ok(String::from_utf8_lossy(&self.data[start..self.pos]).into_owned())
    }

    /// Skip any JSON value (string, number, object, array, literal)
    /// without decoding it — used for unknown SEQUENCE member keys.
    pub fn skip_json_value(&mut self) -> Result<(), DecodeError> {
        self.skip_ws();
        let Some(first) = self.peek_byte() else {
            return Err(DecodeError::new("JER: unexpected end in value".to_string(), self.pos));
        };
        if first == b'"' {
            self.read_json_string()?;
            return Ok(());
        }
        if first == b'{' || first == b'[' {
            let close = if first == b'{' { b'}' } else { b']' };
            let mut depth: i32 = 0;
            let mut in_str = false;
            let mut esc = false;
            loop {
                let Some(b) = self.peek_byte() else {
                    return Err(DecodeError::new("JER: unterminated object/array".to_string(), self.pos));
                };
                self.advance(1);
                if esc {
                    esc = false;
                    continue;
                }
                if b == b'\\' && in_str {
                    esc = true;
                    continue;
                }
                if b == b'"' {
                    in_str = !in_str;
                    continue;
                }
                if !in_str {
                    if b == first {
                        depth += 1;
                    } else if b == close {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(());
                        }
                    }
                }
            }
        }
        // number, true, false, null — must consume something, so a caller
        // looping over skipped values always advances (a stray `}`/`]`/`,`
        // here is malformed input, not an empty value).
        self.read_json_token().map(|_| ())
    }
}
