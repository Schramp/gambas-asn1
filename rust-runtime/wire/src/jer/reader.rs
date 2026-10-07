//! Low-level JSON scanner — hand-rolled recursive-descent, not a full
//! tokenizer (mirrors `JerDecodeStream` + the free functions in
//! `jer_detail::` used by every handler in `runtime/src/JerCodec.cpp`;
//! that file's own `jer_detail::parse` state machine, ported from
//! asn1c's `jer_support.c`, is present there for completeness/future
//! streaming use but its own handlers use these same simpler helpers,
//! so this module doesn't port that tokenizer at all).

use crate::ber::reader::DecodeError;

/// Cursor over a JSON text buffer. Byte-indexed, like `XerReader` —
/// JER text is always ASCII-safe JSON syntax at the structural level
/// (string *content* may be arbitrary UTF-8/escaped, handled by
/// `read_json_string` below, not by cursor arithmetic).
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(text: &'a str) -> Self {
        Reader { data: text.as_bytes(), pos: 0 }
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
    /// unescaped content as an owned `String` — invalid UTF-8 inside an
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
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    other => out.push(other),
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
        // number, true, false, null
        while let Some(b) = self.peek_byte() {
            if b == b',' || b == b'}' || b == b']' || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                break;
            }
            self.advance(1);
        }
        Ok(())
    }
}
