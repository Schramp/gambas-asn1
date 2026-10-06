//! BIT STRING -- X.697 §8.8.1 (unnamed-bit form). `{"value":"HEX","length":N}`.
//! Mirrors `BitStringJerHandler` (`runtime/src/JerCodec.cpp`). The
//! named-bit array form (`["bit0",...]`) is decode-only-recognized on
//! the C++ side too, and not fully implemented there either (bits are
//! dropped) -- matched here by the same limitation, not silently
//! diverging into "more correct than the reference."

use crate::ber::reader::DecodeError;
use crate::bit_string::BitString;
use crate::jer::reader::Reader;
use crate::jer::writer::{parse_hex_str, to_hex_upper};

pub fn encode(bs: &BitString, out: &mut String) {
    out.push_str("{\"value\":\"");
    to_hex_upper(&bs.bytes, out);
    out.push_str("\",\"length\":");
    out.push_str(&bs.bit_count().to_string());
    out.push('}');
}

pub fn decode(r: &mut Reader) -> Result<BitString, DecodeError> {
    if r.peek_char() == b'[' {
        // Named-bit array form -- consume and discard (no named-bit
        // table available here either; same deferred-support shape as
        // the C++ reference).
        r.expect_char(b'[')?;
        let mut depth = 1usize;
        loop {
            match r.peek_char() {
                b'[' => {
                    r.expect_char(b'[')?;
                    depth += 1;
                }
                b']' => {
                    r.expect_char(b']')?;
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                0 => return Err(DecodeError::new("JER: unterminated named-bit array".to_string(), r.pos())),
                _ => r.skip_json_value()?,
            }
        }
        return Ok(BitString::default());
    }
    r.expect_char(b'{')?;
    let mut hex = String::new();
    let mut length: usize = 0;
    loop {
        match r.peek_char() {
            b'}' => {
                r.expect_char(b'}')?;
                break;
            }
            b',' => {
                r.expect_char(b',')?;
                continue;
            }
            0 => return Err(DecodeError::new("JER: unterminated BIT STRING object".to_string(), r.pos())),
            _ => {
                let key = r.read_json_string()?;
                r.expect_char(b':')?;
                match key.as_str() {
                    "value" => hex = r.read_json_string()?,
                    "length" => {
                        let tok = r.read_json_token()?;
                        length = tok.parse().unwrap_or(0);
                    }
                    _ => r.skip_json_value()?,
                }
            }
        }
    }
    let bytes = parse_hex_str(&hex);
    // `length` is the bit count; `unused_bits` is the padding in the last
    // byte (0 when the bit count is already byte-aligned), matching
    // `BitString`'s own field convention (`bit_string.rs`).
    let unused_bits = if length % 8 == 0 { 0 } else { (8 - (length % 8)) as u8 };
    Ok(BitString { bytes, unused_bits })
}
