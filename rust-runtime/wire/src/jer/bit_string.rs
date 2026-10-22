//! BIT STRING -- X.697 §8.8.1 (unnamed-bit form): a bare `"HEX"` string
//! when the effective SIZE is fixed (single value, not extensible), else
//! `{"value":"HEX","length":N}`.
//! Mirrors `BitStringJerHandler` (`runtime/src/JerCodec.cpp`). The
//! named-bit array form (`["bit0",...]`) is decode-only-recognized on
//! the C++ side too, and not fully implemented there either (bits are
//! dropped) -- matched here by the same limitation, not silently
//! diverging into "more correct than the reference."

use crate::ber::reader::DecodeError;
use crate::bit_string::BitString;
use crate::constraints::Constraints;
use crate::jer::reader::Reader;
use crate::jer::writer::{parse_hex_str, to_hex_upper};

/// @brief The fixed bit count of a BIT STRING whose effective SIZE is a
///        single, non-extensible value, which X.697 writes as a bare hex
///        string; `None` for every other BIT STRING. Mirrors the C++
///        `BitStringJerHandler::fixed_size`.
fn fixed_size(c: &Constraints) -> Option<usize> {
    if c.flags & Constraints::SIZE_CONSTRAINED == 0 || c.flags & Constraints::EXTENSIBLE != 0 {
        return None;
    }
    (c.size_lower == c.size_upper && c.size_lower >= 0).then_some(c.size_lower as usize)
}

/// @brief Writes a BIT STRING's JER form.
/// @param c  Its own constraints. A value whose length breaks a fixed
///           size keeps the object form, so the length is not lost.
pub fn encode(bs: &BitString, c: &Constraints, out: &mut String) {
    if fixed_size(c) == Some(bs.bit_count()) {
        out.push('"');
        to_hex_upper(&bs.bytes, out);
        out.push('"');
        return;
    }
    out.push_str("{\"value\":\"");
    to_hex_upper(&bs.bytes, out);
    out.push_str("\",\"length\":");
    out.push_str(&bs.bit_count().to_string());
    out.push('}');
}

/// @brief Reads a BIT STRING in either JER form.
/// @param c  Its own constraints; the bare-string form is accepted only
///           for a fixed size, which also gives its length.
pub fn decode(c: &Constraints, r: &mut Reader) -> Result<BitString, DecodeError> {
    if r.peek_char() == b'"' {
        let Some(n) = fixed_size(c) else {
            return Err(DecodeError::new("JER: BIT STRING is not fixed-size; expected {\"value\",\"length\"}".to_string(), r.pos()));
        };
        let mut bytes = parse_hex_str(&r.read_json_string()?);
        if bytes.len() != n.div_ceil(8) {
            return Err(DecodeError::new(format!("JER: fixed-size BIT STRING: expected {} hex octets", n.div_ceil(8)), r.pos()));
        }
        let unused_bits = (n.div_ceil(8) * 8 - n) as u8;
        if let Some(last) = bytes.last_mut() {
            *last &= 0xFFu8 << unused_bits;
        }
        return Ok(BitString { bytes, unused_bits });
    }
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

#[cfg(test)]
mod malformed_tests {
    use super::*;

    #[test]
    fn malformed_named_bit_array_is_an_error_not_a_hang() {
        let mut r = Reader::new(r#"["value":"5599","length":16}"#);
        assert!(decode(&crate::constraints::UNCONSTRAINED, &mut r).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::UNCONSTRAINED;

    const FIXED20: Constraints = Constraints { flags: Constraints::SIZE_CONSTRAINED, size_lower: 20, size_upper: 20, ..UNCONSTRAINED };
    const FIXED20_EXT: Constraints = Constraints { flags: Constraints::SIZE_CONSTRAINED | Constraints::EXTENSIBLE, size_lower: 20, size_upper: 20, ..UNCONSTRAINED };

    fn bits20() -> BitString {
        BitString { bytes: vec![0x2E, 0xFE, 0x20].into(), unused_bits: 4 }
    }

    fn enc(bs: &BitString, c: &Constraints) -> String {
        let mut out = String::new();
        encode(bs, c, &mut out);
        out
    }

    #[test]
    fn fixed_size_is_a_bare_hex_string_and_round_trips() {
        let s = enc(&bits20(), &FIXED20);
        assert_eq!(s, "\"2EFE20\"");
        assert_eq!(decode(&FIXED20, &mut Reader::new(&s)).unwrap(), bits20());
    }

    #[test]
    fn other_sizes_keep_the_object_form() {
        assert_eq!(enc(&bits20(), &FIXED20_EXT), "{\"value\":\"2EFE20\",\"length\":20}");
        assert_eq!(enc(&bits20(), &UNCONSTRAINED), "{\"value\":\"2EFE20\",\"length\":20}");
        let short = BitString { bytes: vec![0xF0].into(), unused_bits: 4 };
        assert_eq!(enc(&short, &FIXED20), "{\"value\":\"F0\",\"length\":4}");
        assert_eq!(decode(&FIXED20, &mut Reader::new("{\"value\":\"2EFE20\",\"length\":20}")).unwrap(), bits20());
    }

    #[test]
    fn bare_string_needs_a_fixed_size_of_the_right_length() {
        assert!(decode(&UNCONSTRAINED, &mut Reader::new("\"2EFE20\"")).is_err());
        assert!(decode(&FIXED20, &mut Reader::new("\"2EFE\"")).is_err());
    }
}
