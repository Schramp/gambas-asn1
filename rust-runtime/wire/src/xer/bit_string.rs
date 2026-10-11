//! XER BIT STRING encode/decode — X.680 §21's XMLBitStringValue grammar.
//! Mirrors `BitStringXerHandler`'s content model (`runtime/src/
//! XerCodec.cpp`): a string of '0'/'1' characters, one per bit, MSB
//! first within each byte. C++'s writer additionally pretty-prints this
//! across indented 64-character lines, which is cosmetic only (its own
//! decoder skips whitespace), so this impl emits the same bit sequence
//! unspaced, on one line, and accepts (skips) any whitespace on decode.
//! Decode also accepts the non-standard lenient hex-pairs form
//! (`BitStringXerHandler::decode`) when `XerReader::lenient()` is set —
//! a pure `0`/`1` string is decoded as binary either way
//! (indistinguishable from hex, matches the C++ heuristic); any
//! `2`-`9`/`A`-`F`/`a`-`f` character makes it unambiguous and requires
//! lenient mode.

use crate::bit_string::BitString;
use crate::ber::reader::DecodeError;
use crate::xer::reader::XerReader;

/// Unlike every other primitive, BIT STRING genuinely consults `depth`:
/// `BitStringXerHandler` always writes its own content starting on a
/// fresh line, wrapped at 64 bits per line, each line at `depth + 1` —
/// the same "children one level deeper than my own position" convention
/// every composite in this crate uses (`encode_sequence_xer_content`'s
/// own doc, `xer.rs`), even though BIT STRING is otherwise a plain
/// primitive. An empty value still gets exactly one (blank) line —
/// `BitStringXerHandler`'s own `total == 0` branch writes
/// `s.indent(1) << "\n"` unconditionally, never an empty `<name></name>`.
/// Ends with a trailing `\n` + `indent(depth)`, same reason every other
/// composite content ends that way (positions the cursor for the
/// caller's own closing tag).
pub fn encode(value: &BitString, out: &mut String, depth: usize) {
    let total = value.bit_count();
    if total == 0 {
        out.push('\n');
        out.push_str(&crate::xer::writer::indent(depth + 1));
    } else {
        let mut i = 0;
        while i < total {
            out.push('\n');
            out.push_str(&crate::xer::writer::indent(depth + 1));
            let line_end = (i + 64).min(total);
            while i < line_end {
                let bit = (value.bytes[i / 8] >> (7 - (i % 8))) & 1;
                out.push(if bit == 1 { '1' } else { '0' });
                i += 1;
            }
        }
    }
    out.push('\n');
    out.push_str(&crate::xer::writer::indent(depth));
}

pub fn decode_into(value: &mut BitString, r: &mut XerReader) -> Result<(), DecodeError> {
    let text = r.read_text_content();
    let mut content = String::with_capacity(text.len());
    let mut has_hex = false;
    for c in text.chars() {
        if c.is_whitespace() {
            continue;
        }
        match c {
            '0' | '1' => {}
            _ if c.is_ascii_hexdigit() => has_hex = true,
            _ => return Err(DecodeError::new(format!("XER: invalid BIT STRING character '{c}'"), 0)),
        }
        content.push(c);
    }
    if has_hex && !r.lenient() {
        return Err(DecodeError::new(
            "XER: hex BIT STRING requires lenient mode (non-standard extension)".to_string(),
            0,
        ));
    }
    if has_hex {
        // Non-standard asn1c extension: hex pairs, one byte each, 0
        // unused bits (no production for this in X.680 §21's
        // XMLBitStringValue grammar).
        if content.len() % 2 != 0 {
            return Err(DecodeError::new("XER: odd-length hex BIT STRING".to_string(), 0));
        }
        let cbytes = content.as_bytes();
        let mut bytes = Vec::with_capacity(cbytes.len() / 2);
        let mut i = 0;
        while i < cbytes.len() {
            let hi = (cbytes[i] as char).to_digit(16).unwrap() as u8;
            let lo = (cbytes[i + 1] as char).to_digit(16).unwrap() as u8;
            bytes.push((hi << 4) | lo);
            i += 2;
        }
        *value = BitString { bytes, unused_bits: 0 };
        return Ok(());
    }
    let mut bytes = Vec::new();
    let mut cur = 0u8;
    let mut bit_count = 0usize;
    for c in content.chars() {
        let bit = if c == '1' { 1u8 } else { 0u8 };
        cur = (cur << 1) | bit;
        bit_count += 1;
        if bit_count % 8 == 0 {
            bytes.push(cur);
            cur = 0;
        }
    }
    let unused_bits = if bit_count % 8 == 0 {
        0
    } else {
        let pad = 8 - (bit_count % 8);
        cur <<= pad;
        bytes.push(cur);
        pad as u8
    };
    *value = BitString { bytes, unused_bits };
    Ok(())
}
