//! XER BOOLEAN encode/decode — X.693 §8.2. Mirrors `BooleanXerHandler`
//! (`runtime/src/XerCodec.cpp`): BASIC-XER's `EmptyElementBoolean` form,
//! a nested self-closing `<true/>`/`<false/>` tag, not text content.
//! Also accepts EXTENDED-XER §10 TextBoolean (plain `"true"`/`"false"`
//! content) when `XerReader::lenient()` is set — the non-standard asn1c
//! extension `XerDecodeMode::Lenient` allows on the C++ side.

use crate::ber::reader::DecodeError;
use crate::xer::reader::XerReader;

pub fn encode(value: bool, out: &mut String) {
    out.push_str(if value { "<true/>" } else { "<false/>" });
}

pub fn decode(r: &mut XerReader) -> Result<bool, DecodeError> {
    // Detect EXTENDED-XER TextBoolean first: the standard empty-element
    // form (`<true/>`/`<false/>`) has no text content (the reader sits
    // directly on `<`), so an empty result falls through to the tag path
    // unchanged.
    let text = r.read_text_content().trim();
    if !text.is_empty() {
        if !r.lenient() {
            return Err(DecodeError::new("XER BOOLEAN: expected <true/> or <false/>".to_string(), 0));
        }
        return match text {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(DecodeError::new("XER BOOLEAN: expected true or false".to_string(), 0)),
        };
    }
    let ti = r.consume_tag();
    if ti.self_closing && ti.name == "true" {
        Ok(true)
    } else if ti.self_closing && ti.name == "false" {
        Ok(false)
    } else {
        Err(DecodeError::new("XER BOOLEAN: expected <true/> or <false/>".to_string(), 0))
    }
}
