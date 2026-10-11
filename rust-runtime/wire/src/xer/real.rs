//! XER REAL encode/decode — X.693 §17.9. Tag-walking glue only; the
//! actual decimal/special-value text lives in `real::format_xer`/
//! `parse_xer_special`/`parse_xer_decimal` (see `real.rs`'s own doc for
//! why it's kept there, next to `jer::real`'s formatter, rather than
//! here).

use crate::ber::reader::DecodeError;
use crate::real::{format_xer, parse_xer_decimal, parse_xer_special, XerRealText};
use crate::xer::reader::XerReader;

pub fn encode(d: f64, out: &mut String) {
    match format_xer(d) {
        XerRealText::Special(name) => {
            out.push('<');
            out.push_str(name);
            out.push_str("/>");
        }
        XerRealText::Decimal(text) => out.push_str(&text),
    }
}

pub fn decode(r: &mut XerReader) -> Result<f64, DecodeError> {
    let peek = r.peek_tag();
    if !peek.name.is_empty() {
        let ti = r.consume_tag();
        let d = parse_xer_special(&ti.name)
            .ok_or_else(|| DecodeError::new(format!("XER: unknown REAL special value: {}", ti.name), 0))?;
        if !ti.self_closing {
            let close = r.consume_tag();
            if !close.closing || close.name != ti.name {
                return Err(DecodeError::new("XER: malformed REAL special value".to_string(), 0));
            }
        }
        return Ok(d);
    }
    let text = r.read_text_content();
    parse_xer_decimal(&text).map_err(|e| DecodeError::new(e, 0))
}
