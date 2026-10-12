//! X.697 §8.19: the JSON literal `null` — no SEQUENCE-OF-element special
//! case the way `xer::null` needs (JER represents array structure
//! natively, so there's no XML self-closing-tag quirk to carry).

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;

pub fn encode(out: &mut String) {
    out.push_str("null");
}

pub fn decode(r: &mut Reader<'_>) -> Result<(), DecodeError> {
    let tok = r.read_json_token()?;
    if tok != "null" {
        return Err(DecodeError::new(format!("JER: expected null, got: {tok}"), r.pos()));
    }
    Ok(())
}
