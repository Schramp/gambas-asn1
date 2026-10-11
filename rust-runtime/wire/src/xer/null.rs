//! XER NULL encode/decode — X.680 §23, X.693 §19. A member-embedded NULL
//! writes/reads nothing at all (content lives inside the member's own
//! `<name></name>` wrapper, same as every other primitive's plain
//! `xer_encode`/`xer_decode_into`). A NULL *SEQUENCE OF/SET OF element*
//! is different: X.693 has no per-element identifier to wrap it in (a
//! SEQUENCE OF/SET OF element is always its own natural tag, repeated —
//! X.690 §8.9.2's XER analogue), so it self-closes as `<NULL/>`
//! unconditionally, ignoring any declared X.693 §12 identifier — mirrors
//! `NullXerHandler` self-closing exactly when asked to write under the
//! literal name `"NULL"`.

use crate::ber::reader::DecodeError;
use crate::xer::reader::XerReader;

pub fn encode_seqof_element(out: &mut String, depth: usize) {
    out.push('\n');
    out.push_str(&crate::xer::writer::indent(depth + 1));
    out.push_str("<NULL/>");
}

pub fn decode_seqof_element(r: &mut XerReader) -> Result<(), DecodeError> {
    let ti = r.consume_tag();
    if ti.name != "NULL" || ti.closing {
        return Err(DecodeError::new("XER: expected <NULL>".to_string(), 0));
    }
    if !ti.self_closing {
        let close = r.consume_tag();
        if !close.closing || close.name != "NULL" {
            return Err(DecodeError::new("XER: expected </NULL>".to_string(), 0));
        }
    }
    Ok(())
}
