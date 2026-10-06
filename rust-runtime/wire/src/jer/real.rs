//! REAL -- X.697 §8.6. Bare JSON number, or a quoted special value for
//! the three non-finite cases. Mirrors `RealJerHandler`
//! (`runtime/src/JerCodec.cpp`).

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;

pub fn encode(d: f64, out: &mut String) {
    if d.is_nan() {
        out.push_str("\"NaN\"");
        return;
    }
    if d.is_infinite() {
        out.push_str(if d > 0.0 { "\"PLUS-INFINITY\"" } else { "\"MINUS-INFINITY\"" });
        return;
    }
    if d == 0.0 {
        out.push('0');
        return;
    }
    // %.15G-equivalent -- matches asn1c's own REAL JER formatting:
    // 15 significant digits, decimal notation when the decimal exponent
    // is in [-4, 15), exponential (uppercase E) otherwise, trailing
    // mantissa zeros trimmed either way (printf's %G behavior).
    out.push_str(&format_g15(d));
}

fn format_g15(d: f64) -> String {
    const PRECISION: i32 = 15;
    let exp10 = d.abs().log10().floor() as i32;
    if exp10 < -4 || exp10 >= PRECISION {
        // Exponential form: PRECISION-1 digits after the mantissa point,
        // then trim trailing zeros (and a bare trailing '.') like %G.
        let s = format!("{:.*E}", (PRECISION - 1) as usize, d);
        let epos = s.find('E').unwrap();
        let (mantissa, exp) = s.split_at(epos);
        let mantissa = if mantissa.contains('.') {
            mantissa.trim_end_matches('0').trim_end_matches('.')
        } else {
            mantissa
        };
        format!("{mantissa}{exp}")
    } else {
        // Decimal form: PRECISION significant digits total, i.e.
        // (PRECISION - 1 - exp10) digits after the decimal point.
        let decimals = (PRECISION - 1 - exp10).max(0) as usize;
        let s = format!("{d:.decimals$}");
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            s
        }
    }
}

pub fn decode(r: &mut Reader) -> Result<f64, DecodeError> {
    r.skip_ws();
    if r.peek_char() == b'"' {
        let s = r.read_json_string()?;
        return match s.as_str() {
            "NaN" => Ok(f64::NAN),
            "PLUS-INFINITY" => Ok(f64::INFINITY),
            "MINUS-INFINITY" => Ok(f64::NEG_INFINITY),
            other => other
                .parse::<f64>()
                .map_err(|_| DecodeError::new(format!("JER: invalid REAL string: {other}"), r.pos())),
        };
    }
    let tok = r.read_json_token()?;
    tok.parse::<f64>()
        .map_err(|_| DecodeError::new(format!("JER: invalid REAL: {tok}"), r.pos()))
}
