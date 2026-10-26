//! REAL -- X.697 §23. Bare JSON number, or one of Table 2's special-value
//! strings ("-0"/"-INF"/"INF"/"NaN" -- NOT "PLUS-INFINITY"/
//! "MINUS-INFINITY", which is X.693/XER's spelling for a different
//! clause, confirmed against the standard text directly). Mirrors
//! `RealJerHandler` (`runtime/src/JerCodec.cpp`).

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;

pub fn encode(d: f64, out: &mut String) {
    if d.is_nan() {
        out.push_str("\"NaN\"");
        return;
    }
    if d.is_infinite() {
        out.push_str(if d > 0.0 { "\"INF\"" } else { "\"-INF\"" });
        return;
    }
    if d == 0.0 {
        // X.697 §23.1.1/23.2: -0.0 (distinct from +0.0 -- `==` can't
        // tell them apart, hence is_sign_negative) encodes as the
        // special string "-0", not the bare number 0.
        out.push_str(if d.is_sign_negative() { "\"-0\"" } else { "0" });
        return;
    }
    out.push_str(&format_real(d));
}

/// @brief Formats a finite, nonzero REAL as a JSON number that converts
///        back to exactly the same `f64`: the shortest such digit string
///        (`{:e}`), in plain decimal notation when the decimal exponent is
///        in [-4, 15) and as `d.dddE<exp>` otherwise. Mirrors the C++
///        `jer_detail::format_real` (`runtime/src/JerCodec.cpp`) exactly, so
///        both runtimes produce identical text.
/// @see X.697 §23 (REAL as a JSON number).
fn format_real(d: f64) -> String {
    let sci = format!("{:e}", d.abs()); // e.g. 1.9370032316011307e5
    let (mantissa, exp) = sci.split_once('e').expect("{:e} always has an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exp: i32 = exp.parse().expect("{:e} exponent is an integer");
    let mut out = String::new();
    if d < 0.0 {
        out.push('-');
    }
    if (-4..15).contains(&exp) {
        if exp < 0 {
            out.push_str("0.");
            out.extend(std::iter::repeat('0').take((-exp - 1) as usize));
            out.push_str(&digits);
        } else {
            let int_len = exp as usize + 1;
            if digits.len() <= int_len {
                out.push_str(&digits);
                out.extend(std::iter::repeat('0').take(int_len - digits.len()));
            } else {
                out.push_str(&digits[..int_len]);
                out.push('.');
                out.push_str(&digits[int_len..]);
            }
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('E');
        out.push_str(&exp.to_string());
    }
    out
}

/// Decodes a JER REAL: a JSON number (X.697 §23.3), a special-value string
/// (§23.2), or the object `{"base10Value": number}` (§23.4). Mirrors
/// `RealJerHandler::decode` (`runtime/src/JerCodec.cpp`).
pub fn decode(r: &mut Reader) -> Result<f64, DecodeError> {
    r.skip_ws();
    if r.peek_char() == b'{' {
        r.expect_char(b'{')?;
        let key = r.read_json_string()?;
        if key != "base10Value" {
            return Err(DecodeError::new(format!("JER: unexpected REAL object member: {key}"), r.pos()));
        }
        r.expect_char(b':')?;
        let tok = r.read_json_token()?;
        let d = tok
            .parse::<f64>()
            .map_err(|_| DecodeError::new(format!("JER: invalid REAL base10Value: {tok}"), r.pos()))?;
        r.expect_char(b'}')?;
        return Ok(d);
    }
    if r.peek_char() == b'"' {
        let s = r.read_json_string()?;
        return match s.as_str() {
            "NaN" => Ok(f64::NAN),
            "INF" => Ok(f64::INFINITY),
            "-INF" => Ok(f64::NEG_INFINITY),
            "-0" => Ok(-0.0),
            other => other
                .parse::<f64>()
                .map_err(|_| DecodeError::new(format!("JER: invalid REAL string: {other}"), r.pos())),
        };
    }
    let tok = r.read_json_token()?;
    tok.parse::<f64>()
        .map_err(|_| DecodeError::new(format!("JER: invalid REAL: {tok}"), r.pos()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared with the C++ `test_jer_real_format` table: both runtimes
    /// must write exactly these strings.
    const CASES: &[(f64, &str)] = &[
        (-338203.95104146993, "-338203.95104146993"),
        (0.1, "0.1"),
        (1e-5, "1E-5"),
        (0.0001, "0.0001"),
        (123456789012345.6, "123456789012345.6"),
        (1e15, "1E15"),
        (1.7976931348623157e308, "1.7976931348623157E308"),
        (5e-324, "5E-324"),
        (2.0, "2"),
        (100.0, "100"),
        (-2.251799813685248e15, "-2.251799813685248E15"),
        (3.141592653589793, "3.141592653589793"),
        (1234567.0, "1234567"),
        (0.000123456, "0.000123456"),
    ];

    #[test]
    fn reals_encode_to_the_shortest_round_trip_text() {
        for &(d, want) in CASES {
            let mut out = String::new();
            encode(d, &mut out);
            assert_eq!(out, want, "encoding {d:?}");
            let mut r = Reader::new(&out);
            assert_eq!(decode(&mut r).unwrap().to_bits(), d.to_bits(), "round trip of {want}");
        }
    }

    /// Shared with the C++ `test_jer_basic` base10Value cases.
    #[test]
    fn base10_value_object_decodes() {
        let cases: &[(&str, Option<f64>)] = &[
            ("{ \"base10Value\" : 14 }", Some(14.0)), // X.697 §23.4 example
            ("{\"base10Value\":14.56}", Some(14.56)),
            ("{\"base10Value\":-1.5E3}", Some(-1500.0)),
            ("{\"base10Value\":\"14\"}", None),
            ("{\"base2Value\":14}", None),
            ("{\"base10Value\":14,\"x\":1}", None),
            ("{}", None),
        ];
        for &(json, want) in cases {
            let mut r = Reader::new(json);
            assert_eq!(decode(&mut r).ok(), want, "{json}");
        }
    }

    #[test]
    fn special_values_keep_their_strings() {
        for (d, want) in [(f64::NAN, "\"NaN\""), (f64::INFINITY, "\"INF\""), (f64::NEG_INFINITY, "\"-INF\""), (-0.0, "\"-0\""), (0.0, "0")] {
            let mut out = String::new();
            encode(d, &mut out);
            assert_eq!(out, want);
        }
    }
}
