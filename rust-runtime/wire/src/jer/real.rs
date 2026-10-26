//! REAL -- X.697 §23. Bare JSON number, or one of Table 2's special-value
//! strings ("-0"/"-INF"/"INF"/"NaN" -- NOT "PLUS-INFINITY"/
//! "MINUS-INFINITY", which is X.693/XER's spelling for a different
//! clause, confirmed against the standard text directly). Mirrors
//! `RealJerHandler` (`runtime/src/JerCodec.cpp`).

use crate::ber::reader::DecodeError;
use crate::jer::reader::Reader;
use crate::constraints::{Constraints, REAL_BASE_10};
use crate::real::{parse_decimal_number, Real};

/// Encodes a JER REAL: a `Decimal` as its exact digits, a bare JSON number
/// when the JER-visible base constraint admits only 10 (X.697 §23.1.4) and
/// `{"base10Value": n}` otherwise (§23.4); any other value as a JSON number
/// or special-value string (§23.2, §23.3). Mirrors `RealJerHandler::encode`.
pub fn encode(v: &Real, c: &Constraints, out: &mut String) {
    if let Some(text) = v.decimal_text() {
        if c.flags & REAL_BASE_10 != 0 {
            out.push_str(&text);
        } else {
            out.push_str("{\"base10Value\":");
            out.push_str(&text);
            out.push('}');
        }
        return;
    }
    let d = v.value();
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
/// (§23.2), or the object `{"base10Value": number}` (§23.4), which gives an
/// exact `Decimal`. A number gives a `Double`, or a `Decimal` when the base
/// constraint admits only 10 (§23.1.4). Mirrors `RealJerHandler::decode`
/// (`runtime/src/JerCodec.cpp`).
pub fn decode(r: &mut Reader, c: &Constraints) -> Result<Real, DecodeError> {
    r.skip_ws();
    if r.peek_char() == b'{' {
        r.expect_char(b'{')?;
        let key = r.read_json_string()?;
        if key != "base10Value" {
            return Err(DecodeError::new(format!("JER: unexpected REAL object member: {key}"), r.pos()));
        }
        r.expect_char(b':')?;
        let tok = r.read_json_token()?;
        let v = parse_decimal_number(&tok)
            .ok_or_else(|| DecodeError::new(format!("JER: invalid REAL base10Value: {tok}"), r.pos()))?;
        r.expect_char(b'}')?;
        return Ok(v);
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
        }
        .map(Real::new);
    }
    let tok = r.read_json_token()?;
    if c.flags & REAL_BASE_10 != 0 {
        return parse_decimal_number(&tok).ok_or_else(|| DecodeError::new(format!("JER: invalid REAL: {tok}"), r.pos()));
    }
    tok.parse::<f64>()
        .map(Real::new)
        .map_err(|_| DecodeError::new(format!("JER: invalid REAL: {tok}"), r.pos()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::UNCONSTRAINED;

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
            encode(&Real::new(d), &UNCONSTRAINED, &mut out);
            assert_eq!(out, want, "encoding {d:?}");
            let mut r = Reader::new(&out);
            assert_eq!(decode(&mut r, &UNCONSTRAINED).unwrap().to_bits(), d.to_bits(), "round trip of {want}");
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
            let got = decode(&mut r, &UNCONSTRAINED).ok();
            assert_eq!(got.as_ref().map(Real::value), want, "{json}");
            if let Some(v) = got {
                assert_eq!(v.storage(), crate::real::Storage::Decimal, "{json}");
            }
        }
    }

    /// Shared with the C++ `test_jer_basic` Decimal checks.
    #[test]
    fn decimal_is_exact_through_ber_and_jer() {
        let pi = Real::decimal(false, "3141592653589793238462643383279", -30);
        let mut out = String::new();
        encode(&pi, &UNCONSTRAINED, &mut out);
        assert_eq!(out, "{\"base10Value\":3141592653589793238462643383279E-30}");
        assert_eq!(decode(&mut Reader::new(&out), &UNCONSTRAINED).unwrap(), pi);

        let ber_in = crate::real::decode_real_value(b"\x0214.56", 0).unwrap();
        let mut json = String::new();
        encode(&ber_in, &UNCONSTRAINED, &mut json);
        let via_jer = decode(&mut Reader::new(&json), &UNCONSTRAINED).unwrap();
        let mut content = Vec::new();
        crate::real::encode_real_content(&mut content, &via_jer);
        assert_eq!(content, b"\x031456.E-2");

        let mut xer = String::new();
        crate::xer::real::encode(&via_jer, &mut xer);
        assert_eq!(xer, "1456E-2");
    }

    /// Shared with the C++ `test_jer_basic` base-constraint checks.
    #[test]
    fn base_10_only_constraint_uses_a_bare_number() {
        let c = Constraints { flags: REAL_BASE_10, ..UNCONSTRAINED };
        let v = Real::decimal(false, "1456", -2);
        let mut out = String::new();
        encode(&v, &c, &mut out);
        assert_eq!(out, "1456E-2");
        let back = decode(&mut Reader::new("14.56"), &c).unwrap();
        assert_eq!(back, v);
        let mut base2 = String::new();
        encode(&Real::new(14.5), &c, &mut base2);
        assert_eq!(base2, "14.5", "a base-2 value is a JSON number either way (§23.1.2)");
        assert_eq!(decode(&mut Reader::new("14.56"), &UNCONSTRAINED).unwrap().storage(), crate::real::Storage::Double);
    }

    #[test]
    fn special_values_keep_their_strings() {
        for (d, want) in [(f64::NAN, "\"NaN\""), (f64::INFINITY, "\"INF\""), (f64::NEG_INFINITY, "\"-INF\""), (-0.0, "\"-0\""), (0.0, "0")] {
            let mut out = String::new();
            encode(&Real::new(d), &UNCONSTRAINED, &mut out);
            assert_eq!(out, want);
        }
    }
}
