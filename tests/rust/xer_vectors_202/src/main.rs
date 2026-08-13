// XER vector test: asn1c data-202 (202-XIOTCertificate-OK.asn1), Rust
// codegen leg — port of tests/seq/test_xer_vectors_202.cpp.
//
// Decodes s1.xer (a minimal X.509-style certificate) and verifies field
// values. s1.xer uses asn1c's non-standard XER extensions — hex BIT STRING
// and text BOOLEAN — auto-detected/accepted only in lenient mode
// (XerReader::new_lenient). No round-trip comparison: the encoder always
// uses binary BIT STRING format, not hex.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn main() {
    let datadir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/tests-c-compiler/data-202".to_string());

    println!("\n\u{2500}\u{2500} XER vectors: data-202 (202-XIOTCertificate-OK.asn1, Rust) \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");

    let mut failures = 0;

    let xer_path = format!("{datadir}/s1.xer");
    let xml = std::fs::read_to_string(&xer_path).unwrap_or_else(|e| panic!("failed to read {xer_path}: {e}"));

    let cert = asn1cpp_ber::xer::decode_sequence_xer_lenient(&certificate::CERTIFICATE_SPEC, &xml);
    check("s1.xer  XER decode ok", cert.is_ok(), &mut failures);
    let cert = match cert {
        Ok(c) => c,
        Err(e) => {
            println!("  error: {} at {}", e.message, e.pos);
            std::process::exit(1);
        }
    };

    let tbs = &cert.tbs_certificate;

    // version = 2 (named value v3(2))
    check("s1.xer  version == 2", tbs.version == 2, &mut failures);

    // signature BIT STRING: hex "3045..." = 69 bytes
    check("s1.xer  signature bit size == 69 bytes", cert.signature.bytes.len() == 69, &mut failures);
    check("s1.xer  signature unused bits == 0", cert.signature.unused_bits == 0, &mut failures);

    // subjectPublicKey BIT STRING: hex "04AA..." = 32 bytes
    check(
        "s1.xer  subjectPublicKey byte size == 32",
        tbs.subject_public_key_info.subject_public_key.bytes.len() == 32,
        &mut failures,
    );

    // issuer: SEQUENCE SIZE(1) OF DistinguishedName, each SET SIZE(1) OF CommonName
    check("s1.xer  issuer has 1 DistinguishedName", tbs.issuer.0.len() == 1, &mut failures);
    if !tbs.issuer.0.is_empty() {
        check("s1.xer  issuer[0] has 1 CommonName", tbs.issuer.0[0].0.len() == 1, &mut failures);
        if !tbs.issuer.0[0].0.is_empty() {
            let cn = &tbs.issuer.0[0].0[0];
            check("s1.xer  issuer CommonName == \"XIOT Root CA\"", cn.value.0 == "XIOT Root CA", &mut failures);
        }
    }

    // extensions: OPTIONAL, present with 1 extension
    check("s1.xer  extensions present", tbs.extensions.is_some(), &mut failures);
    if let Some(extensions) = &tbs.extensions {
        check("s1.xer  extensions has 1 entry", extensions.0.len() == 1, &mut failures);
        if let Some(ext) = extensions.0.first() {
            // critical DEFAULT FALSE but s1.xer sets it to true
            check("s1.xer  extension critical present", ext.critical.is_some(), &mut failures);
            if let Some(critical) = ext.critical {
                check("s1.xer  extension critical == true", critical, &mut failures);
            }
            // extnValue OCTET STRING: hex "30030101FF" = 5 bytes
            check("s1.xer  extnValue byte size == 5", ext.extn_value.len() == 5, &mut failures);
        }
    }

    // BER round-trip
    let ber = cert.encode();
    check("s1.xer  BER encode non-empty", !ber.is_empty(), &mut failures);

    if !ber.is_empty() {
        let cert2 = certificate::Certificate::decode(&ber);
        check("s1.xer  BER decode ok", cert2.is_ok(), &mut failures);
        if let Ok(cert2) = cert2 {
            check("s1.xer  BER round-trip version", cert2.tbs_certificate.version == 2, &mut failures);
            check("s1.xer  BER round-trip signature size", cert2.signature.bytes.len() == 69, &mut failures);
        }
    }

    println!("\n  {failures} failure(s).");
    if failures != 0 {
        std::process::exit(1);
    }
    println!("  All tests passed.");
}
