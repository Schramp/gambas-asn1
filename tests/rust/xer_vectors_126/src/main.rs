// XER-UPER vector test: asn1c data-126 test suite (schema
// 126-per-extensions-OK.asn1), Rust codegen leg — port of
// tests/seq/test_xer_vectors_126.cpp.
//
// Mirrors the original check-126.-gen-UPER.c logic (same as the C++ leg):
//   Each .in file is XER-decoded, UPER-encoded, then:
//   - (none): binary must equal .out; UPER-decoded+XER re-encoded must equal .in.
//   - -C: binary may differ from .out; .out decodes ok; round-trip XER == .in.
//   - -P: UPER decode of .out must fail; our own round-trip must succeed.
//   - -X: binary must equal .out; round-trip XER must differ from .in.
//
// KNOWN_PERMISSIVE: files whose .out was generated with an older schema
// version (fewer extension members). Our decoder accepts them (reads only
// as many extension members as the wire says, treating missing known
// members as absent). asn1c rejects them. This is correct
// forward-compatible decoder behavior — same rationale as the C++ leg's
// own KNOWN_PERMISSIVE.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::value::Asn1Value;
use asn1cpp_wire::per::reader::Reader;
use asn1cpp_wire::per::writer::Writer;
use asn1cpp_wire::constraints::UNCONSTRAINED;
use asn1cpp_wire::xer::{decode_sequence_xer, encode_sequence_xer};
use std::fs;
use std::path::{Path, PathBuf};

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

#[derive(PartialEq)]
enum Kind { Ok, P, C, X }

// -P files whose .out was encoded with an older schema version; our
// permissive decoder accepts them rather than failing. Assertion: decode
// SUCCEEDS (not fails). Mirrors the C++ leg's own KNOWN_PERMISSIVE exactly.
const KNOWN_PERMISSIVE: &[&str] = &["data-126-04-P.in"];

fn classify(name: &str) -> Kind {
    let Some(dot) = name.rfind('.') else { return Kind::Ok };
    if dot == 0 {
        return Kind::Ok;
    }
    match name.as_bytes()[dot - 1] {
        b'P' => Kind::P,
        b'C' => Kind::C,
        b'X' => Kind::X,
        _ => Kind::Ok,
    }
}

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn per_encode(val: &pdu::PDU) -> Vec<u8> {
    let mut w = Writer::new();
    val.per_encode(&mut w, &UNCONSTRAINED);
    w.flush();
    w.into_bytes()
}

fn per_decode(bytes: &[u8]) -> bool {
    let mut r = Reader::new(bytes);
    let mut val = pdu::PDU::default();
    val.per_decode_into(&mut r, &UNCONSTRAINED).is_ok()
}

/// Returns local failure count. Wrapped in catch_unwind by the caller so one
/// genuine gap doesn't take down the whole sweep.
fn process_inner(path: &Path, name: &str) -> i32 {
    let mut failures = 0;
    let kind = classify(name);

    let out_path = path.with_extension("out");
    let input = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let out_bytes = fs::read(&out_path).unwrap_or_else(|e| panic!("failed to read {}: {e}", out_path.display()));

    // 1. XER decode .in
    let decoded = decode_sequence_xer(&pdu::PDU_SPEC, &input);
    check(&format!("{name}  XER decode ok"), decoded.is_ok(), &mut failures);
    let Ok(val) = decoded else { return failures };

    // 2. UPER encode
    let our_bytes = per_encode(&val);
    check(&format!("{name}  UPER encode non-empty"), !our_bytes.is_empty(), &mut failures);
    if our_bytes.is_empty() {
        return failures;
    }

    // 3. Binary comparison vs .out
    if kind == Kind::Ok || kind == Kind::X {
        check(&format!("{name}  UPER bytes == .out"), our_bytes == out_bytes, &mut failures);
    } else if kind == Kind::C {
        check(&format!("{name}  UPER bytes diverge from .out (expected)"), our_bytes != out_bytes, &mut failures);
    }
    // -P: skip binary comparison; .out is intentionally invalid.

    // 4. Decode .out: for -P must fail (unless known-permissive); for -C must succeed.
    if kind == Kind::P {
        let out_dec = per_decode(&out_bytes);
        let known = KNOWN_PERMISSIVE.contains(&name);
        if known {
            check(&format!("{name}  UPER decode of .out succeeds (known-permissive: old encoding)"), out_dec, &mut failures);
        } else {
            check(&format!("{name}  UPER decode of .out fails (as expected)"), !out_dec, &mut failures);
        }
    } else if kind == Kind::C {
        check(&format!("{name}  UPER decode of .out succeeds"), per_decode(&out_bytes), &mut failures);
    }

    // 5. Round-trip: UPER decode our own bytes -> XER re-encode -> compare to .in
    let mut val2 = pdu::PDU::default();
    let rt_ok = {
        let mut r = Reader::new(&our_bytes);
        val2.per_decode_into(&mut r, &UNCONSTRAINED).is_ok()
    };
    check(&format!("{name}  UPER round-trip decode ok"), rt_ok, &mut failures);
    if !rt_ok {
        return failures;
    }

    let reenc = encode_sequence_xer(&pdu::PDU_SPEC, &val2);
    if kind == Kind::X {
        check(&format!("{name}  XER re-encode differs from .in (expected)"), strip_ws(&reenc) != strip_ws(&input), &mut failures);
    } else {
        check(&format!("{name}  XER round-trip equals .in"), strip_ws(&reenc) == strip_ws(&input), &mut failures);
    }

    failures
}

fn process(path: &Path, failures: &mut i32) {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| process_inner(path, &name)));
    match result {
        Ok(local_failures) => *failures += local_failures,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("panic");
            println!("  \x1b[31mFAIL\x1b[0m  {name}  panicked: {msg}");
            *failures += 1;
        }
    }
}

fn main() {
    let datadir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/tests-c-compiler/data-126".to_string());

    println!("\n\u{2500}\u{2500} XER\u{2192}UPER vectors: data-126 (schema 126-per-extensions-OK.asn1, Rust) \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");

    let mut files: Vec<PathBuf> = fs::read_dir(&datadir)
        .unwrap_or_else(|e| panic!("failed to read {datadir}: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "in")
                && p.file_name().unwrap().to_string_lossy().starts_with("data-126-")
        })
        .collect();
    files.sort();

    std::panic::set_hook(Box::new(|_| {}));

    let processed = files.len();
    let mut failures = 0;
    for f in &files {
        process(f, &mut failures);
    }

    println!("\n  Processed {processed} files, {failures} failed.");
    if failures != 0 {
        std::process::exit(1);
    }
    println!("  All tests passed.");
}
