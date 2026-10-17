// XER vector test: asn1c data-70 test suite (schema 70-xer-test-OK.asn1),
// Rust codegen leg — gambas-asn1#324, port of tests/seq/test_xer_vectors_70.cpp.
//
// Mirrors the original check-70.c logic (same as the C++ leg):
//   Each .in file is XER-decoded, BER-encoded, BER-decoded, then XER-re-encoded,
//   and the result is compared to the original using whitespace-stripped equality.
//
//   - (none) / -E files: round-trip must succeed; output must equal input (whitespace-stripped).
//   - -B files: XER decode must fail (broken input).
//   - -D / -X files: round-trip must succeed; output may differ from input.
//
// Same known limitations as the C++ leg — files in KNOWN_SKIP are counted as
// skipped, not failed (XML comments in content — issue #34; inline elements
// inside UTF8String text content — issue #35).
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use std::collections::HashSet;
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

fn known_skip() -> HashSet<&'static str> {
    [
        // XML comments in element/text content — https://github.com/Schramp/gambas-asn1/issues/34
        "data-70-07-D.in", "data-70-09-D.in",
        "data-70-14-D.in",
        "data-70-17-D.in",
        "data-70-37-D.in", "data-70-38-B.in",
        "data-70-57-D.in", "data-70-58-D.in", "data-70-59-D.in",
        "data-70-60-D.in", "data-70-61-D.in", "data-70-62-D.in",
        // Inline elements inside UTF8String text content — https://github.com/Schramp/gambas-asn1/issues/35
        "data-70-15.in",
        "data-70-19.in",
        "data-70-20-D.in", "data-70-21-D.in", "data-70-22-D.in", "data-70-23-D.in", "data-70-24-D.in",
        "data-70-40-D.in", "data-70-41-D.in",
    ]
    .into_iter()
    .collect()
}

/// Rust-only skip set (the C++ leg does not skip these — they pass there).
/// Currently empty; kept as a named place for a future Rust-only gap to
/// land, same as the C++ leg's own KNOWN_SKIP pattern above.
fn rust_known_skip() -> HashSet<&'static str> {
    HashSet::new()
}

// Strip all whitespace characters for loose XER comparison (mirrors xer_encoding_equal).
fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

// The .in files are complete XER documents rooted at <PDU>...</PDU>
// (X.693 §8.3.1, same as asn1c's asn_fprint output format).
fn xer_decode(xml: &str) -> Option<PDU::PDU> {
    asn1cpp_wire::xer::object::decode_pdu(xml).ok()
}

fn xer_encode(val: &PDU::PDU) -> String {
    asn1cpp_wire::xer::object::encode_pdu(val).unwrap()
}

enum Expect {
    Ok,
    Broken,
    Different,
}

fn classify(name: &str) -> Expect {
    let Some(dot) = name.rfind(".in") else { return Expect::Ok };
    if dot < 2 {
        return Expect::Ok;
    }
    match name.as_bytes()[dot - 1] {
        b'B' => Expect::Broken,
        b'D' | b'X' => Expect::Different,
        _ => Expect::Ok,
    }
}

/// Returns true if this file was skipped (not counted as pass/fail).
fn process(path: &Path, skip: &HashSet<&str>, failures: &mut i32) -> bool {
    let name = path.file_name().unwrap().to_string_lossy().to_string();

    if skip.contains(name.as_str()) {
        println!("  \x1b[33mSKIP\x1b[0m  {name}");
        return true;
    }

    // A handful of fixtures exercise codegen combinations still stubbed as
    // `MemberAccess::Unsupported` (gambas-asn1#385) — those panic on actual
    // use rather than returning a decode error. Catch here so one genuine
    // gap doesn't take down the whole sweep; reported as a FAIL like any
    // other unmet expectation, not silently absorbed.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| process_inner(path, &name)));
    match result {
        Ok((skipped, local_failures)) => {
            *failures += local_failures;
            skipped
        }
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("panic");
            println!("  \x1b[31mFAIL\x1b[0m  {name}  panicked: {msg}");
            *failures += 1;
            false
        }
    }
}

/// Returns (skipped, failures) — failures local to this file, merged into
/// the caller's total only if this call doesn't panic first (see `process`).
fn process_inner(path: &Path, name: &str) -> (bool, i32) {
    let mut failures = 0;
    let exp = classify(name);
    let input = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

    let decoded = xer_decode(&input);

    if matches!(exp, Expect::Broken) {
        check(&format!("{name}  XER decode must fail"), decoded.is_none(), &mut failures);
        return (false, failures);
    }

    check(&format!("{name}  XER decode ok"), decoded.is_some(), &mut failures);
    let Some(val) = decoded else { return (false, failures) };

    let ber = asn1cpp_wire::ber::object::encode_pdu(&val).unwrap();
    check(&format!("{name}  BER encode non-empty"), !ber.is_empty(), &mut failures);
    if ber.is_empty() {
        return (false, failures);
    }

    let val2 = asn1cpp_wire::ber::object::decode_pdu::<PDU::PDU>(&ber);
    check(&format!("{name}  BER decode ok"), val2.is_ok(), &mut failures);
    let Ok(val2) = val2 else { return (false, failures) };

    let reenc = xer_encode(&val2);

    if matches!(exp, Expect::Different) {
        check(&format!("{name}  round-trip ok (output differs by design)"), !reenc.is_empty(), &mut failures);
        return (false, failures);
    }

    // (none) / -E: whitespace-stripped output must match input.
    check(
        &format!("{name}  XER round-trip equal (whitespace-stripped)"),
        strip_ws(&reenc) == strip_ws(&input),
        &mut failures,
    );
    (false, failures)
}

fn main() {
    let datadir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/tests-c-compiler/data-70".to_string());

    println!("\n\u{2500}\u{2500} XER vectors: data-70 (schema 70-xer-test-OK.asn1, Rust) \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");

    let mut files: Vec<PathBuf> = fs::read_dir(&datadir)
        .unwrap_or_else(|e| panic!("failed to read {datadir}: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "in")
                && p.file_name().unwrap().to_string_lossy().starts_with("data-70-")
        })
        .collect();
    files.sort();

    // Panics from Unsupported-stub codegen gaps (see `process`) are caught
    // and reported as FAILs; suppress the default panic-hook backtrace
    // noise so the PASS/FAIL log stays readable.
    std::panic::set_hook(Box::new(|_| {}));

    let skip: HashSet<&str> = known_skip().into_iter().chain(rust_known_skip()).collect();
    let processed = files.len();
    let mut failures = 0;
    let mut skipped = 0;
    for f in &files {
        if process(f, &skip, &mut failures) {
            skipped += 1;
        }
    }

    println!("\n  Processed {processed} files, {skipped} skipped, {failures} failed.");
    if failures != 0 {
        std::process::exit(1);
    }
    println!("  All active tests passed.");
}
