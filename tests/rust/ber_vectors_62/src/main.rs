// BER vector test: asn1c data-62 test suite (schema 62-any-OK.asn1),
// Rust codegen leg — gambas-asn1#323, port of tests/seq/test_ber_vectors_62.cpp.
//
// Mirrors the original asn1c check-62.c logic (same as the C++ leg):
//   - OK files: decode must succeed; re-encode must be byte-identical.
//   - -B files: decode must fail (broken BER).
//   - -L files: decode must succeed; re-encode may be shorter (extensions stripped).
//   - -D files: decode must succeed; re-encode may differ (e.g. DER canonicalisation).
//
// Files 13/15/17/21/23 (-B) break the TLV structure inside an ANY member;
// the decoder checks that structure (X.690 §8.1) and rejects them, as asn1c
// and the C++ leg do.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

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

enum Expect {
    Ok,
    Broken,
    Recless,
    Different,
}

fn classify(name: &str) -> Expect {
    let Some(dot) = name.rfind(".ber") else { return Expect::Ok };
    if dot < 2 {
        return Expect::Ok;
    }
    match name.as_bytes()[dot - 1] {
        b'B' => Expect::Broken,
        b'L' => Expect::Recless,
        b'D' => Expect::Different,
        _ => Expect::Ok,
    }
}

fn process(path: &Path, failures: &mut i32) {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let exp = classify(&name);

    let raw = fs::read(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

    if matches!(exp, Expect::Broken) {
        let decoded = asn1cpp_wire::ber::object::decode_pdu::<T::T>(&raw).is_ok();
        check(&name, !decoded, failures);
        return;
    }

    // All non-broken files must decode successfully.
    let val = match asn1cpp_wire::ber::object::decode_pdu::<T::T>(&raw) {
        Ok(v) => {
            check(&format!("{name}  decode ok"), true, failures);
            v
        }
        Err(_) => {
            check(&format!("{name}  decode ok"), false, failures);
            return;
        }
    };

    // Re-encode and compare.
    let reenc = asn1cpp_wire::ber::object::encode_pdu(&val).unwrap();
    match exp {
        Expect::Ok => check(&format!("{name}  re-encode byte-identical"), reenc == raw, failures),
        Expect::Recless => {
            // Extensions stripped: re-encoded must be shorter or equal.
            check(&format!("{name}  re-encode <= original size"), reenc.len() <= raw.len(), failures)
        }
        Expect::Different => check(&format!("{name}  re-encode non-empty"), !reenc.is_empty(), failures),
        Expect::Broken => unreachable!(),
    }
}

fn main() {
    // CMake passes the data directory as the first argument.
    let datadir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/tests-c-compiler/data-62".to_string());

    println!("\n\u{2500}\u{2500} BER vectors: data-62 (schema 62-any-OK.asn1, Rust) \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");

    let mut files: Vec<PathBuf> = fs::read_dir(&datadir)
        .unwrap_or_else(|e| panic!("failed to read {datadir}: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "ber")
                && p.file_name().unwrap().to_string_lossy().starts_with("data-62-")
        })
        .collect();
    files.sort();

    let processed = files.len();
    let mut failures = 0;
    for f in &files {
        process(f, &mut failures);
    }

    println!("\n  Processed {processed} files.");
    if failures != 0 {
        println!("  {failures} test(s) FAILED");
        std::process::exit(1);
    }
    println!("  All tests passed.");
}
