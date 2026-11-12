// XER-UPER-XER vector test: asn1c data-119 test suite (schema
// 119-per-strings-OK.asn1), Rust codegen leg — port of
// tests/seq/test_xer_vectors_119.cpp.
//
// Mirrors the original check-119.c logic (same as the C++ leg):
//   Each .in file is XER-decoded, UPER-encoded, UPER-decoded, then
//   XER-re-encoded, and the result is compared to the original using
//   whitespace-stripped equality.
//
//   - (none) files: round-trip must succeed; output must equal input
//     (whitespace-stripped).
//   - -P files: PER-incompatible input (alphabet/size constraint
//     violation); UPER encode must be rejected — `per::object::encode_pdu`
//     returns `Err`, as the C++ leg's PerCodec sets `encode_failed()`.
//
// The suite ships no UPER for its inputs, so the round trip alone cannot
// tell a wrong encoding shared by encoder and decoder from a right one.
// tests/vectors/per_strings_119.vectors holds asn1c's UPER for every non -P
// input; the encoding must equal it, and decoding it must give the input.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

fn decode_sequence_xer_pdu(xml: &str) -> Result<PDU::PDU, asn1cpp_wire::DecodeError> {
    asn1cpp_wire::xer::object::decode_pdu(xml)
}
fn encode_sequence_xer_pdu(val: &PDU::PDU) -> String {
    asn1cpp_wire::xer::object::encode_pdu(val).unwrap()
}
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

// -P files (asn1c's naming): PER-incompatible by design (alphabet or SIZE
// constraint violation); UPER encode must fail.
fn is_p_file(name: &str) -> bool {
    name.ends_with("-P.in")
}

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn per_encode(val: &PDU::PDU) -> Result<Vec<u8>, asn1cpp_wire::EncodeError> {
    asn1cpp_wire::per::object::encode_pdu(val)
}

fn per_decode(bytes: &[u8]) -> Result<PDU::PDU, asn1cpp_wire::per::reader::DecodeError> {
    asn1cpp_wire::per::object::decode_pdu(bytes)
}

fn process(path: &Path, failures: &mut i32) {
    let name = path.file_name().unwrap().to_string_lossy().to_string();

    // A handful of fixtures could exercise codegen combinations still
    // stubbed/unimplemented at runtime — catch here so one genuine gap
    // doesn't take down the whole sweep; reported as a FAIL like any
    // other unmet expectation, not silently absorbed.
    let is_p = is_p_file(&name);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| process_inner(path, &name, is_p)));
    match result {
        Ok(local_failures) => {
            *failures += local_failures;
        }
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

fn process_inner(path: &Path, name: &str, is_p: bool) -> i32 {
    let mut failures = 0;
    // Lossy: a -P fixture may carry bytes outside UTF-8 (the C++ leg reads
    // raw bytes); they become U+FFFD, still outside every PER alphabet.
    let raw = fs::read(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let input = String::from_utf8_lossy(&raw).into_owned();

    let decoded = decode_sequence_xer_pdu(&input);
    check(&format!("{name}  XER decode ok"), decoded.is_ok(), &mut failures);
    let Ok(val) = decoded else { return failures };

    let per = per_encode(&val);
    if is_p {
        check(&format!("{name}  UPER encode rejected (constraint violation)"), per.is_err(), &mut failures);
        return failures;
    }
    let per = per.unwrap_or_default();
    check(&format!("{name}  UPER encode non-empty"), !per.is_empty(), &mut failures);
    if per.is_empty() {
        return failures;
    }

    let val2 = per_decode(&per);
    check(&format!("{name}  UPER decode ok"), val2.is_ok(), &mut failures);
    let Ok(val2) = val2 else { return failures };

    // encode_sequence_xer already includes the outer <PDU>...</PDU> wrapper
    // (decode_sequence_xer consumes the same wrapper on the way in).
    let reenc = encode_sequence_xer_pdu(&val2);
    check(
        &format!("{name}  XER round-trip equal (whitespace-stripped)"),
        strip_ws(&reenc) == strip_ws(&input),
        &mut failures,
    );
    failures
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// asn1c's UPER for each non -P input (made by make_ber_vectors.py): our
/// encoding must equal it byte for byte, and decoding it must give the
/// input value back. Returns the number of vectors.
fn check_vectors(path: &str, failures: &mut i32) -> usize {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let mut n = 0;
    for line in text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let col: Vec<&str> = line.split('\t').collect();
        n += 1;
        check(&format!("vector {n}  has asn1c UPER"), col.len() == 6 && col[5] != "-", failures);
        if col.len() != 6 || col[5] == "-" {
            continue;
        }
        let asn1c = from_hex(col[5]);
        let val = decode_sequence_xer_pdu(col[1]);
        check(&format!("vector {n}  XER decode ok"), val.is_ok(), failures);
        let ours = val.ok().and_then(|v| per_encode(&v).ok());
        check(&format!("vector {n}  UPER encode == asn1c ({} octets)", asn1c.len()),
              ours.as_deref() == Some(asn1c.as_slice()), failures);
        let back = per_decode(&asn1c);
        check(&format!("vector {n}  asn1c UPER decodes to the input"),
              back.is_ok_and(|b| strip_ws(&encode_sequence_xer_pdu(&b)) == strip_ws(col[1])), failures);
    }
    n
}

fn main() {
    let datadir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/tests-c-compiler/data-119".to_string());

    println!("\n\u{2500}\u{2500} XER\u{2192}UPER\u{2192}XER vectors: data-119 (schema 119-per-strings-OK.asn1, Rust) \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");

    let mut files: Vec<PathBuf> = fs::read_dir(&datadir)
        .unwrap_or_else(|e| panic!("failed to read {datadir}: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "in")
                && p.file_name().unwrap().to_string_lossy().starts_with("data-119-")
        })
        .collect();
    files.sort();

    std::panic::set_hook(Box::new(|_| {}));

    let processed = files.len();
    let mut failures = 0;
    for f in &files {
        process(f, &mut failures);
    }
    let inputs = files.iter().filter(|f| !is_p_file(&f.file_name().unwrap().to_string_lossy())).count();

    let vectors = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "tests/vectors/per_strings_119.vectors".to_string());
    println!("\n\u{2500}\u{2500} asn1c UPER vectors ({vectors}) \u{2500}\u{2500}");
    let rows = check_vectors(&vectors, &mut failures);
    check(&format!("one vector per non -P input ({rows} vectors, {inputs} inputs)"), rows == inputs, &mut failures);

    println!("\n  Processed {processed} files, {rows} asn1c vectors, {failures} failed.");
    if failures != 0 {
        std::process::exit(1);
    }
    println!("  All active tests passed.");
}
