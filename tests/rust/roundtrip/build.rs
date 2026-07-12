// Pulls the compiler-generated Point.rs (tests/CMakeLists.txt's
// gen_rust_simple_seq custom target, same pattern as SIMPLE_SEQ_GEN_DIR on
// the C++ side) into OUT_DIR so src/lib.rs can include!() it — gambas-asn1#219.
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let gen_dir = env::var("ASN1CPP_RUST_GEN_DIR").expect(
        "ASN1CPP_RUST_GEN_DIR must be set to the directory containing the compiler-generated \
         Point.rs (see tests/CMakeLists.txt's rust_roundtrip_test ENVIRONMENT property)",
    );
    let src = PathBuf::from(&gen_dir).join("Point.rs");
    let out_dir = env::var("OUT_DIR").unwrap();
    let dst = PathBuf::from(&out_dir).join("point_generated.rs");

    // RustBackend::emit_declaration_preamble emits a `//!` (inner doc
    // comment) module header — valid at the true start of a file/module,
    // but src/lib.rs pulls this content in via `include!()` after its own
    // crate-level `//!` doc comment, so by the time rustc sees it, it's no
    // longer at the start of an item (E0753). Neutralize it into a regular
    // `//` comment on the way through; nothing here needs the module doc.
    let content = fs::read_to_string(&src)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", src.display(), e));
    let content: String = content
        .lines()
        .map(|line| if let Some(rest) = line.strip_prefix("//!") { format!("//{rest}") } else { line.to_string() })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&dst, content)
        .unwrap_or_else(|e| panic!("failed to write {}: {}", dst.display(), e));

    println!("cargo:rerun-if-env-changed=ASN1CPP_RUST_GEN_DIR");
    println!("cargo:rerun-if-changed={}", src.display());
}
