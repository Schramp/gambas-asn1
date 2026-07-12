// Pulls the compiler-generated Point.rs (tests/CMakeLists.txt's
// gen_rust_simple_seq custom target, same pattern as SIMPLE_SEQ_GEN_DIR on
// the C++ side) and Widget.rs (gambas-asn1#282) into OUT_DIR so src/lib.rs
// can include!() them — gambas-asn1#219.
use std::env;
use std::fs;
use std::path::PathBuf;

// Neutralizes RustBackend::emit_declaration_preamble's `//!` (inner doc
// comment) module header — valid at the true start of a file/module, but
// src/lib.rs pulls this content in via `include!()` after its own
// crate-level `//!` doc comment, so by the time rustc sees it, it's no
// longer at the start of an item (E0753). Turns it into a regular `//`
// comment on the way through; nothing here needs the module doc.
fn copy_neutralizing_inner_doc_comment(src: &std::path::Path, dst: &std::path::Path) {
    let content = fs::read_to_string(src)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", src.display(), e));
    let content: String = content
        .lines()
        .map(|line| if let Some(rest) = line.strip_prefix("//!") { format!("//{rest}") } else { line.to_string() })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(dst, content).unwrap_or_else(|e| panic!("failed to write {}: {}", dst.display(), e));
}

fn main() {
    let gen_dir = env::var("ASN1CPP_RUST_GEN_DIR").expect(
        "ASN1CPP_RUST_GEN_DIR must be set to the directory containing the compiler-generated \
         Point.rs (see tests/CMakeLists.txt's rust_roundtrip_test ENVIRONMENT property)",
    );
    // gambas-asn1#282: Widget.rs lives in a *separate* generated directory
    // (ASN1CPP_RUST_WIDE_GEN_DIR) — each asn1cpp invocation deletes any .rs
    // in its own out-dir it didn't itself produce, so Point.rs/Widget.rs
    // can't share one out-dir without one compiler run wiping the other's
    // output (see tests/CMakeLists.txt's RUST_WIDE_TYPES_GEN_DIR comment).
    let wide_gen_dir = env::var("ASN1CPP_RUST_WIDE_GEN_DIR").expect(
        "ASN1CPP_RUST_WIDE_GEN_DIR must be set to the directory containing the compiler-generated \
         Widget.rs (see tests/CMakeLists.txt's rust_roundtrip_test ENVIRONMENT property)",
    );
    let out_dir = env::var("OUT_DIR").unwrap();

    let point_src = PathBuf::from(&gen_dir).join("Point.rs");
    let point_dst = PathBuf::from(&out_dir).join("point_generated.rs");
    copy_neutralizing_inner_doc_comment(&point_src, &point_dst);

    let widget_src = PathBuf::from(&wide_gen_dir).join("Widget.rs");
    let widget_dst = PathBuf::from(&out_dir).join("widget_generated.rs");
    copy_neutralizing_inner_doc_comment(&widget_src, &widget_dst);

    println!("cargo:rerun-if-env-changed=ASN1CPP_RUST_GEN_DIR");
    println!("cargo:rerun-if-env-changed=ASN1CPP_RUST_WIDE_GEN_DIR");
    println!("cargo:rerun-if-changed={}", point_src.display());
    println!("cargo:rerun-if-changed={}", widget_src.display());
}
