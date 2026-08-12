// Pulls every compiler-generated .rs file for 62-any-OK.asn1 (T.rs,
// T1Ext.rs, T2.rs, T2M3.rs, T3.rs, T4.rs, lib.rs) from the directory named
// by ASN1CPP_RUST_BV62_GEN_DIR into OUT_DIR — gambas-asn1#323.
//
// Unlike tests/rust/roundtrip/'s build.rs (which pulls one self-contained
// type per include!()), 62-any-OK.asn1 is a real multi-type schema whose
// generated files reference each other by module path (`use
// crate::t1_ext::T1Ext;` etc, per the compiler's own generated `lib.rs`).
// Rather than hand-list every file/module name here (fragile — breaks
// silently if the schema or the compiler's snake_case naming ever changes),
// this reads the generated `lib.rs` itself as the manifest: each
// `#[path = "X.rs"] pub mod y;` line names one file to copy and one module
// name to preserve. The copied `#[path]` targets are rewritten to
// OUT_DIR-absolute so the whole set can be textually spliced into
// src/main.rs via `include!()` regardless of where cargo's OUT_DIR happens
// to sit relative to this crate's own source tree.
use std::env;
use std::fs;
use std::path::PathBuf;

// See tests/rust/roundtrip/build.rs's identical helper for why: a
// generated file's `//!` inner doc comment is only valid at the true start
// of a file/module, but this file lands here via `include!()` after
// whatever already precedes it in src/main.rs, so by the time rustc sees
// it, it's no longer at the start of an item (E0753).
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
    let gen_dir = env::var("ASN1CPP_RUST_BV62_GEN_DIR").expect(
        "ASN1CPP_RUST_BV62_GEN_DIR must be set to the directory containing the compiler-generated \
         T.rs/T1Ext.rs/T2.rs/T2M3.rs/T3.rs/T4.rs/lib.rs (see tests/CMakeLists.txt's \
         rust_ber_vectors_62 ENVIRONMENT property)",
    );
    let out_dir = env::var("OUT_DIR").unwrap();

    let lib_src = PathBuf::from(&gen_dir).join("lib.rs");
    let lib_text = fs::read_to_string(&lib_src)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", lib_src.display(), e));

    let mut rewritten = String::new();
    for line in lib_text.lines() {
        let Some(start) = line.find("#[path = \"") else {
            rewritten.push_str(line);
            rewritten.push('\n');
            continue;
        };
        let after_quote = start + "#[path = \"".len();
        let rest = &line[after_quote..];
        let end = rest.find('"').unwrap_or_else(|| panic!("malformed #[path] line in {}: {line}", lib_src.display()));
        let fname = &rest[..end];

        let src = PathBuf::from(&gen_dir).join(fname);
        let dst = PathBuf::from(&out_dir).join(fname);
        copy_neutralizing_inner_doc_comment(&src, &dst);
        println!("cargo:rerun-if-changed={}", src.display());

        rewritten.push_str(&format!("#[path = \"{}\"", dst.display()));
        rewritten.push_str(&line[after_quote + end + 1..]);
        rewritten.push('\n');
    }
    fs::write(PathBuf::from(&out_dir).join("lib_paths.rs"), rewritten).unwrap();

    println!("cargo:rerun-if-env-changed=ASN1CPP_RUST_BV62_GEN_DIR");
    println!("cargo:rerun-if-changed={}", lib_src.display());
}
