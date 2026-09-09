// Pulls every compiler-generated .rs file for
// 201-nested-choice-name-collision-OK.asn1 (HandoverCommand.rs and its
// component types + lib.rs) from the directory named by
// ASN1CPP_RUST_NC201_GEN_DIR into OUT_DIR.
//
// Identical strategy to tests/rust/xer_vectors_202/build.rs: reads the
// compiler's own generated lib.rs as the manifest (each
// `#[path = "X.rs"] pub mod y;` line names one file to copy and one module
// name to preserve), rewriting each `#[path]` target to OUT_DIR-absolute so
// the whole set can be textually spliced into src/main.rs via include!().
use std::env;
use std::fs;
use std::path::PathBuf;

// See xer_vectors_202/build.rs's identical helper for why: a generated
// file's `//!` inner doc comment is only valid at the true start of a
// file/module, but this file lands here via include!() after whatever
// already precedes it in src/main.rs (E0753).
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
    let gen_dir = env::var("ASN1CPP_RUST_NC201_GEN_DIR").expect(
        "ASN1CPP_RUST_NC201_GEN_DIR must be set to the directory containing the compiler-generated \
         HandoverCommand.rs and friends + lib.rs (see tests/CMakeLists.txt's rust_nested_choice_201 ENVIRONMENT property)",
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

    println!("cargo:rerun-if-env-changed=ASN1CPP_RUST_NC201_GEN_DIR");
    println!("cargo:rerun-if-changed={}", lib_src.display());
}
