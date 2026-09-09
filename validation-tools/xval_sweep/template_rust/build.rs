// Pulls every compiler-generated .rs file for the real ETSI LI PS-PDU
// schema from examples/sample.source.ETSI-LI-PS-PDU/rust-probe/src/ (built
// fresh by this crate's own Makefile before `cargo build` runs) into
// OUT_DIR — same lib.rs-as-manifest strategy as
// asn1cpp/tests/rust/ber_vectors_62/build.rs: reads the compiler's own
// generated lib.rs as the manifest (each `#[path = "X.rs"] pub mod y;`
// line names one file to copy and one module name to preserve), rewriting
// each `#[path]` target to OUT_DIR-absolute so the whole set can be
// textually spliced into src/lib.rs via include!().
use std::env;
use std::fs;
use std::path::PathBuf;

// See ber_vectors_62/build.rs's identical helper for why: a generated
// file's `//!` inner doc comment is only valid at the true start of a
// file/module, but this file lands here via include!() after whatever
// already precedes it in src/lib.rs (E0753).
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
    let gen_dir = env::var("ASN1CPP_RUST_ETSI_GEN_DIR").expect(
        "ASN1CPP_RUST_ETSI_GEN_DIR must be set to examples/sample.source.ETSI-LI-PS-PDU/rust-probe/src \
         (an absolute path) — see this crate's own Makefile, which sets it after ensuring rust-probe is built",
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
        // rust-probe/src/ is wiped and regenerated wholesale by this
        // crate's own Makefile on every invocation, so every file's mtime
        // genuinely changes on a real regeneration (unlike an incremental
        // rebuild that leaves most files untouched) — cargo's mtime-based
        // rerun-if-changed still works correctly here, it just can't be
        // narrowed to "only the files that actually changed" the way an
        // incremental build's dependency graph could.
        println!("cargo:rerun-if-changed={}", src.display());

        rewritten.push_str(&format!("#[path = \"{}\"", dst.display()));
        rewritten.push_str(&line[after_quote + end + 1..]);
        rewritten.push('\n');
    }
    fs::write(PathBuf::from(&out_dir).join("lib_paths.rs"), rewritten).unwrap();

    println!("cargo:rerun-if-changed={}", lib_src.display());
    println!("cargo:rerun-if-env-changed=ASN1CPP_RUST_ETSI_GEN_DIR");
}
