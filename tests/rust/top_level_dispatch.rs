// Mirrors RustBackend's top-level dispatch output (emit_hpp_preamble,
// emit_namespace_open/close, emit_seq_of_hpp, emit_typeref_alias_hpp — see
// tests/codegen/test_backend_naming.cpp). emit_cpp_preamble and
// emit_builtin_alias_hpp are deliberately empty for Rust (see their doc
// comments in RustBackend.cpp) so there is nothing to mirror for them here.

//! Module: MyModule { 1 2 3 }

pub mod myns {

pub type MyList2 = Vec<i64>;

pub type MyAlias = i64;

}

fn main() {
    let v: myns::MyList2 = vec![1, 2, 3];
    assert_eq!(v.len(), 3);
    let a: myns::MyAlias = 42;
    assert_eq!(a, 42);
    println!("ok");
}
