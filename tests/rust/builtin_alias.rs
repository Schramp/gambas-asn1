// Mirrors RustBackend::emit_builtin_alias_cpp's output for a bounded
// SIZE(1..10) OCTET STRING (see tests/codegen/test_backend_naming.cpp).
pub type MyBytes = Vec<u8>;

pub fn my_bytes_size_ok(v: &Vec<u8>) -> bool {
    (v.len() as i64) >= 1 && (v.len() as i64) <= 10
}

fn main() {
    assert!(my_bytes_size_ok(&vec![1, 2, 3]));
    assert!(!my_bytes_size_ok(&vec![]));
    println!("ok");
}
