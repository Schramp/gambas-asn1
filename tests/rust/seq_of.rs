// Mirrors RustBackend::emit_seq_of_cpp's output for a bounded SIZE(1..10)
// SEQUENCE OF (see tests/codegen/test_backend_naming.cpp). Generic over the
// element type — no real element type exists yet (no --target=rust wiring).
pub fn my_list_size_ok<T>(v: &Vec<T>) -> bool {
    (v.len() as i64) >= 1 && (v.len() as i64) <= 10
}

fn main() {
    let v: Vec<i64> = vec![1, 2, 3];
    assert!(my_list_size_ok(&v));
    let empty: Vec<i64> = vec![];
    assert!(!my_list_size_ok(&empty));
    let s: Vec<String> = vec!["a".to_string()];
    assert!(my_list_size_ok(&s));
    println!("ok");
}
