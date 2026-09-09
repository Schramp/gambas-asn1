// Mirrors RustBackend::emit_integer_hpp/cpp's output for a constrained
// INTEGER (0..100), U64 storage (see tests/codegen/test_backend_naming.cpp).
pub type MyInt = u64;

pub fn my_int_in_range(v: i64) -> bool {
    v >= 0 && v <= 100
}

fn main() {
    let x: MyInt = 42;
    assert!(my_int_in_range(x as i64));
    assert!(!my_int_in_range(200));
    println!("ok");
}
