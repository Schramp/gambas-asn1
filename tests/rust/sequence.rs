// Mirrors RustBackend::emit_sequence_hpp/cpp's output for a SEQUENCE with
// one required INTEGER member and one optional String member
// (see tests/codegen/test_backend_naming.cpp).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MySeq {
    pub count: i64,
    pub label: Option<String>,
}

impl MySeq {
    pub fn new() -> Self {
        Self::default()
    }
}

fn main() {
    let mut s = MySeq::new();
    assert_eq!(s.count, 0);
    assert_eq!(s.label, None);
    s.count = 42;
    s.label = Some("hi".to_string());
    assert_eq!(s.count, 42);
    assert_eq!(s.label, Some("hi".to_string()));
    println!("ok");
}
