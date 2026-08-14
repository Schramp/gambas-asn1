// Mirrors RustBackend::emit_builtin_alias_cpp's output for a bounded
// SIZE(1..10) OCTET STRING (see tests/codegen/test_backend_naming.cpp).
//
// This file is compiled standalone by run_rust_tests.py (plain rustc, no
// crate linking) — the real generated code references
// asn1cpp_ber::octet_string::OctetString from the actual runtime crate;
// this local stand-in mirrors its shape (see octet_string.rs's own module
// doc for OctetString itself) just enough to exercise the same pattern.
mod asn1cpp_ber {
    pub mod octet_string {
        #[derive(Debug, Clone, Default, PartialEq)]
        pub struct OctetString(pub Vec<u8>);

        impl std::ops::Deref for OctetString {
            type Target = Vec<u8>;
            fn deref(&self) -> &Self::Target { &self.0 }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MyBytes(pub asn1cpp_ber::octet_string::OctetString);

impl std::ops::Deref for MyBytes {
    type Target = asn1cpp_ber::octet_string::OctetString;
    fn deref(&self) -> &Self::Target { &self.0 }
}

pub fn my_bytes_size_ok(v: &asn1cpp_ber::octet_string::OctetString) -> bool {
    (v.len() as i64) >= 1 && (v.len() as i64) <= 10
}

fn main() {
    assert!(my_bytes_size_ok(&asn1cpp_ber::octet_string::OctetString(vec![1, 2, 3])));
    assert!(!my_bytes_size_ok(&asn1cpp_ber::octet_string::OctetString(vec![])));
    println!("ok");
}
