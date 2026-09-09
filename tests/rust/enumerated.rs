// Mirrors RustBackend::emit_enumerated_hpp/cpp's output for a simple
// ENUMERATED { foo(0), bar(1) } type (see tests/codegen/test_backend_naming.cpp).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum MyEnum {
    Foo = 0,
    Bar = 1,
}

impl std::convert::TryFrom<i64> for MyEnum {
    type Error = ();
    fn try_from(v: i64) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(MyEnum::Foo),
            1 => Ok(MyEnum::Bar),
            _ => Err(()),
        }
    }
}

fn main() {
    use std::convert::TryFrom;
    assert_eq!(MyEnum::try_from(0), Ok(MyEnum::Foo));
    assert_eq!(MyEnum::try_from(1), Ok(MyEnum::Bar));
    assert_eq!(MyEnum::try_from(2), Err(()));
    println!("ok");
}
