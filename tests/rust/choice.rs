// Mirrors RustBackend::emit_choice_hpp/cpp's output for a CHOICE with an
// INTEGER alternative and a String alternative
// (see tests/codegen/test_backend_naming.cpp).
#[derive(Debug, Clone, PartialEq)]
pub enum MyChoice {
    Num(i64),
    Label(String),
}

pub fn my_choice_get_num(x: &mut MyChoice) -> &mut i64 {
    match x { MyChoice::Num(v) => v, _ => panic!("wrong variant") }
}

pub fn my_choice_get_label(x: &mut MyChoice) -> &mut String {
    match x { MyChoice::Label(v) => v, _ => panic!("wrong variant") }
}

fn main() {
    let mut c = MyChoice::Num(42);
    *my_choice_get_num(&mut c) += 1;
    assert_eq!(c, MyChoice::Num(43));

    let mut c2 = MyChoice::Label("hi".to_string());
    my_choice_get_label(&mut c2).push_str("!");
    assert_eq!(c2, MyChoice::Label("hi!".to_string()));

    println!("ok");
}
