// Rust leg of the REAL value-range constraint test
// (real_constraint_test.asn1); mirrors tests/seq/test_real_constraint.cpp.
// Inline-constrained members validate through `Asn1Seq::validate`; the
// named Pct / Finite types carry their range in `{Type}_CONSTRAINTS`.
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/lib_paths.rs"));

use asn1cpp_wire::constraints::validate_real;
use asn1cpp_wire::real::Real;
use asn1cpp_wire::spec::object::Asn1Seq;
use Ranges::Ranges as Rec;

fn check(label: &str, cond: bool, failures: &mut i32) {
    if cond {
        println!("  \x1b[32mPASS\x1b[0m  {label}");
    } else {
        println!("  \x1b[31mFAIL\x1b[0m  {label}");
        *failures += 1;
    }
}

fn main() {
    let mut failures = 0;
    let inf = f64::INFINITY;
    println!("=== REAL value-range constraints ===");

    let pct = &Pct::Pct_CONSTRAINTS;
    check("Pct (0..100): 0, 50 and 100 valid", [0.0, 50.0, 100.0].iter().all(|&v| validate_real(v, pct) == 0), &mut failures);
    check("Pct: -2.5 below by 3", validate_real(-2.5, pct) == 3, &mut failures);
    check("Pct: 100.25 above by 1", validate_real(100.25, pct) == -1, &mut failures);
    check("Pct: NaN outside", validate_real(f64::NAN, pct) == 1, &mut failures);
    check("Pct: PLUS-INFINITY above, saturated", validate_real(inf, pct) == -i64::MAX, &mut failures);

    let fin = &Finite::Finite_CONSTRAINTS;
    check("Finite: 1e300 valid", validate_real(1e300, fin) == 0, &mut failures);
    check("Finite: PLUS-INFINITY excluded", validate_real(inf, fin) < 0, &mut failures);
    check("Finite: MINUS-INFINITY excluded", validate_real(-inf, fin) > 0, &mut failures);
    check("Finite: NaN excluded", validate_real(f64::NAN, fin) != 0, &mut failures);

    let with = |f: &dyn Fn(&mut Rec)| {
        let mut r = Rec { unit: Real::new(0.5), both: Real::new(1.0), ..Default::default() };
        f(&mut r);
        r
    };
    check("in-range record: every present member valid", [0, 2, 3].iter().all(|&i| with(&|_| {}).validate(i) == 0), &mut failures);
    check("unit (0<..<1): open endpoint 0 excluded", with(&|r| r.unit = Real::new(0.0)).validate(0) > 0, &mut failures);
    check("unit: open endpoint 1 excluded", with(&|r| r.unit = Real::new(1.0)).validate(0) < 0, &mut failures);
    check("big (1.5E3..MAX): PLUS-INFINITY valid", with(&|r| r.big = Some(Real::new(inf))).validate(1) == 0, &mut failures);
    check("big: 1499 below", with(&|r| r.big = Some(Real::new(1499.0))).validate(1) == 1, &mut failures);
    check("both (-10..10)(0..5): 6 above intersection", with(&|r| r.both = Real::new(6.0)).validate(2) < 0, &mut failures);
    check("both: -1 below intersection", with(&|r| r.both = Real::new(-1.0)).validate(2) > 0, &mut failures);
    check("ext (-1..1, ...): extensible accepts 5", with(&|r| r.ext = Real::new(5.0)).validate(3) == 0, &mut failures);

    println!("\n{} ({failures} failure{})", if failures > 0 { "FAILED" } else { "OK" }, if failures == 1 { "" } else { "s" });
    std::process::exit(if failures > 0 { 1 } else { 0 });
}
