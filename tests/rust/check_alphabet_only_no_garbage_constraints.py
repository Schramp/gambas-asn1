#!/usr/bin/env python3
"""Regression check for gambas-asn1#466's discovered bug: a FROM-alphabet-only
member (no SIZE constraint at all) left MemberTypeDescriptorSpec's
size_lower/size_upper uninitialized (Generator.cpp), so the generated
Constraints table literally contained garbage stack values — both C++ and
Rust format these fields unconditionally, so `flags`'s SIZE_CONSTRAINED bit
being clear (harmless at runtime, since validate_size/validate_string never
read size_lower/size_upper in that case) hid the bug from every functional
test; only the generated *source text* itself shows it. `tag` in
tests/asn1/rust_alphabet_test.asn1 is exactly this combination: FROM-only,
no SIZE, on an inline SEQUENCE member.

Checked via exact substring match against the real compiler's own output
(not a hand-populated spec, which would bypass Generator.cpp's own
field-population code entirely, the actual bug location) — a garbage value
still compiles as valid Rust, so a build-success-only check would not have
caught this.
"""
import sys
from pathlib import Path

def main():
    if len(sys.argv) != 2:
        print("usage: check_alphabet_only_no_garbage_constraints.py <path/to/Code.rs>", file=sys.stderr)
        return 2
    text = Path(sys.argv[1]).read_text()
    expected = (
        "static ASN_TYP_CODE_TAG_CONSTRAINTS: asn1cpp_ber::constraints::Constraints "
        "= asn1cpp_ber::constraints::Constraints {\n"
        "    flags: 0, lower_bound: 0, upper_bound: 0, lower_u64: 0, upper_u64: 0, "
        "size_lower: 0, size_upper: 9223372036854775807, encode_table: Some(&ASN_TYP_CODE_TAG_ENC),\n"
        "};"
    )
    if expected not in text:
        print("FAIL: expected FROM-only Constraints table (size_lower: 0, "
              "size_upper: i64::MAX sentinel — not garbage) not found in", sys.argv[1], file=sys.stderr)
        print("--- looking for ---", file=sys.stderr)
        print(expected, file=sys.stderr)
        return 1
    print("OK: FROM-only member's Constraints table has clean size_lower/size_upper, not garbage.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
