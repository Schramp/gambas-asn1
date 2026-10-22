#!/usr/bin/env python3
"""Checks the --container-config sidecar handling of the asn1cpp compiler.

1. --list-contained on tests/asn1/containing_test.asn1 + its sidecar must
   print exactly tests/asn1/containing_test.contained.expected.
2. Each malformed sidecar below must make the compiler fail with the given
   message fragment.
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

BAD = [
    ('{ "container_fields": [ ] , }', "expected a member name string"),
    ('{ "fields": [] }', 'unknown top-level key "fields"'),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Holder", "field": "viaConfig" } ] }',
     '"inner_type" is required'),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Holder", "field": "kind", "inner_type": "Inner" } ] }',
     "is not an OCTET STRING"),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Holder", "field": "viaConstraint", "inner_type": "Envelope" } ] }',
     "conflicts with its CONTAINING"),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Holder", "field": "viaConfig", "inner_type": "Nope" } ] }',
     "is not defined"),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Holder", "field": "viaConfig", "inner_type": "Inner",'
     ' "when": { "member": "kind", "equals": "odd" } } ] }',
     "is not a value of 'kind'"),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Holder", "field": "viaConfig", "inner_type": "Inner",'
     ' "when": { "member": "raw", "equals": 1 } } ] }',
     "must be ENUMERATED, INTEGER or BOOLEAN"),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Pick", "field": "inner",'
     ' "when": { "member": "other", "equals": 1 } } ] }',
     "a CHOICE has no sibling members"),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Holder", "field": "viaConfig", "inner_type": "Inner", "xer": "pretty" } ] }',
     '"xer" must be hex, inline or inline_raw'),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Holder", "field": "viaConfig", "inner_type": "Inner", "colour": 1 } ] }',
     'unknown key "colour"'),
    ('{ "container_fields": [ { "module": "ContainingTest", "type": "Holder", "field": "viaConfig", "inner_type": "Inner" },'
     ' { "module": "ContainingTest", "type": "Holder", "field": "viaConfig", "inner_type": "Inner" } ] }',
     "is already configured at line"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--asn1cpp", required=True)
    ap.add_argument("--tests-dir", required=True)
    args = ap.parse_args()
    tdir = Path(args.tests_dir)
    schema = tdir / "asn1" / "containing_test.asn1"
    failures = 0

    r = subprocess.run([args.asn1cpp, str(schema),
                        "--container-config=" + str(tdir / "asn1" / "containing_test.container.json"),
                        "--list-contained"], capture_output=True, text=True)
    got = [l for l in r.stdout.splitlines() if l.startswith("contained:")]
    want = (tdir / "asn1" / "containing_test.contained.expected").read_text().splitlines()
    if r.returncode != 0 or got != want:
        failures += 1
        print("FAIL  --list-contained output differs (rc=%d)" % r.returncode)
        print("  got:\n    " + "\n    ".join(got))
        print("  want:\n    " + "\n    ".join(want))
        print(r.stderr)
    else:
        print("PASS  --list-contained")

    with tempfile.TemporaryDirectory() as td:
        for i, (text, frag) in enumerate(BAD):
            cfg = Path(td) / ("bad%d.json" % i)
            cfg.write_text(text)
            r = subprocess.run([args.asn1cpp, str(schema), "--container-config=" + str(cfg),
                                "--list-contained"], capture_output=True, text=True)
            if r.returncode == 0 or frag not in r.stderr:
                failures += 1
                print("FAIL  bad config %d: rc=%d, expected %r in:\n%s" % (i, r.returncode, frag, r.stderr))
            else:
                print("PASS  bad config %d (%s)" % (i, frag))

    print("FAILED" if failures else "all passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
