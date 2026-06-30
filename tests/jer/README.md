# JER test fixtures

JER (JSON Encoding Rules, X.697) test corpus ported from asn1c's randomized
test suite (`asn1c/tests/tests-randomized/`).

## Structure

```
bundles/
  <TypeName>/
    test.asn1          ASN.1 schema defining type T
    samples/
      000.jer          JER-encoded instance (copied from asn1c random-data/jer/)
      000.xer          Matching XER instance (ground-truth reference)
      001.jer … 004.jer
      001.xer … 004.xer
```

## Type coverage

| Bundle | ASN.1 type |
|--------|-----------|
| NULL | NULL |
| BOOLEAN | BOOLEAN |
| INTEGER | INTEGER with named numbers |
| ENUMERATED | ENUMERATED (extensible) |
| REAL | REAL (IEEE 754 double) |
| BIT-STRING | BIT STRING with named bits |
| OCTET-STRING | OCTET STRING |
| VisibleString | VisibleString |
| OBJECT-IDENTIFIER | OBJECT IDENTIFIER |
| RELATIVE-OID | RELATIVE-OID |
| UTF8String | UTF8String (constrained) |
| BMPString | BMPString (constrained) |
| UniversalString | UniversalString (constrained) |
| UTCTime | UTCTime |
| GeneralizedTime | GeneralizedTime |
| CHOICE | CHOICE (extensible) |
| SEQUENCE | SEQUENCE (with SEQUENCE OF member) |
| SEQUENCE-OF | SEQUENCE OF |
| SET-OF | SET OF |

## Test runner

`run_jer_tests.py` decodes each `.jer` sample using asn1cpp JER, re-encodes
to XER, and compares against the `.xer` fixture (asn1c ground truth).

```bash
python3 asn1cpp/tests/jer/run_jer_tests.py --verbose
```

**Status: EXPECTED TO FAIL** — asn1cpp JER decode is not implemented yet.
See GitHub issues #156 (basic types) and #157 (composites).

The test is wired into ctest as `jer_bundle_roundtrip` with `WILL_FAIL TRUE`.
It will be flipped to expected-pass when #159 is completed.

## Adding samples

To regenerate or extend the corpus, re-run the asn1c randomized suite and
copy files from `.tmp.<N>-<Type>-bundle/random-data/{jer,xer}/`.
