# gambas-asn1

**A modern C++20 ASN.1 compiler and runtime.**

ASN.1 underpins X.509 certificates, telecom signalling, lawful-interception
records, and the air-interface messages of every generation of mobile
network. The dominant open-source compiler, [asn1c](https://github.com/vlm/asn1c),
generates C code with `void *` callback tables in a style from the early
2000s. gambas-asn1 is that compiler written today: it reads ASN.1 schemas
and generates clean, type-safe C++20 — with all codec logic living once in
a runtime library, not duplicated per generated type.

```bash
./build/compiler/asn1cpp path/to/schema.asn1 -o output/dir/
```

## Features

- **BER, XER, and UPER (PER)** encode/decode; JER (JSON) in progress
- **Table-only generated code** — no codec logic per type, so adding an
  encoding rule means writing one runtime class, not touching generated files
- **Constraint validation** (range, size, alphabet) with path-tracked reports
- **Cross-validated against asn1c** — 440/440 BER records, 40,000/40,000 UPER
  records, wire-fuzzed with zero crashes across 225k corrupted records
- **10× faster BER encode, 1.2× faster BER decode** than asn1c (see
  [Performance Figures](doc/book.md#16-performance-figures))

Proven against two demanding real-world schemas: **ETSI TS 102 232**
(lawful interception, BER) and **3GPP TS 25.331** (RRC, UPER) — both large,
deeply nested, and full of the ASN.1 constructs simpler compilers skip.

## Design goals

- **Performance without compromise.** No heap allocation in the encode hot
  path (reserve-and-patch length fields instead of temporary buffers), stack
  buffers for OID arcs, table-driven dispatch instead of virtual calls.
- **Minimal generated code.** Generated files are data — descriptor tables —
  never logic. A 300-type schema doesn't produce 300 copies of SEQUENCE
  encode logic.
- **asn1c as ground truth, not a dependency.** gambas-asn1 doesn't wrap or
  link against asn1c; it compiles ASN.1 directly. But any divergence in
  output from asn1c is presumed a gambas-asn1 bug until proven otherwise —
  enforced continuously via cross-validation and wire-fuzzing.
- **Owning, self-contained decoded objects.** Decode copies value bytes out
  of the input buffer, so a decoded object outlives the buffer it came from.
  Simple lifetime contract, at the cost of one allocation per string/octet
  field. See [Limitations](doc/book.md#limitations) for the borrowing-decode
  design considered and not (yet) taken.

Full rationale, trade-offs, and the story of how it was built:
[**doc/book.md**](doc/book.md).

## Getting started

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel $(nproc)
ctest --test-dir build --output-on-failure
```

Dependencies (CMake ≥ 3.20, GCC/Clang with C++20, Bison ≥ 3.8, RE/flex
6.1.0) and full build/run/test instructions, including the ETSI LI example
library and cross-validation setup: [**doc/QUICKSTART.md**](doc/QUICKSTART.md).

## Status

Compiler passes all asn1c parser conformance tests. BER and UPER codecs are
complete for their target schemas; XER is complete; JER is a stub. See
[Status and Conformance](doc/book.md#14-status-and-conformance) and
[Known Limitations](doc/book.md#15-known-limitations) for the details.

## Contributing

Code style, commit conventions, and the required test matrix before
submitting a change: [doc/book.md §17](doc/book.md#17-contributing). Open
work is tracked as [GitHub issues](https://github.com/Schramp/gambas-asn1/issues).

## License

BSD 2-Clause — see [LICENSE](LICENSE). Builds on the grammar and test suite
of [asn1c](https://github.com/vlm/asn1c) (Lev Walkin) and its
[active fork](https://github.com/mouse07410/asn1c) (Mouse) — see
[doc/book.md §2](doc/book.md#2-credits) for full credits.
