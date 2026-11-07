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

- **BER, XER, JER (JSON) and UPER (PER)** encode/decode, in C++, Rust and Java
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
Installing the compiler and the Java runtime (into the local Maven
repository, `~/.m2`): [**INSTALL.md**](INSTALL.md).

## Using a release

[![Maven Central](https://img.shields.io/maven-central/v/io.github.schramp.gambasasn1/gambasasn1-wire)](https://central.sonatype.com/artifact/io.github.schramp.gambasasn1/gambasasn1-wire)

Each [release](https://github.com/Schramp/gambas-asn1/releases) has the
compiler with the C++ and Rust runtimes for linux-x86_64 as a tarball. The
Java runtime is on Maven Central as
`io.github.schramp.gambasasn1:gambasasn1-wire`. The compiler and the runtime
must be the same version; generated code does not compile against a runtime
of another version.

Generating Java and building it with Maven, for release `V`:

```bash
V=0.1.0
curl -LO https://github.com/Schramp/gambas-asn1/releases/download/v$V/asn1cpp-$V-linux-x86_64.tar.gz
tar xzf asn1cpp-$V-linux-x86_64.tar.gz
export PATH=$PWD/asn1cpp-$V/bin:$PATH
asn1cpp --target=java --package=contacts contact.asn1 -o src/main/java/contacts
```

`-o` is the directory of the `--package`, and the compiler owns it: keep your
own sources outside it.

```xml
<dependency>
  <groupId>io.github.schramp.gambasasn1</groupId>
  <artifactId>gambasasn1-wire</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle: `implementation("io.github.schramp.gambasasn1:gambasasn1-wire:0.1.0")`
with `mavenCentral()`. A Maven build that runs the compiler itself, or
compiles generated code that is checked in: [INSTALL.md](INSTALL.md#generating-java)
and [`examples/contact-book/maven`](examples/contact-book/maven).

## Status

0.1.0 is the first release (see [Using a release](#using-a-release)).

- **Compiler.** Reads every module of ETSI TS 102 232 and 3GPP TS 25.331.
  Passes all 145 asn1c parser pass-tests and all 3 reject-tests, and handles
  34 of the 35 semantic-error tests.
- **Backends.** C++ (`--target=cpp`, the reference), Rust (`--target=rust`)
  and Java (`--target=java`). All three emit the same descriptor tables,
  checked by `validation-tools/table_diff`, and each runtime implements BER,
  XER, JER and unaligned PER (UPER), with constraint validation.
- **Cross-validation.** `validation-tools/xval_sweep` runs 72 schema/PDU
  targets through every encode/decode path of the C++, Rust and Java codecs
  and compares the results: on every pull request across the three runtimes
  (with a decoder fuzz pass), on `main` also against asn1c. An Erlang/OTP
  leg runs alongside for information.

Details per codec: [Status and Conformance](doc/book.md#14-status-and-conformance).
Open gaps: [Known Limitations](doc/book.md#15-known-limitations).

## Contributing

Code style, commit conventions, and the required test matrix before
submitting a change: [doc/book.md §17](doc/book.md#17-contributing). Open
work is tracked as [GitHub issues](https://github.com/Schramp/gambas-asn1/issues).

## License

BSD 2-Clause — see [LICENSE](LICENSE). Builds on the grammar and test suite
of [asn1c](https://github.com/vlm/asn1c) (Lev Walkin) and its
[active fork](https://github.com/mouse07410/asn1c) (Mouse) — see
[doc/book.md §2](doc/book.md#2-credits) for full credits.
