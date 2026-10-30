# gambas-asn1

### A Modern C++20 ASN.1 Compiler and Runtime

---

*Ruud Schramp*
*2025–2026*

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Credits](#2-credits)
3. [A Short History of ASN.1 and Its Uses Today](#3-a-short-history-of-asn1-and-its-uses-today)
4. [Building a Minimal ASN.1 Program](#4-building-a-minimal-asn1-program)
5. [Types and Sequences in ASN.1](#5-types-and-sequences-in-asn1)
6. [BER, PER, XER and Other Encoding Flavours](#6-ber-per-xer-and-other-encoding-flavours)
7. [Your First ASN.1 Schema](#7-your-first-asn1-schema)
8. [Your First Encoder and Decoder](#8-your-first-encoder-and-decoder)
9. [gambas-asn1 CLI Reference](#9-gambas-asn1-cli-reference)
10. [Design Philosophy](#10-design-philosophy)
11. [How asn1cpp Was Built](#11-how-asn1cpp-was-built)
12. [Challenges in Building a Fast ASN.1 Implementation](#12-challenges-in-building-a-fast-asn1-implementation)
13. [The Honest Parts: Where Complexity Lives](#13-the-honest-parts-where-complexity-lives)
14. [Status and Conformance](#14-status-and-conformance)
15. [Known Limitations](#15-known-limitations)
16. [Performance Figures](#16-performance-figures)
17. [Contributing](#17-contributing)
18. [References](#18-references)

---

## 1. Introduction

ASN.1 — Abstract Syntax Notation One — is one of the quiet foundations of the modern
world. It underpins X.509 certificates that secure every TLS connection. It carries the
signalling messages that set up phone calls across continents. It encodes the lawful
interception records that telecom operators are legally required to produce. It defines the
air-interface messages exchanged between handsets and base stations in 3G, 4G, and 5G
networks.

Despite this reach, ASN.1 tooling has remained largely frozen in the C era. The dominant
open-source compiler, asn1c, generates C code using callback tables and `void *` pointers
in a style that reflects its origin in the early 2000s. It works. It is fast. But it is
not the compiler you would write today.

gambas-asn1 is that compiler written today.

It reads ASN.1 module files and generates clean, type-safe C++20 code. The generated files
contain only static descriptor tables — no codec logic. All encoding and decoding is
handled by a compact runtime library. Changing the runtime does not require regenerating
any schema. Adding a new encoding rule (say, JSON Encoding Rules) means writing one new
codec class, not touching generated files at all.

The project targets two demanding real-world schemas:

- **ETSI TS 102 232** — the European standard for lawful interception of IP traffic,
  using Basic Encoding Rules (BER).
- **3GPP TS 25.331** — the Radio Resource Control protocol for UMTS (3G), using
  Packed Encoding Rules (UPER).

Both schemas are large, deeply nested, and full of the advanced ASN.1 constructs that
simpler compilers quietly ignore. Passing them is not a checkbox — it is proof that the
compiler handles the language as standardised.

This book describes the compiler, the runtime, the design choices behind them, and the
hard lessons learned building something that is both correct and fast.

---

## 2. Credits

gambas-asn1 stands on the shoulders of two decades of prior work.

**Lev Walkin** created the original asn1c compiler, released under the BSD 2-Clause
licence. asn1c is a complete, standards-conformant ASN.1 compiler that has been used in
production systems worldwide since the early 2000s. Its grammar, its test suite, and its
approach to generating table-driven C code provided both the starting point and the
reference ground truth for this project.

**Mouse** (mouse07410 on GitHub) maintains the active fork of asn1c, fixing bugs and
extending support for modern platforms and newer ASN.1 constructs. The fork's test suite
— 188 parser tests, BER vector sets for five schemas, and skeleton codec tests — is
mirrored verbatim into this project and must pass in full.

The ASN.1 grammar files in gambas-asn1 (`compiler/grammar/asn1.l` and `asn1.y`) are
direct ports of the asn1c grammar, adapted for RE/flex and Bison C++ mode with the
smallest possible changes. The intellectual work in those grammars belongs to Lev Walkin
and Mouse. It is retained here under the BSD 2-Clause licence.

---

## 3. A Short History of ASN.1 and Its Uses Today

### Origins

ASN.1 was standardised by the CCITT (now ITU-T) in 1984, alongside the Basic Encoding
Rules that give it a binary wire format. The driving need was interoperability: as
telecommunications networks became digital and connected, different vendors' equipment
needed to exchange structured data without agreeing on internal representations in
advance. ASN.1 provides the schema language; the encoding rules provide the wire format.

The 1988 revision added Distinguished Encoding Rules (DER), a canonical subset of BER
used wherever byte-for-byte reproducibility matters — most importantly in digital
signatures, where the signed bytes must be identical on every platform.

The 1994 and 2002 revisions added Packed Encoding Rules (PER), which discard all
self-describing tag and length fields and pack values into the minimum number of bits
dictated by the schema's constraints. A constrained INTEGER (0..7) encodes in three bits.
A SEQUENCE OF five elements with a SIZE (1..8) constraint needs no length field at all.
PER is the encoding of choice wherever bandwidth is precious — radio interfaces, satellite
links, embedded devices.

XML Encoding Rules (XER) arrived in 1998 and became important for logging and
diagnostics: a BER-encoded ASN.1 message can be transcoded to XER and read by a human
or a standard XML parser without any schema-specific tool.

### ASN.1 Today

ASN.1 is invisible infrastructure. You encounter it constantly without seeing it:

**Public Key Infrastructure.** Every X.509 certificate is ASN.1 encoded in DER. Every
time your browser validates a TLS certificate, it decodes ASN.1. The PKIX standards
(RFC 5280 and family) are written in ASN.1 module notation.

**Telecommunications.** 3GPP radio protocols — RRC for 3G/4G, NR RRC for 5G — are
defined in ASN.1 and encoded in UPER or APER. A base station and a handset exchange
hundreds of ASN.1 messages during a call setup.

**Lawful interception.** ETSI TS 102 232 defines the Handover Interface (HI2/HI3)
between network operators and law enforcement agencies. The PS-PDU structure that
encapsulates intercepted IP traffic, together with its identity and sequence records, is
ASN.1 encoded in BER. Every telecommunications operator in Europe is legally required to
implement this interface.

**Network management.** SNMP MIBs are defined using a subset of ASN.1. LDAP directory
entries are BER-encoded ASN.1 structures.

**Legacy finance and infrastructure.** EMV payment cards carry ASN.1 BER-encoded data.
Many air-traffic control and defence systems use ASN.1 for ground-to-ground messaging.

The language is 40 years old. It is not going away.

---

## 4. Building a Minimal ASN.1 Program

### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| GCC or Clang | C++20 | GCC 13+ (native `<format>`), or GCC 11 + libfmt (Ubuntu 22.04 LTS) |
| libfmt | ≥ 8.0 | Only needed on GCC < 13: `sudo apt install libfmt-dev` |
| CMake | ≥ 3.20 | |
| Bison | ≥ 3.8 | `sudo apt-get install bison` |
| RE/flex | 6.1.0 | Must be built from source (see below) |

### Install RE/flex

RE/flex is a modern C++ replacement for flex. It must be built from source:

```bash
git clone --branch v6.1.0 --depth 1 https://github.com/Genivia/RE-flex
cd RE-flex
./build.sh
sudo cp bin/reflex /usr/local/bin/
sudo cp -r include/reflex /usr/local/include/
sudo cp lib/libreflex.a /usr/local/lib/
```

### Clone and Build

```bash
git clone https://github.com/Schramp/gambas-asn1.git
cd gambas-asn1
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel $(nproc)
```

The compiler binary is at `build/compiler/asn1cpp`.

### Run the Tests

```bash
ctest --test-dir build/tests --output-on-failure
```

All 24 tests must pass. They cover BER, XER, PER round-trips, constraint validation,
explicit and implicit tagging, CHOICE extension skipping, and the full asn1c BER vector
suite for schema 62.

### Generate Code from a Schema

```bash
./build/compiler/asn1cpp my_schema.asn1 -o generated/
```

This produces one `.hpp` + `.cpp` pair per ASN.1 type defined in the schema. Link the
generated `.cpp` files against `libasn1cpp_runtime.a` from `build/runtime/`.

Generated names keep the ASN.1 spelling, with each hyphen turned into an underscore,
and are never recased: recasing could fold two distinct ASN.1 names into one. A
name that is a keyword of the target language is escaped. C++ appends `_`. Rust
uses a raw identifier (`r#type`), except for `self`, `Self`, `super` and `crate`,
which cannot be raw identifiers and get `_` appended instead (`self_`). No
ASN.1 name ends in a hyphen (X.680 §11.2, §11.3), so an escaped name never
clashes with another one. The codecs always use the ASN.1 name itself: an
ENUMERATED item `self` is `<self/>` in XER, whatever the Rust variant is called.

---

## 5. Types and Sequences in ASN.1

ASN.1 defines a rich type system. Understanding the core types is prerequisite to
reading any schema.

### Primitive Types

| ASN.1 Type | Description | C++ mapping |
|------------|-------------|-------------|
| `INTEGER` | Arbitrary-precision signed integer; constrained variants fit in `int64_t` or `uint64_t` | `asn1::Integer` / `asn1::UInteger` |
| `BOOLEAN` | True or false | `asn1::Boolean` |
| `NULL` | Carries no value; used as a marker | `asn1::Null` |
| `REAL` | IEEE 754 double or special values ±∞, NaN | `asn1::Real` |
| `ENUMERATED` | Named integer values | generated `asn1::EnumValue` subclass |
| `BIT STRING` | Sequence of bits with an optional named-bits table | `asn1::BitString` |
| `OCTET STRING` | Raw byte sequence | `asn1::OctetString` |
| `OBJECT IDENTIFIER` | Globally unique dotted-arc identifier | `asn1::Oid` |
| `RELATIVE-OID` | OID relative to a known base arc | `asn1::RelativeOid` |
| `UTCTime` | Date/time in YYMMDDHHmmssZ format | `asn1::UtcTime` |
| `GeneralizedTime` | Date/time in YYYYMMDDHHMMSS.fff format | `asn1::GeneralizedTime` |

String types — `UTF8String`, `PrintableString`, `IA5String`, `VisibleString`,
`NumericString`, `BMPString`, `UniversalString`, and others — all map to
`asn1::AsnString<tag>` and share a single string-handling runtime path.

### ENUMERATED values

A generated ENUMERATED type `E` derives from `asn1::EnumValue` and holds its items
as a plain inner `enum E::Enm`, so `E::item` names a value. `present()` returns the
`Enm` value and `value()` the number. Two values compare with `==` and `!=`, and a
value compares with an item in either operand order (`v == E::item`,
`E::item != v`). These are plain C++20 comparisons: there is one `operator==`
per shape and `!=` and the reversed order are rewritten from it, so clang's
`-Wambiguous-reversed-operator` stays silent.

### REAL values

REAL values in a schema may use `PLUS-INFINITY` and `MINUS-INFINITY` (X.680 §20.6) and
`realnumber` notation with a fraction, an exponent, or both: `2.5`, `1e-5`, `1.5E3`
(§11.9). Both may appear as value-range endpoints, as in
`REAL (MINUS-INFINITY <..< PLUS-INFINITY)`. A bare `1.` is not accepted, so that `1..2`
stays a range.

A REAL value is mantissa × base^exponent with base 2 or 10 (X.680 §20.5). Base-2 and
base-10 values are distinct values, even when they are numerically equal.
`asn1::Real` (Rust: `asn1cpp_wire::real::Real`) holds a value in one of three storage
classes:

| Storage | Holds | Produced by |
|---|---|---|
| `Double` | IEEE 754 double, base 2 (default, no allocation) | `Real{d}` / `Real::new(d)`, `set(d)`, BER binary values a double holds exactly, every XER value, JER numbers |
| `Binary` | base 2, arbitrary mantissa | BER binary values a double cannot hold: mantissas over 53 significant bits, exponents beyond the double range |
| `Decimal` | base 10, arbitrary digit string | BER decimal form, JER `{"base10Value": n}`, `Real::decimal(neg, digits, exp)` |

`value()` returns the double exactly for `Double` and the nearest double otherwise (±∞ or ±0
beyond the double range). `storage()`, `base()` and `exact()` (sign, mantissa, exponent)
expose the rest. `==` compares abstract values, so a `Decimal` never equals a `Double`;
`numerically_equal()` compares `value()`. Encoding follows the storage class:

- **BER/PER:** `Binary` uses the binary form normalized per X.690 §11.3.1. `Decimal` uses
  NR3 per §11.3.2 (`1456.E-2`, with exponent `+0` when zero). Both are valid CER/DER.
  `Double` keeps its usual binary form.
- **JER:** `Decimal` is written as `{"base10Value": 1456E-2}` (X.697 §23.4). Other values
  are a JSON number. When the type's JER-visible base constraint admits only 10, as in
  `REAL (WITH COMPONENTS { ..., base (10) })`, a `Decimal` is a bare JSON number and a
  JSON number decodes as `Decimal` (X.697 §23.1.4). The effective constraint follows
  X.697 §23.1.3: intersections intersect, unions unite, `EXCEPT` and extensible
  constraints are ignored. So `REAL (0 | WITH COMPONENTS { ..., base (10) })` counts as
  base 10 only.
- **XER:** `Decimal` is written as its exact digits (`1456E-2`). Other values are written as
  fixed-point text. An XER value always decodes as `Double`, as in asn1c, so a `Decimal` is
  exact through BER and JER but not back through XER.

The Rust `Real` is a struct with private fields: build one with `Real::new(f64)` or
`Real::from(f64)`, and read it with `value()` (it also derefs to `f64`).

BER decode (X.690 §8.5) accepts every encoding the standard defines:

- **Binary form (§8.5.7):**
  - bases 2, 8 and 16 (§8.5.7.2) and the scaling factor F;
  - all four exponent formats of §8.5.7.4, including format d (a length octet, then
    that many exponent octets);
  - unnormalized mantissas of any length (§8.5.7.5 NOTE 1).

  A value a double holds exactly is a `Double`, and any other is a `Binary`, kept exactly.
  `value()` rounds to the nearest double, ties to even, subnormals included. Exponents
  wider than 56 bits are a decode error.
- **Decimal form (§8.5.8):** ISO 6093 NR1, NR2 and NR3. Accepted: leading spaces, an
  optional sign, `.` or `,` as the decimal mark, and `E`/`e` before an optional signed
  exponent. NR2 requires a decimal mark, NR3 requires an exponent, and the mark is
  optional in NR3. The digits are kept exactly as a `Decimal`, and `value()` is the
  nearest double. Reserved NR codes, malformed text and exponents wider than 64 bits
  are decode errors.

A value-range constraint on a REAL type or member (X.680 §47.4) is checked by
`asn1::validate()` (C++) and `asn1cpp_wire::constraints::validate_real` (Rust), the same
fail-soft way as INTEGER ranges. Endpoints may be closed or open (`<`). `MIN`, `MAX` and
the infinities count as unbounded ends, and serial constraints such as `(-10..10)(0..5)`
intersect. NOT-A-NUMBER lies outside every range, so `(MINUS-INFINITY <..< PLUS-INFINITY)`
admits finite values only. An extensible range (`(0..1, ...)`) is never a violation.
`RandomFiller` draws only values inside the range. The range does not change any
encoding. A range written with a value reference that is not an integer leaves the
type unconstrained.

A REAL member may have a DEFAULT: a realnumber, an integer literal, `PLUS-INFINITY` or
`MINUS-INFINITY`. An absent member decodes as its default, and a member equal to its
default is not encoded. REAL equality is value identity: minus zero and plus zero
differ, and NOT-A-NUMBER equals itself, since X.690 §8.5.9 encodes each separately.
So `-0` in a member that defaults to `0` is still encoded. This applies to
`asn1::Real::operator==` and to Rust's `PartialEq` for `Real`.

A value beyond the double range decodes losslessly as `Binary` or `Decimal`, with
`value()` returning ±∞ or ±0. asn1c rejects such values instead (ERANGE). For every
encoding, both runtimes give the same storage class, the same double bit for bit, and the
same re-encoding. `tests/ber/test_real_ber.cpp` and the Rust `real.rs` tests share the
vector tables.

Malformed encodings are also decode errors:
- format d with a length of 0, or a truncated exponent;
- a special value (§8.5.9) with extra contents octets;
- a reserved special-value octet.

### Structured Types

**SEQUENCE** is a fixed-order list of named members, each with its own type. Members
may be OPTIONAL or carry a DEFAULT value. This is the workhorse of ASN.1 — most
real-world structures are SEQUENCES of SEQUENCES.

```asn1
Point ::= SEQUENCE {
    x  INTEGER,
    y  INTEGER,
    label  UTF8String  OPTIONAL
}
```

**SET** is like SEQUENCE but the wire order of members is not specified. The decoder
must accept them in any order. gambas-asn1 decodes SETs using the same tag-driven path
as SEQUENCE.

**SEQUENCE OF** is a variable-length homogeneous list. **SET OF** is the same without
order guarantee. Both map to `asn1::VectorSeqOf<T>` in generated code.

**CHOICE** is a discriminated union: exactly one alternative is present. The tag of the
encoded value identifies which alternative was chosen.

```asn1
Shape ::= CHOICE {
    circle   Circle,
    square   Square,
    polygon  Polygon
}
```

**ANY** holds a raw BER encoding whose type is not known at compile time. Used in
extensibility points and algorithm identifier parameters. Decoded as a verbatim byte
buffer (`asn1::AnyBer`).

### Tags and Tagging Modes

*(X.680 §30 — Tagging; X.690 §8.14 — BER tagging)*

Every ASN.1 type has a tag — a class and number that identify it on the wire. Universal
tags are standardised (INTEGER is `[UNIVERSAL 2]`, SEQUENCE is `[UNIVERSAL 16]`). Tag
classes are: UNIVERSAL (built-in types), APPLICATION (per-standard types),
CONTEXT-SPECIFIC (disambiguates members within a structure), and PRIVATE.

When a SEQUENCE has two OPTIONAL members of the same type, the decoder cannot tell them
apart by tag alone. ASN.1 resolves this with explicit or implicit tagging:

```asn1
Wrapper ::= SEQUENCE {
    first   [0] IMPLICIT UTF8String  OPTIONAL,
    second  [1] IMPLICIT UTF8String  OPTIONAL
}
```

**IMPLICIT tagging** replaces the original universal tag with the context tag. On the
wire, `first` encodes with tag `[0]` (0x80) instead of `UTF8String`'s `[UNIVERSAL 12]`
(0x0C). The decoder uses its knowledge of the schema to know that context tag 0 means a
UTF8String at this position. No additional bytes are spent.

**EXPLICIT tagging** wraps the original encoding in an outer TLV. The inner encoding is
preserved intact. `[0] EXPLICIT UTF8String` encodes as tag `[0]` (0xA0, constructed)
containing the full `UTF8String` TLV. This costs 2–4 extra bytes but is required when
the inner type is CHOICE, OPEN, or ANY — types whose own tag determines which
alternative is present and must be preserved.

A tag can also sit on a type assignment rather than on a member:
`TBool ::= [APPLICATION 1] BOOLEAN`. Every reference to `TBool`, whether it is a
SEQUENCE member, a CHOICE alternative or a SEQUENCE OF element, then encodes as
`[APPLICATION 1]` (`41 01 FF`), not `[UNIVERSAL 1]` (`01 01 FF`). On decode, both
runtimes accept only that tag (X.680 §31.2, X.690 §8.14). XER and JER are not affected:
`TBool` is still written as a BOOLEAN. The same holds for a CONTAINING type assignment
such as `TCont ::= [APPLICATION 5] OCTET STRING (CONTAINING Inner)`.

BER decode checks the identifier octets of every TLV against the expected tag
(X.690 §8.1.2): the PDU's own tag, each member's tag, and each SEQUENCE OF element's
tag. A TLV with any other tag is a decode error, also for SEQUENCE, SEQUENCE OF and
OCTET STRING values; it is never read as a value of the wrong type.

Tagging affects the schema as a design decision: once a type is deployed with a specific
tag, changing the tagging mode is a wire-format break. The extension marker (`...`) and
version brackets (`[[...]]`) in ASN.1 provide managed extensibility without breaking
existing decoders — unknown extension members are skipped by tag, not by position.

### Constraints

ASN.1 constraints restrict the set of valid values:

```asn1
SmallInt  ::= INTEGER (0..255)
ShortStr  ::= UTF8String (SIZE (1..64))
PortNum   ::= INTEGER (0..65535)
Digit     ::= IA5String (FROM ("0123456789"))
PrintOnly ::= UTF8String (FROM (UNIVERSAL 32 .. UNIVERSAL 126))
```

Constraints are compiled into `Constraints` structs in the descriptor tables. They are
used by the constraint validator and, for PER, determine the minimum number of bits
needed to encode a value. A `FROM` alphabet constraint restricts the character set of a
string type; the validator checks every character against the allowed set.

#### Contents constraints (`CONTAINING` / `ENCODED BY`)

*(X.682 §11)*

```asn1
Wrapper ::= SEQUENCE {
    cc   OCTET STRING (CONTAINING TS33128Payloads.CCPayload),
    blob OCTET STRING (CONTAINING Inner ENCODED BY { joint-iso-itu-t asn1(1) basic-encoding(1) })
}
```

All three X.682 §11.1 productions are parsed: `CONTAINING Type`, `ENCODED BY Value` and
`CONTAINING Type ENCODED BY Value`. The compiler checks that the contained type is
defined (module-qualified references included). It also checks that the constraint sits
on an OCTET STRING, or a BIT STRING without named bits (§11.3); anything else is an
error. Without `ENCODED BY`, the contents use the encoding rules of the enclosing octet
string (§11.4).

An `ENCODED BY` OID other than BER, CER, DER or unaligned/aligned PER gives a warning:
those contents stay raw bytes. An OID given as a value reference is not resolved for
this and also counts as unsupported.

#### Contained values

A *contained field* is an OCTET STRING whose bytes are the encoding of another type. It
comes from a contents constraint in the schema, or from a `--container-config` sidecar
for fields the schema leaves unconstrained. ETSI LI's
`EncryptionContainer.encryptedPayload`, for example, carries a BER `EncryptedPayload` but
says so only in a comment.

```json
{
  "container_fields": [
    {
      "module": "LI-PS-PDU",
      "type": "EncryptionContainer",
      "field": "encryptedPayload",
      "inner_type": "EncryptedPayload",
      "decoder": "zero_padding",
      "when": { "member": "encryptionType", "equals": "none" }
    }
  ]
}
```

Each entry names a direct member of a type assignment (`type` + `field`), in a module
given by `module` (name) or `module_oid` (dotted numbers; it wins over the name). Fields
inside anonymous nested types are reachable only through a contents constraint.

| Key | Values | Default |
|-----|--------|---------|
| `inner_type`, `inner_module` | the contained type | required without a contents constraint; must match it when there is one |
| `encoding` | `ber`, `der`, `cer`, `per`, `aper` | `ber` for sidecar fields; for a contents constraint, its `ENCODED BY` or else the outer encoding (X.682 §11.4) |
| `decode` | `eager`, `off` | `eager` |
| `decoder` | `plain`, `zero_padding`, `pkcs7`, `none`, or a name the application registers | `plain` |
| `when` | `{ "member": <sibling>, "equals": <value> }`; the sibling is ENUMERATED (identifier), INTEGER or BOOLEAN | always |
| `on_error` | `keep_raw`, `fail` | `keep_raw` |
| `xer`, `jer` | `hex`, `inline`, `inline_raw` | `hex` |

An entry for a field with a contents constraint changes only the options it sets. An
unknown module or field is a warning, and the entry is skipped. Malformed JSON, unknown
keys, bad values, a non-OCTET STRING field, a conflicting inner type and duplicate
entries are errors.

The ETSI LI example (`examples/sample.source.ETSI-LI-PS-PDU/container_fields.json`,
passed by its Makefile) declares the entry above. With it, one `PS_PDU` decode yields the
encryption container's raw bytes, which IntegrityCheck hashes are computed over, and the
decoded `EncryptedPayload`. The two TS 33.128 fields that carry a contents constraint
(`threeGPP33128DefinedCC`/`IRI`) need no entry.

The example's `nested-decoder` prints each PS-PDU as XER from that one decode.
`--xer-form hex|inline|inline_raw` sets `ContainedOptions::xer` for the output:

| `--xer-form` | Output |
|--------------|--------|
| `hex` (default) | `encryptedPayload` as hex, then the decoded `EncryptedPayload` as a separate document after `--- EncryptedPayload (N bytes, M zero-padded) ---`. Matches the asn1c nested decoder line for line. |
| `inline` | The `EncryptedPayload` inside `<encryptedPayload>`, no separate document. |
| `inline_raw` | As `inline`, plus `<!-- raw: HEX -->` with the original bytes, padding included. |

A payload that is not decoded (`encryptionType` other than `none`, or a decode failure)
stays hex in every form; its status and reason go to stderr.

`--list-contained` prints the merged result:

```
contained: LI-PS-PDU.EncryptionContainer.encryptedPayload -> LI-PS-PDU.EncryptedPayload source=config encoding=ber decode=eager decoder=zero_padding when=encryptionType==none(1) on_error=keep_raw xer=hex jer=hex
```

Both backends generate contained fields as a contained-value type:
`asn1::Containing<T>` in C++, `asn1cpp_wire::containing::Containing<T>` in Rust. The
inner type joins the `-pdu` reachable set. C++ generates no setters for these fields.

**Runtime (C++).** A contained field is stored as `asn1::Containing<T>`
(`<asn1cpp/types/Containing.hpp>`). It is an `OctetString` holding the raw bytes, plus the
decoded inner value:

| Member | Meaning |
|--------|---------|
| `bytes()`, `set(...)` | The raw bytes. `set` drops the inner value. |
| `status()` | `NotDecoded`, `Decoded`, `Skipped` (`decode: off`, a `when` mismatch, decoder `none`) or `Failed` |
| `error()` | Reason for `Skipped`/`Failed`; for `Decoded`, a warning (e.g. non-zero padding) |
| `value()`, `has_value()` | The inner value, or nullptr |
| `value_mut()`, `set_value(T)` | Change the inner value; it is then *dirty* |

The inner value is decoded during the outer BER or PER decode, after the enclosing
SEQUENCE/SET (or CHOICE) has decoded all its members, so a decoder can look at siblings.
A failed inner decode keeps the raw bytes and does not fail the outer decode, unless the
field is `on_error: fail`. On encode, the raw bytes are written unchanged, so a hash or
signature over them stays valid. Once the inner value is dirty, encode writes its
encoding instead, through the decoder's encode side (`pkcs7` pads). If that is not
possible, the encode fails: C++ reports `encode_failed()` on the writer or stream, Rust
returns an `EncodeError`. This happens when the decoder has no encode side (a decode-only
application decoder), the field uses `aper`, or the inner value itself does not encode. A
modified value is never written as its old bytes.

A field without `ENCODED BY` (`encoding` defaults to the outer encoding) holds
contents encoded under the same rules as the message around it (X.682 §11.4). The value
remembers which rules its raw bytes are in. If it is written under other rules, encode
re-derives the bytes from the inner value: for example, a BER-decoded record written as
PER, or a value read from inline XER/JER or made by the random filler (bytes derived as
BER) and then written as PER. Bytes stay as they are when the rules match, when the value
was not decoded, or when the bytes were set directly with `set(...)`. XER and JER carry such
a field's contents as BER.

Decoders are looked up by name in an `asn1::ContainedDecoders` registry
(`<asn1cpp/codec/ContainedDecoders.hpp>`). Built-ins:

| Name | Decode | Encode |
|------|--------|--------|
| `plain` | the bytes are exactly one value | the value's encoding |
| `zero_padding` | one value, then only 0x00 octets; a non-zero tail keeps the value with a warning | no padding |
| `pkcs7` | strip RFC 5652 §6.3 padding, then `plain` | pad to `pkcs7_block_size` (16) |
| `none` | never decodes | — |

An application adds its own decoder (for example one that decrypts first) or replaces a
built-in, and passes the registry with `asn1::ContainedOptions` on the reader or stream:

```cpp
asn1::ContainedDecoders reg;
reg.add("li_decrypt", [&](const asn1::ContainedDecodeArgs& a) {
    auto plain = decrypt(a.raw, a.outer);                 // a.outer: the enclosing value
    return asn1::ContainedDecoders::decode_value(a, plain);
});
asn1::ContainedOptions opts{&reg};
asn1::BerReader r{bytes};
r.set_contained(&opts);                                    // PerDecodeStream: same call
asn1::BerDecodeStream s{r};
asn1::BerCodec::instance().decode(s, PS_PDU::asn_DEF, &pdu);
```

`ContainedOptions::off = true` decodes no contained value at all.

Cost: contained fields are rare, so the codecs gate all of this on one flag of the
enclosing SEQUENCE/SET/CHOICE descriptor (`TypeDescriptor::has_contained`; Rust:
`SequenceSpec::contained_members`, `ChoiceSpec::has_contained`). A type without
contained fields pays one test at the end of decode and nothing per member. A type with
them walks its sorted `contained_members` list with a cursor, one compare per member.

**XER and JER.** A contained field has three output forms. The standards make hex and
inline *alternatives*, so in a conformant encoding the inline form replaces the hex:

| Form | XER | JER | Conformant |
|------|-----|-----|-----------|
| `hex` (default) | `<f>HEX</f>` | `"HEX"` | yes |
| `inline` | `<f><Inner>…</Inner></f>` (X.680 §22.4 XMLTypedValue) | `{"containing": …}` (X.697 §25.4) | yes for a contents constraint; an extension for a sidecar field |
| `inline_raw` | inline plus `<!-- raw: HEX -->` | `{"containing": …, "raw": "HEX"}` | no (extension) |

The form comes from the field's `xer`/`jer` setting. The C++ runtime can also override
it per stream with `ContainedOptions::xer`/`jer` on the XER/JER encode stream. If the
inner value is not decoded, the output falls back to hex.

Decoding accepts all three forms for every contained field. A hex value is decoded like
BER, after the enclosing SEQUENCE/CHOICE. An inline value becomes the inner value
directly, and its raw bytes are the inner value's encoding (the field's `encoding`; BER
by default). With `inline` the original bytes are therefore not available: padding, a
non-canonical encoding, or a hash over the bytes cannot be reproduced. `inline_raw` keeps
them, and its `raw` part is taken as the raw bytes.

**Runtime (Rust).** `asn1cpp_wire::containing::Containing<T>` has the same model.
It derefs to the raw `OctetString` and offers `bytes()`, `set_raw()`, `status()`,
`error()`, `value()`, `value_mut()` and `set_value()`. The built-in decoders are the
same. An application registry goes in `ContainedOptions { decoders: Some(reg), .. }`.
Every codec takes it on decode as `decode_pdu_with` (BER, PER, XER, JER) or through the
reader's `set_contained`, and on encode as `encode_pdu_with`, plus `encode_pdu_into_with`
for BER and PER. On encode, the registry's encode side re-derives a modified inner value,
for example with an application encoder that encrypts. `ContainedOptions::xer`/`jer`
override every field's XER/JER form. A decoder gets the enclosing value as
`ContainedDecodeArgs::outer` and calls `containing::decode_value` / `decode_value_from`
after its own transform.

---

## 6. BER, PER, XER and Other Encoding Flavours

### Basic Encoding Rules (BER)

*(X.690 §8 — BER encoding rules)*

BER encodes every value as a Tag-Length-Value triple. The tag identifies the type, the
length gives the number of value bytes, and the value bytes encode the content according
to type-specific rules. Nested structures encode as constructed TLVs whose value bytes
are themselves TLVs.

**Wire example.** `INTEGER 42` encodes as three bytes:

```
02  01  2A
│   │   └─ value: 42 (0x2A)
│   └───── length: 1 byte
└───────── tag: UNIVERSAL 2, primitive (INTEGER)
```

A `SEQUENCE { a INTEGER, b UTF8String }` with `a=1`, `b="Hi"` encodes as:

```
30 09          -- tag 0x30: UNIVERSAL 16, constructed (SEQUENCE); length 9
  02 01 01     -- tag 0x02: UNIVERSAL  2, primitive (INTEGER);   length 1; value 1
  0C 02 48 69  -- tag 0x0C: UNIVERSAL 12, primitive (UTF8String); length 2; "Hi"
```

BER is self-describing: a decoder that does not know the schema can still traverse the
structure, read tag numbers and lengths, and skip unknown fields. This makes it robust
to schema evolution.

The price is space: every field carries a tag (1–4 bytes) and a length (1–5 bytes)
regardless of how small the value is. A BOOLEAN takes 3 bytes. A single-byte INTEGER
takes 3 bytes.

Distinguished Encoding Rules (DER) are a canonical subset of BER: lengths always use
the shortest encoding, constructed strings are forbidden, SET members are sorted by tag.
DER is used wherever byte-for-byte reproducibility matters — chiefly in digital
signatures (X.690 §11).

### Packed Encoding Rules (PER / UPER / APER)

*(X.691 — PER encoding rules)*

PER dispenses with self-description entirely. The encoder and decoder must both know the
schema; the encoded bits carry only the minimum information needed to reconstruct the
value.

A constrained `INTEGER (0..7)` needs 3 bits. A BOOLEAN needs 1 bit. A SEQUENCE with
three OPTIONAL members has a 3-bit preamble bitmap before any values. CHOICE alternatives
are identified by an index into the alternative list, encoded in ⌈log₂(n)⌉ bits.

**PER imposes requirements on the schema itself.** For a type to have an efficient PER
encoding, it should carry constraints: an `INTEGER` without bounds must use an
unconstrained encoding (length-prefixed, variable width). A `SEQUENCE OF` without a
`SIZE` constraint requires a length prefix before each element count. Well-constrained
schemas — where every variable-length type has explicit bounds — produce the most compact
PER output. The 3GPP RRC schema is an example: almost every field carries constraints,
and the resulting UPER encodings are extremely dense.

The extension marker (`...`) also has a PER effect. A SEQUENCE with `...` writes a 1-bit
extension flag before the root member preamble. If any extension members are present, a
presence bitmap follows; its length is encoded as a normally small number (X.691 §12.2.6),
and each present extension is wrapped as an open-type (length-prefixed octet string).
An extension-free encoding sets the flag to 0 and encodes only root members.

When a decoder encounters an extension member whose index exceeds the number of known
alternatives in its schema (schema version skew), it skips the open-type payload by
reading and discarding its length-prefixed bytes. This preserves forward compatibility:
an older receiver can always decode a newer sender's message as long as the root members
are unchanged. After decoding, `PerDecodeStream::skipped_extensions()` returns the number
of open-type fields that were skipped; a nonzero value indicates the stream contained a
newer schema version than the decoder's descriptor tables.

A `BIT STRING` defined with named bits (`BIT STRING { a(0), b(1), c(2) }`) gives its
trailing 0 bits no meaning (X.680 §22.7), so PER sends such a value with its trailing 0
bits removed, then padded with 0 bits up to the `SIZE` lower bound when there is one
(X.691 §15.2, §15.3). `'01000000'B` goes out as the 2 bits `01` in an unconstrained or
`SIZE (2..8)` type, and as all 8 bits in `SIZE (8)`; decoding returns that transmitted
form. This applies to inline members, named types and aliases of them, in both runtimes.
For the same reason the `SIZE` check on such a type only looks at the bits up to the last
1 bit. A `BIT STRING` without named bits is sent at its own length. BER keeps the value
as given (X.690 §8.6.2.4 allows either).

Unaligned PER (UPER) packs values at bit boundaries with no byte alignment. Aligned PER
(APER) byte-aligns certain constructs. 3GPP uses UPER for radio interface protocols.

The payoff is density: a typical 3GPP RRC message that takes 50 bytes in BER takes 5–10
bytes in UPER.

**PER encode-time constraint validation.** `PerEncodeStream` rejects values that PER
cannot encode: a `FROM` alphabet constraint means every character of a string must come
from the declared set; a non-extensible `SIZE(lower..upper)` constraint with an upper bound
below 64K means the length of a string, OCTET STRING or BIT STRING, or the element count of
a SEQUENCE OF / SET OF, must fall within the declared range (including fixed-size `SIZE(n)`
where lower equals upper), since the constrained length of X.691 §10.9.4.1 cannot represent
any other count. An extensible SIZE takes the extension form instead; with a larger upper
bound the length is written in the general form and the violation is only reported by
validation. Violations set an internal flag rather than throwing
(Rust returns an `EncodeError`):

```cpp
std::vector<uint8_t> buf;
asn1::PerEncodeStream s{buf};
asn1::PerCodec::instance().encode(s, MyType::asn_DEF, &val);
if (s.encode_failed()) {
    // value violates a PER constraint (FROM alphabet or SIZE)
}
```

`encode_failed()` returns true if any member violated its constraint during encoding.
BER and XER encoders do not enforce PER constraints; they accept any structurally valid
value.

### XML Encoding Rules (XER)

*(X.693 — XER encoding rules)*

XER transcodes ASN.1 values to XML. Each type has a canonical XML representation:
SEQUENCE becomes a parent element whose child elements are the member values; CHOICE
becomes a single child element named after the chosen alternative; OCTET STRING becomes
uppercase hex pairs; BIT STRING becomes a binary string of `0` and `1` characters
(xmlbstring per X.680 §21); BOOLEAN becomes an empty element (`<true/>` or `<false/>`).

**Non-standard extensions — lenient decode mode**

Some encoders (notably asn1c) produce XER that deviates from BASIC-XER (X.693 §8):

| Field | Standard BASIC-XER | Non-standard (lenient mode) |
|-------|--------------------|-----------------------------|
| BOOLEAN | `<true/>` / `<false/>` empty elements | Text content `true` / `false` (valid in EXTENDED-XER §10, not BASIC-XER) |
| BIT STRING | Binary `0`/`1` characters (xmlbstring, X.680 §21) | Hex pairs `AABBCC…` (no grammar production in the standard — asn1c extension) |

To decode XER produced by such encoders, pass `XerDecodeMode::Lenient` to
`XerDecodeStream`:

```cpp
std::string xml = read_file("cert.xer");
Certificate cert{};
// lenient: accepts text BOOLEAN and hex BIT STRING
asn1::XerDecodeStream xs{xml, asn1::XerDecodeMode::Lenient};
asn1::XerCodec::instance().decode(xs, Certificate::asn_DEF, &cert);
```

The default is `XerDecodeMode::Strict`, which rejects both non-standard forms.

**OCTET STRING / Base64** is a separate mechanism: Base64 encoding is a compile-time
annotation (`XerEncoding::Base64` on the `TypeDescriptor`, set via the `BASE64`
encoding instruction in the schema). It is always active for annotated types and is
independent of `XerDecodeMode`.

XER can be used wherever XML interoperability is required. Some ETSI standards mandate
XER for management interfaces; NETCONF (RFC 6241) uses YANG but many legacy network
management protocols carry ASN.1 XER payloads. It is also well-suited for diagnostics
and logging — an existing XML toolchain (SAX parser, XSLT, XPath) can process XER
output without any ASN.1-specific tool.

XER is not compact — the XER encoding of a typical ETSI record is 10–20× larger than
its BER encoding — but it is human-readable and toolchain-compatible.

### JSON Encoding Rules (JER)

JER (X.697) maps ASN.1 to JSON. Both runtimes implement it (C++ `JerCodec`,
Rust `asn1cpp_wire::jer::object`), and C++ and Rust write identical text.

A REAL is a JSON number that converts back to exactly the same double. It is
the shortest such digit string, in plain decimal notation when the decimal
exponent is in [-4, 15) (`-338203.95104146993`, `0.0001`, `100`) and as
`d.dddE<exp>` otherwise (`1E-5`, `1.7976931348623157E308`). The special
values are the strings `"NaN"`, `"INF"`, `"-INF"` and `"-0"` (X.697 §23).
The decoder accepts any JSON number notation. It also accepts the base-10 object form
`{"base10Value": 14}` (X.697 §23.4), which it decodes exactly as a `Decimal`. Any other
member, or a value that is not a JSON number, is a decode error.

A BIT STRING whose SIZE is fixed (a single value, not extensible) is a bare
hex string, `"2EFE20"` for `BIT STRING (SIZE (20))`; the length comes from
the type. Every other BIT STRING is an object, `{"value":"2EFE20","length":20}`.
A value whose length breaks its fixed SIZE keeps the object form, so the
length is not lost.

The decoder accepts every JSON string escape (RFC 8259 §7) in every JER string,
member and alternative names included (X.697 §23.4 NOTE): `\"`, `\\`, `\/`,
`\b`, `\f`, `\n`, `\r`, `\t` and `\uXXXX`. A `\u` escape is a UTF-16 code unit;
a surrogate pair (`😀`) combines into one code point, stored as
UTF-8. A lone surrogate, a `\u` with fewer than four hex digits, or any other
character after a backslash is a decode error. The encoder escapes `"`, `\`
and control characters below U+0020 (as `\u00XX`).

### Encoding Rule Comparison

| Property | BER/DER | UPER | XER |
|----------|---------|------|-----|
| Self-describing | Yes | No | Yes |
| Requires schema to decode | No | Yes | No |
| Size | Medium | Minimum | Large |
| Human readable | No | No | Yes |
| Used for | General, PKI, telecom | Radio interfaces, 3GPP | Logging, diagnostics |
| asn1cpp status | Complete | Complete | Complete |

---

## 7. Your First ASN.1 Schema

Let us write a simple schema from scratch. We will model a contact book entry.

A working copy of this schema is kept in `examples/contact-book/contact.asn1`.
**Note to authors:** if you modify the schema in this section, update that file too.

Create `examples/contact-book/contact.asn1`:

```asn1
ContactBook DEFINITIONS IMPLICIT TAGS ::= BEGIN

    PhoneNumber ::= SEQUENCE {
        countryCode  INTEGER (1..999),
        number       NumericString (SIZE (4..15))
    }

    Address ::= SEQUENCE {
        street   UTF8String (SIZE (1..100)),
        city     UTF8String (SIZE (1..50)),
        country  PrintableString (SIZE (2))
    }

    Contact ::= SEQUENCE {
        name     UTF8String (SIZE (1..100)),
        email    IA5String (SIZE (0..254))  OPTIONAL,
        phone    [0] PhoneNumber            OPTIONAL,
        address  [1] Address                OPTIONAL
    }

    ContactList ::= SEQUENCE OF Contact

END
```

This schema defines four types. `Contact` has one mandatory field (`name`) and three
optional fields. `ContactList` is an unbounded list of contacts. `phone` and `address`
need the explicit `[0]`/`[1]` tags: both are OPTIONAL SEQUENCE-typed fields, so without a
tag of their own they'd both carry the same UNIVERSAL SEQUENCE tag — the decoder would
have no way to tell, from the wire tag alone, which optional field (if either) is present.

Generate C++ code:

```bash
./build/compiler/asn1cpp examples/contact-book/contact.asn1 -o generated/
```

The compiler emits one `.hpp` + `.cpp` pair per type:

```
generated/
  PhoneNumber.hpp   PhoneNumber.cpp   -- struct PhoneNumber + asn_DEF_PhoneNumber
  Address.hpp       Address.cpp       -- struct Address + asn_DEF_Address
  Contact.hpp       Contact.cpp       -- struct Contact + asn_DEF_Contact
  ContactList.hpp   ContactList.cpp   -- struct ContactList + asn_DEF_ContactList
```

Each `.hpp` declares the type and its descriptor. Each `.cpp` defines the static
descriptor tables that the runtime uses to drive encoding and decoding.

---

## 8. Your First Encoder and Decoder

Link your application against the generated `.cpp` files and the runtime library:

```cmake
add_executable(myapp main.cpp
    generated/PhoneNumber.cpp
    generated/Address.cpp
    generated/Contact.cpp
    generated/ContactList.cpp
)
target_include_directories(myapp PRIVATE generated/)
target_link_libraries(myapp PRIVATE asn1cpp_runtime)
```

### Encoding

```cpp
#include "Contact.hpp"
#include "PhoneNumber.hpp"
#include <asn1cpp/codec/BerCodec.hpp>
#include <fstream>

int main() {
    Contact c{};
    c.set_name(asn1::Utf8String("Alice"));

    // OPTIONAL members are std::unique_ptr — construct in place
    c.email = std::make_unique<asn1::Ia5String>("alice@example.com");

    // Encode to BER
    std::vector<uint8_t> buf;
    asn1::BerWriter w{buf};
    asn1::BerEncodeStream s{w};
    asn1::BerCodec::instance().encode(s, Contact::asn_DEF, &c);

    // Write to file
    std::ofstream f("alice.ber", std::ios::binary);
    f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
}
```

### Decoding

```cpp
#include "Contact.hpp"
#include <asn1cpp/codec/BerCodec.hpp>
#include <fstream>
#include <vector>

int main() {
    // Read from file
    std::ifstream f("alice.ber", std::ios::binary);
    std::vector<uint8_t> buf(std::istreambuf_iterator<char>(f), {});

    Contact c{};
    asn1::BerReader reader{buf};
    asn1::BerDecodeStream s{reader};
    auto result = asn1::BerCodec::instance().decode(s, Contact::asn_DEF, &c);
    if (!result) {
        std::cerr << "Decode error: " << result.error().message << "\n";
        return 1;
    }

    std::cout << "Name: " << std::string(c.name) << "\n";
    if (c.email)
        std::cout << "Email: " << std::string(*c.email) << "\n";
}
```

### XER (Human-readable) Output

```cpp
#include <asn1cpp/codec/XerCodec.hpp>

asn1::XerEncodeStream xs{std::cout};
asn1::XerCodec::instance().encode(xs, Contact::asn_DEF, &c);
```

Output:

```xml
<Contact>
  <name>Alice</name>
  <email>alice@example.com</email>
</Contact>
```

### Constraint Validation

In Debug builds, constraint validation runs automatically on encode and decode.
Violations increment a counter and (optionally) record a path:

```cpp
#include <asn1cpp/Validate.hpp>

asn1::ValidationReportScope report;
Contact bad{};
bad.set_name("");  // violates SIZE (1..100)
asn1::BerCodec::instance().encode(buf, asn_DEF_Contact, &bad);

for (auto& fail : report.failures())
    std::cerr << fail.path << ": " << fail.type_name << "\n";
```

### Error Handling

Neither runtime aborts the process on anything a caller can trigger. A
record the codec cannot handle fails that one encode or decode; the
process keeps running and the next record is unaffected.

**Decode** returns an error in both runtimes: C++ `ICodec::decode` returns
`Expected<void, DecodeError>`, Rust `<codec>::object::decode_pdu` returns
`Result<T, DecodeError>` (PER: `per::reader::DecodeError`).

**Encode** reports a failure the caller must check:

| Runtime | How encode failure is reported |
|---------|-------------------------------|
| C++ | `encode_failed()` on the stream after `encode`: `BerEncodeStream` (via `BerWriter`), `XerEncodeStream`, `JerEncodeStream`, `PerEncodeStream`; nested values share the flag of the stream the caller passed |
| Rust | `ber`/`xer`/`jer`/`per::object::encode_pdu` return `Result<_, EncodeError>`; `encode_pdu_into` returns `Result<(), EncodeError>` and leaves a partial record in the buffer, to be discarded |

Causes of a per-record error:

- **Malformed input** — truncated or inconsistent TLVs, wrong tags, bad XML/JSON (decode).
- **Input nested deeper than 256 constructed levels** — a self-referential
  type (X.680 §29) lets an input nest without bound; every decoder in both
  runtimes stops at 256 SEQUENCE/SET/CHOICE/SEQUENCE OF levels with
  `nesting deeper than 256 levels` instead of exhausting the stack
  (C++ `kMaxDecodeDepth`, `codec/DecodeDepth.hpp`; Rust
  `nesting::MAX_DECODE_DEPTH`). Levels are counted, not recursion
  cycles. The count lives in the decoder's own reader, so concurrent
  decodes never share it.
- **A schema construct the Rust runtime does not support** — e.g. an
  untagged `ANY` between other members, which has no tag to detect it by.
  Code generation still emits the type; any encode or decode that reaches
  the member fails with `member '<name>' not supported: <reason>`
  (`alternative '<name>' not supported` for a CHOICE alternative).
- **A primitive kind a Rust codec leg has no form for** — XER for
  `ArbitraryInteger` and `ANY`, JER for `ArbitraryInteger`, PER for
  `BigInteger`/`ArbitraryInteger` (`XER encoding not supported for ANY`, ...).
  Code generation does not select these storage kinds today; the errors
  guard direct use of the runtime types.
- **A type with no codec** — a descriptor whose kind lands on a codec's
  fallback dispatch slot (or has no direct handler): C++ encode sets
  `encode_failed()`, decode returns `<Codec>: unsupported: <type>`.
- **A CHOICE with no alternative to encode** — in C++ a CHOICE whose
  `_present` is 0 (default-constructed, or an unknown extension skipped on
  decode) fails BER/XER/JER/PER encode with `CHOICE <name>: no alternative
  selected`. A Rust extensible CHOICE
  holding an alternative the schema does not define (`UnknownExtension`,
  kept on decode, X.680 §29.6) re-encodes in BER (the captured TLV is
  replayed) but fails XER/JER/PER encode with `CHOICE <name>: no
  alternative selected`.
- **A PER constraint violation** — a character string outside its SIZE or
  permitted alphabet cannot be represented in PER, so PER encode fails
  (`string length violates SIZE constraint`, `character not in FROM alphabet`, ...).
  BER/XER/JER still encode such a value and only count the violation (see
  Constraint Validation above).

Each C++ encode failure is traced (with the reason) under `ASN1CPP_DEBUG`
bit `0x10` (BER), `0x04` (XER and JER) or `0x08` (PER).

Both runtimes' decoders are fuzzed by `validation-tools/xval_sweep/xval_sweep.py
--fuzz`: for every curated target it feeds BER corrupted by randgen's
BerCorruptor and mutated PER/XER/JER records to every C++ and Rust decoder,
and fails only on a crash (signal, abort, Rust panic, hang); the xval Rust
tools keep overflow checks on for this. ctest runs `fuzz_ber` (C++) and
`rust_fuzz_smoke` (Rust) as fixed-seed smoke tests.

The cross-validation tools (`ber-to-xer`, `xer-to-ber`, ...) print one line
per failed record (`BER decode failed record #N ...`, `XER encode failed
record #N ...`) and exit 1; a panic, abort or signal is always a bug.

### Traversing a Decoded Object by Type

`TypedVisitor` walks a fully-decoded object tree once and fires a callback for
each node of a registered type — no matter where in the tree it sits, and
without a second decode or a manual cast. Register one or more types; each match
delivers a typed `const T&`.

Each callback is a lambda that **captures the surrounding (outer) scope**, so it
collects results straight into your own container — no global state, no return
plumbing through the walk. Capture by reference (`[&]`) to accumulate:

```cpp
#include <asn1cpp/codec/TypedVisitor.hpp>

PS_PDU pdu = /* ...decoded... */;

std::vector<const CCPayload*> cc_units;   // collector in the outer scope
int location_count = 0;

asn1::TypedVisitor v;
v.on<CCPayload>([&](const CCPayload& cc) {         // [&] captures cc_units
    cc_units.push_back(&cc);                       // cc.payloadDirection,
    return asn1::VisitControl::Continue;           // cc.timeStamp, cc.cCContents
});                                                //   are directly usable
v.on<Location>([&](const Location& loc) {          // [&] captures location_count
    ++location_count;
    return asn1::VisitControl::Continue;           // or SkipChildren / Stop
});
v.visit(pdu);   // single pass, both callbacks fire in document order
// cc_units and location_count are now populated.
```

The collected pointers stay valid as long as `pdu` lives (the walk hands out
references into the object, it never copies). Matching is by descriptor identity
(`&T::asn_DEF`). The walk descends SEQUENCE, SET, CHOICE (active alternative
only), and SEQUENCE OF / SET OF elements — including through recursively-typed
schemas. A matched node is still descended into unless the callback returns
`SkipChildren`; `Stop` aborts the whole walk.

A `TypedVisitor` holds no per-walk state, so once all callbacks are registered
it may be reused across many objects — and shared read-only across threads to
walk different objects concurrently.

`TypedMutator` is the mutable sibling: callbacks receive `T&` and may modify
fields in place, so you can find-and-edit (e.g. redact every matching field)
then re-encode the object.

```cpp
asn1::TypedMutator m;
m.on<Location>([](Location& loc) {
    loc = Location{};                // redact in place
    return asn1::VisitControl::Continue;
});
m.visit(pdu);
```

---

## 9. gambas-asn1 CLI Reference

### Compiler

```
asn1cpp [options] file.asn1 [file2.asn1 ...]
```

Reads one or more ASN.1 module files, resolves cross-module references, and generates
one `.hpp` + `.cpp` pair per type in the output directory.

**Options:**

| Flag | Effect |
|------|--------|
| `-h`, `--help` | Print option summary and exit. |
| `-E` | Parse only — skip semantic analysis and code generation. Exit 0 on parse success. Useful for validating syntax without resolving imports. |
| `-o <dir>` | Output directory (default: `generated`; ignored with `-E`) |
| `-fallow-newer-modules` | Accept module version mismatches silently |
| `-fbless-SIZE` | **(Non-standard)** Accept `SIZE()` constraints on `INTEGER` and `ENUMERATED`. X.680 §47.5.2 forbids this; the constraint is silently ignored during code generation. Matches asn1c's `-fbless-SIZE` extension for byte-width hints in legacy schemas. |
| `--integer-type=<kind>` | Override default integer storage kind. `int64` (default) — signed 64-bit; `uint64` — unsigned 64-bit; `int128` and `arbitrary` are reserved (emit a warning and fall back to `int64`). Storage is otherwise auto-selected from constraint range. |
| `-pdu=<TypeName>` | Limit generation to `<TypeName>` and all types reachable from it (transitive BFS through TypeRef edges). May be specified multiple times. `-pdu=all` generates all types (same as omitting the flag). Note: types embedded as `OCTET STRING` bytes (two-level nested BER, e.g. `EncryptedPayload` inside `PS-PDU`) are not TypeRef dependencies and must be listed as separate `-pdu=` roots, unless the field is a [contained field](#contained-values): its inner type is reachable (C++ backend). |
| `--target=<lang>` | Output language: `cpp` (default), `rust` (**WIP**, gambas-asn1#214) or `java` (**WIP**: one `.java` file per type; constructs not emitted yet stop generation with `error: emit_<construct>: not implemented for this backend`). |
| `--package=<name>` | `--target=java` only: the Java package every generated class declares (e.g. `com.example.asn1`). Default: the unnamed package. Files are written flat into `-o <dir>`; point `-o` at the matching source directory. `-fprefix` is rejected with `--target=java`. |
| `--container-config=<file>` | JSON sidecar naming OCTET STRING fields that hold the encoding of another type, and how to decode them. See [Contained values](#contained-values). |
| `--list-contained` | Print every contained field (contents constraints and sidecar entries, merged) with its settings, then exit without generating code. |

### Comparison with asn1c CLI

The following table maps asn1c flags to gambas-asn1 equivalents or notes the gap.
Open issues are linked for gaps that have been prioritised for implementation.

| asn1c flag | gambas-asn1 equivalent | Status |
|------------|----------------------|--------|
| `-o <dir>` | `-o <dir>` | Supported |
| `-fallow-newer-modules` | `-fallow-newer-modules` | Supported |
| `-fbless-SIZE` | `-fbless-SIZE` | Supported (non-standard; SIZE on INTEGER/ENUMERATED silently ignored) |
| `-pdu={all\|auto\|Type}` | `-pdu=<TypeName>` (may be repeated; `-pdu=all` = generate all) | Supported (auto not implemented — treated as all) |
| `-flong-size=32\|64` | — | [Issue #15](https://github.com/Schramp/gambas-asn1/issues/15) |
| `-fprefix=<prefix>` | `-fprefix=<ns>` (wraps generated types in C++ namespace `ns`) | Supported (asn1c compat alias; asn1c uses name-mangling, gambas-asn1 uses `namespace`) |
| `-fno-constraints` | `ASN1CPP_VALIDATE=0` at runtime | Runtime flag only |
| `-fno-include-deps` | — | Not applicable (C++ `#include` is explicit) |
| `-fwide-types` | — | UInteger auto-selected by constraint range |
| `-finteger-native-type=<mode>` | `--integer-type=int64\|uint64` | Override via CLI flag; auto-selected from range by default |
| `-E` (print parse tree) | `-E` | Supported (parse-only, skip sema + codegen) |
| `-no-gen-BER/XER/UPER` | — | Not applicable; all codecs are in the runtime |
| `-gen-autotools` | — | Not applicable; CMake is the build system |
| `-Werror` | — | Not implemented |

### Runtime Environment Variables

Set before running any binary linked against `libasn1cpp_runtime`:

| Variable | Effect |
|----------|--------|
| `ASN1CPP_DEBUG=<hex>` | Enable runtime trace flags (see table below) |
| `ASN1CPP_VALIDATE=0` | Disable constraint validation globally |

**Debug trace flags** (bitmask):

| Bit | Flag | What it traces |
|-----|------|---------------|
| `0x01` | `DBG_BER_CHOICE` | CHOICE tag misses — type name, peek tag, all alternative tags |
| `0x02` | `DBG_BER_SEQ` | SEQUENCE EXPLICIT wrap/unwrap — outer tag + first byte |
| `0x08` | `DBG_PER` | PER bit-level ops — every `put_bits`/`get_bits` with offset and value |
| `0x10` | `DBG_BER_WRITE` | BER encode — member name, tag, EXPLICIT/IMPLICIT, byte count |
| `0x40` | `DBG_VALIDATE_TRACE` | Constraint violations — type name, delta, codec (all encodings) |

```bash
# Trace BER encoding:
ASN1CPP_DEBUG=0x10 ./my-encoder input.ber

# Trace CHOICE dispatch during decode:
ASN1CPP_DEBUG=0x01 ./my-decoder input.ber

# Enable all:
ASN1CPP_DEBUG=0xff ./my-tool input.ber
```

#### Validation output vs. validation reporting

Constraint failures have two independent channels:

| Channel | Controlled by | Purpose |
|---------|--------------|---------|
| **Counter** (`validate_fail_count`) | always active when `ASN1CPP_VALIDATE=1` | machine-readable; poll after encode/decode to detect violations |
| **Report** (`ValidationReport`) | `ASN1CPP_VALIDATE_REPORT=1` + `ValidationReportScope` | structured per-failure records with type name, delta, path, and encode/decode direction; used by application code |
| **stderr trace** | `ASN1CPP_DEBUG=0x40` (`DBG_VALIDATE_TRACE`) | human-readable line per failure; includes type name, delta, codec tag, and (for BER) the ASN.1 tag class+number; for debugging only |

Validation failures are **silent on output** unless `DBG_VALIDATE_TRACE` is set.
`record_validate_fail` and `bump_validate_fail` always fire regardless of debug flags.

### Validation API

```cpp
#include <asn1cpp/Validation.hpp>

// Encode with strict validation (returns false if any constraint violated):
bool ok = asn1::encode_validated(codec, buf, asn_DEF_MyType, &obj,
                                 asn1::ValidationPolicy::Strict);

// Decode with strict validation (returns DecodeError if constraint violated):
auto result = asn1::decode_validated(codec, stream, asn_DEF_MyType, &obj,
                                     asn1::ValidationPolicy::Strict);
```

---

## 10. Design Philosophy

### High Performance Without Compromise

gambas-asn1 is designed for throughput. The target workloads — ETSI lawful interception
processing, RRC message parsing — involve millions of records per hour, often in
single-threaded pipelines. Performance is not an afterthought.

Key design decisions that serve performance:

**No heap allocation in the encode hot path.** `BerWriter::write_constructed` uses a
reserve-and-patch strategy: it reserves space for the length field in the flat output
buffer, writes the nested content, then patches the length in place. No temporary
`vector` is allocated per nesting level. For a PS-PDU with 20 nesting levels, this
eliminates 20 heap allocations per record.

**Stack buffers for small variable-length data.** OID arc encoding and decoding use
fixed-size stack buffers (20 bytes for encoding, 16 elements for decoding) instead of
heap vectors. Realistic OIDs fit entirely on the stack.

**Table-driven dispatch, not virtual functions.** The runtime dispatches on
`TypeDescriptor` tables, not virtual function tables. A SEQUENCE encode pass iterates
`asn_MBR_T[]` directly. There is no polymorphic overhead per member.

**No generated codec logic.** Generated files contain only data tables. The codec
logic is compiled once into the runtime library, not instantiated per type. A schema
with 200 types does not produce 200 copies of SEQUENCE encode logic.

### asn1c Drop-in Replacement (Architecture, Not ABI)

gambas-asn1 is not a wrapper around asn1c. It generates C++ directly from the ASN.1
source, with no dependency on asn1c-generated headers at runtime.

However, it is designed as a conceptual drop-in: the same ASN.1 schemas that asn1c
compiles, gambas-asn1 also compiles. The descriptor table structure mirrors asn1c's
`asn_TYPE_descriptor_t` family closely enough that a developer familiar with asn1c's
output can read gambas-asn1's generated code without confusion.

### Cross-Validation and Round-Trip Testing

asn1c is the ground truth. Any divergence between asn1c output and gambas-asn1 output
is presumed a gambas-asn1 bug until proven otherwise.

The primary correctness tool is `compare_random.py` (in the umbrella validation tools,
not part of the gambas-asn1 repository itself). For each run it:

1. Generates N random records using gambas-asn1's `RandomFiller` — a type-aware random
   data generator that respects constraints and produces valid ASN.1 object graphs.
2. Encodes each record to BER with gambas-asn1.
3. Decodes that BER with gambas-asn1; re-encodes; checks BER-roundtrip identity.
4. Encodes to XER with gambas-asn1.
5. Feeds the BER to asn1c's `ber-to-xer` converter.
6. Compares the XER outputs byte-for-byte.

Each record is put through 11 checks (encode, decode, roundtrip, XER match, and
combinations). Running four seeds × 10 records = 440 records total, 4,840 assertions.
A failure names the seed, record index, and check that failed — narrowing the bug to
a specific type within seconds.

`RandomFiller` is deterministic (seed-controlled) and schema-aware: it fills required
members, randomly includes optional members, and respects SIZE and value constraints.
A [contained field](#contained-values) gets a random inner value, encoded through the
field's decoder (`pkcs7` pads; `zero_padding` adds 0–15 zero octets), so the nested
decode is exercised too. Corrupted-record variants (`BerCorruptor`) test that the decoder never crashes or
asserts on malformed input.

### Fully Table-Based: Minimal Generated Code

The fundamental principle is that generated files are data, not code. No `switch`
statements. No inline encode/decode logic. No type-specific codec helpers.

The benefit is proportional to schema size. A schema with 300 types generates 300 ×
(a few hundred lines of tables). The runtime is compiled once. Adding a new codec rule —
say, strict DER ordering — means changing one file in the runtime, not touching 300
generated files.

### Limitations

#### Owning value types — decode copies, objects are self-contained

Every leaf type owns its data: `OctetString` and the restricted string types hold a
`std::string`, `Integer` holds an `int64_t`, and generated SEQUENCE/CHOICE structs embed
these by value. Decoding a primitive therefore **copies** its value bytes out of the input
buffer into the object's own storage (e.g. `OctetString::set()` does `bytes_.assign(...)`).

This is a deliberate choice, not an oversight. The payoff is a simple, safe lifetime
contract: **a decoded object is fully self-contained and outlives the buffer it was decoded
from.** You can free or reuse the input immediately after `decode()` returns; the object
keeps working. That is what makes streaming loops trivial — e.g. `PspduStream` decodes each
PDU into a reused byte buffer, and the decoded object remains valid because it copied
everything it needs. Accessors like `OctetString::bytes()` then return a zero-copy
`std::span` **view into the owned storage**, so reading is free; the copy happened once, at
decode time.

The cost is that decode is copy- and allocation-heavy: one `std::string` per string/octet
field per object. For a value nested inside an encryption container this happens twice — the
container's `encryptedPayload` is copied on the outer decode, and the inner value again on the
inner decode. At current throughput (hundreds of MB/s) this is not the bottleneck, but it is
the reason decode dominates the profile.

#### Not implemented: borrowing decode (view-backed leaves)

When the caller can guarantee the input buffer outlives the decoded object — as
`etsi-pcap` can — those copies are avoidable. That path is **not implemented**. Three shapes
were considered:

- **Full shadow / ownership-templated types** — a parallel `…View` family (or every generated
  type templated on an ownership policy). Rejected: it forks both the codec and the generated
  code into two families for a niche gain.
- **Projection / cursor (available today)** — `BerProjection` and `BerCursor` sidestep the
  issue by never building owning objects: they hand back `std::span`s into the frame on demand,
  zero-copy and zero-allocation. The trade-off is navigation by path/tag instead of typed field
  access. This is the supported zero-copy route for hot scan/extract paths.
- **Hybrid owning-or-view leaves (the plausible future option)** — give only the relevant leaf
  types (OCTET STRING, the large string types, `ANY`) an internal "owned `std::string` *or*
  borrowed `span`" mode, selected by a decode flag; scalars and generated code stay unchanged,
  and `bytes()` returns a span either way. This would delete the decode copies (and, more
  significantly, the per-field allocations). It is non-trivial because: the lifetime contract
  inverts (the whole object then borrows from the frame, needing enforcement or a debug guard);
  constructed/segmented BER strings are not contiguous and must fall back to owning; and a
  borrowed value is read-only until a `set()` transitions it to owned. Whether it is worth the
  complexity is gated on measuring how much of decode time is allocation versus traversal — if
  allocation dominates, this becomes attractive; if not, the owning default stands.

---

## 11. How asn1cpp Was Built

### Starting Point: the asn1c Grammar

ASN.1 is a large and somewhat irregular language. Its grammar is ambiguous in places,
context-sensitive in others, and has evolved across five decades of ITU-T revisions.
Writing a correct ASN.1 parser from scratch is a multi-year project.

The asn1c grammar, developed by Lev Walkin over many years and maintained by Mouse, is
the accepted reference implementation for open-source ASN.1 parsing. Rather than
rewriting it, gambas-asn1 ports it — with the smallest possible changes needed for
RE/flex and Bison C++ mode.

The grammar files `compiler/grammar/asn1.l` and `asn1.y` are direct derivatives of
`asn1c/libasn1parser/asn1p_l.l` and `asn1p_y.y`. Diffs between the two are
intentionally minimal and are tracked via `compare_tokens.py` in the validation tools.

### RE/flex: Modern Lexing

asn1c uses the classic flex/lex for tokenisation. gambas-asn1 uses RE/flex 6.1.0, a
C++ replacement that integrates cleanly with Bison's C++ API and supports Unicode
natively.

The migration required two non-trivial adaptations:

1. **Grouped state blocks.** RE/flex 6.1.0 generates broken C++ from flex's grouped
   `<state>{ ... }` syntax. All grouped rules were expanded to individual
   `<state>rule` lines.

2. **`bison-complete` mode, not `bison-cc`.** The `bison-cc-parser` option causes
   RE/flex to emit a double-namespace `yy::yy` prefix that conflicts with Bison's
   generated parser. `bison-complete` emits the correct single `yy::` prefix.

### Bison C++: Parser Generation

The grammar uses Bison's `%skeleton "lalr1.cc"` mode with `api.token.constructor` and
`api.value.type variant`. This gives type-safe semantic values throughout the parse
tree without `union` and without manual `new`/`delete`.

The AST is a `std::vector<ast::Module>`, one per input file. Modules reference each
other's types through the `Resolver` semantic analysis pass.

### Cross-Validation as the Development Loop

The primary development tool is `compare_random.py`. It:

1. Generates N random records using gambas-asn1's `RandomFiller`.
2. Encodes each record to BER with gambas-asn1.
3. Decodes each BER record back to an object with gambas-asn1; re-encodes to BER;
   checks that the two BER buffers are identical.
4. Encodes each record to XER with gambas-asn1.
5. Feeds the original BER to asn1c's `ber-to-xer` tool.
6. Compares the XER outputs byte-for-byte.

Eleven checks, four seeds, 110 records per run. A failure points to a specific record
and a specific check, which narrows the bug to a specific type or encoding path within
seconds.

This loop made it practical to implement complex features incrementally. UPER support,
for example, was validated with 40,000 cross-checks against asn1c across four RRC types
before being declared complete.

---

## 12. Challenges in Building a Fast ASN.1 Implementation

This chapter documents the non-obvious performance problems encountered and the
solutions chosen. The git history has the full record; this is the distilled version.

### The Heap Allocation Problem

The original `BerWriter::write_constructed` allocated a fresh `std::vector<uint8_t>`
for each nested construct, wrote the nested content into it, prepended the tag and
length, then appended the whole thing to the parent buffer. ETSI PS-PDU records have
roughly 20 nesting levels. That is 20 heap allocations per record, every record.

Profiling (gperftools, `-O0`) showed `malloc`/`free` at 35% of CPU time in BER encoding.

The fix: reserve space for the length field in the flat output buffer before writing
nested content. After the content is written, compute the actual length and patch it in
place. If the content fits in 65535 bytes (true for all ETSI constructs), no movement
is needed. Longer content falls back to the old path.

Throughput improvement at `-O3`: BER encode went from 40 MB/s to 53 MB/s — a 30% gain.

### OID Encoding Allocations

`Oid::encode` originally used a `std::vector<uint8_t>` to accumulate the arc bytes
before writing them as a BER primitive. The same pattern for decode: a
`std::vector<uint32_t>` to accumulate decoded arcs.

Both were replaced with stack buffers. An OID encoding never exceeds 20 bytes for any
realistic OID (the longest ETSI OIDs are 10–12 bytes). An OID never has more than 16
arcs in practice. Stack buffers cover 100% of real-world cases with no heap involvement.

### IMPLICIT-Member Re-Tagging

When a SEQUENCE member carries an IMPLICIT context tag, the original decoder allocated
a temporary buffer to re-tag the value bytes before passing them to the inner decoder.
For example, `[0] IMPLICIT UTF8String` means the UTF8String tag (0x0C) is replaced by
the context tag (0x80). The original code built a new TLV with the universal tag, then
decoded that.

The fix: pass the value bytes directly, with the context tag stripped and the universal
tag synthesised inline. No allocation.

### The `void *` Problem

Early versions of the runtime used `void *` throughout the codec interface:

```cpp
virtual void encode(IEncodeStream& dst, const TypeDescriptor& def,
                    const void* src) const = 0;
```

`void *` forces a reinterpret cast somewhere, and that cast carries an implicit layout
assumption. As the type hierarchy grew — `Integer`, `UInteger`, `EnumValue`,
`AsnStringBase`, CHOICE variants — layout assumptions accumulated silently.

The fix was a mandatory base class: `Asn1Object`. Every encodable type inherits from it.
The codec interface uses `Asn1Object *` throughout. Layout is expressed by the language,
not by programmer discipline.

### Why -O3 Absorbed Some Improvements

Some micro-optimisations that showed large gains in Debug profiles showed no measurable
gain in Release builds. The `read_tlv` fast path — a hand-written inline version of
the common case — is an example. At `-O3 -flto`, the compiler already inlines and
optimises the function call chain to produce equivalent code.

The lesson: profile in Release, not Debug, before deciding that an optimisation is worth
the maintenance cost. Debug profiles identify hot spots correctly but overstate the
benefit of eliminating function call overhead, which LTO already eliminates.

---

## 13. The Honest Parts: Where Complexity Lives

Every project has ugly corners. Documenting them honestly is more useful than pretending
they do not exist.

### No Per-Instance VTables in Generated Types

Generated types do not use `virtual` methods for their own member operations (get, set,
presence query). This is a design choice, not an oversight. Understanding why requires
examining what "normal inheritance" would cost.

**Why not virtual member accessors?**

A SEQUENCE type with 20 members, compiled with virtual `get_<member>()` accessors, would
carry a vptr in every instance — 8 bytes of overhead before any payload. More
importantly, a virtual call through a vptr requires loading the vtable, loading the
function pointer, and an indirect branch. In a BER encode loop that iterates all 20
members sequentially, these 20 indirect branches defeat the branch predictor. At the
scale of millions of records per hour, this matters.

**Why not `std::variant<>` for CHOICE?**

`std::variant<Alt1, Alt2, ..., AltN>` looks attractive for CHOICE: it is type-safe,
standard, and has a discriminator. The problem is template instantiation. A CHOICE with
20 alternatives visited by a codec that calls `std::visit` with a lambda produces 20
template instantiations of the visitor — one per alternative. With 50 CHOICE types in a
schema, that is 1,000 instantiations that the compiler cannot merge even when the
generated code is identical. Compile time explodes; binary size grows.

**The actual approach: opaque storage + TypeDescriptor function pointers**

Generated CHOICE types use a fixed-size opaque storage buffer sized to `sizeof` of the
largest alternative:

```cpp
alignas(max_align_t) char storage_[MaxAltSize];
int index_{-1};  // which alternative is active
```

This is a manual union — not `std::variant`, not a pointer, not a heap allocation. Every
mandatory member of a SEQUENCE lives inline inside the SEQUENCE object, and every
alternative of a CHOICE lives inline inside the CHOICE storage. The entire object graph
for a deeply nested SEQUENCE is allocated in one block.

The TypeDescriptor carries a table of function pointers (`get_const_fn`, `get_mut_fn`,
`construct_fn`, `destruct_fn`) per alternative. These are **type-level** function
pointers, not **instance-level** vptrs. There is one table entry per type, shared across
all instances of that type — the same information a vtable carries, but stored in static
data alongside the descriptor rather than behind a pointer in each object.

This is the ugliest part of the design, and it deserves an honest apology. Manual storage
management, placement new in the alternative slots, and explicit destructor calls are
not idiomatic C++. They are a deliberate trade: one design-time complexity for zero
runtime overhead on every instance, every access, every encode loop.

The result: a SEQUENCE with 20 members and no optional fields allocates exactly once.
No virtual dispatch per member. No per-instance overhead beyond the fields themselves.

### External Descriptor Tables

The descriptor tables (`asn_MBR_T`, `asn_SPC_T`, `asn_DEF_T`) are static data in the
generated `.cpp` files. They reference runtime type descriptors by pointer
(`&asn1::asn_DEF_Integer`, `&asn1::asn_DEF_OctetString`). This means the generated
`.cpp` files must be compiled together with the runtime.

It also means the tables are correct only for the runtime version they were generated
against. Regenerating after a runtime `TypeDescriptor` change is required. In practice
this is managed by the `make regen` target in the ETSI example Makefile.

### The `Expected<T, E>` Return Type

gambas-asn1 uses a hand-rolled `Expected<T, E>` type (similar to `std::expected` from
C++23) throughout the codec return paths. This avoids exceptions — which are
incompatible with the no-allocation goal in hot paths — but requires callers to check
every return value explicitly.

The pattern is verbose:

```cpp
auto tag_r = read_tag();
if (!tag_r) return make_unexpected<TLV, DecodeError>(tag_r.error());
Tag tag = *tag_r;
```

C++23's `std::expected` with monadic `.and_then()` / `.transform()` would be cleaner.
The current `Expected<>` was written before C++23 was widely available and is
functionally correct. Replacing it with `std::expected` is a future cleanup.

### PER Extension Points

UPER extension handling is complete:

- SEQUENCE preamble bitmap and extension flag (X.691 §18.1).
- Extension members: present-bitmap (normally-small number of extensions, then n bits),
  each present member wrapped as an open-type (length-prefixed octet string, X.691 §12).
- CHOICE root alternatives encoded by canonical-tag-order index in ⌈log₂(n)⌉ bits.
  Extension alternatives use the normally-small-non-negative-number encoding (X.691 §22.6).
- Unknown extension members from newer senders are skipped by consuming the open-type
  length prefix. `PerDecodeStream::skipped_extensions()` reports the skip count.

**Canonical ordering**: The generator (`Generator.cpp`) emits CHOICE alternative tables
in canonical tag order (tag class ascending, then tag number ascending, separately for
root and extension alternatives). The runtime uses the array index directly as the
canonical index — no runtime sorting.

---

## 14. Status and Conformance

### Compiler

The compiler reads and processes all ASN.1 modules in both ETSI TS 102 232 and
3GPP TS 25.331 without error. It passes all 145 asn1c parser pass-tests and all
3 reject-tests. 34 of 35 semantic-error tests are correctly handled.

Parser conformance is tracked by `tests/run_parser_tests.py`, which runs the asn1cpp
compiler on ~200 asn1c test files and checks pass/fail outcomes. Known failures are
listed in `tests/parser_known_failures.txt`; both the ctest harness and the convenience
wrapper `asn1cpp-validation-tools/validate_parser.py` read from that file.

### BER Codec

BER encode and decode are complete for all types present in ETSI LI PS-PDU:

- SEQUENCE, SET, SEQUENCE OF, SET OF
- CHOICE (tagged and untagged alternatives, extension skip)
- IMPLICIT and EXPLICIT tagging (all tag classes)
- ALL primitive types (INTEGER, OCTET STRING, BIT STRING, OID, RELATIVE-OID,
  BOOLEAN, NULL, REAL, ENUMERATED, all string types, UTCTime, GeneralizedTime)
- ANY (stored and replayed as verbatim BER bytes)
- DEFAULT value suppression on encode, fill on decode
- Indefinite-length encoding (decode only; encode always uses definite)
- Extension marker skip on decode

Cross-validation: **440/440** records across seeds {1, 7, 42, 99}, 10 records per seed,
all 11 checks passing. Wire-fuzz (8 corruption modes, 180k ETSI + 45k PKIX records):
zero signal kills, zero assertion failures.

The asn1c BER vector suite for schema 62 (33 vectors): 27 pass, 5 intentionally skipped
(malformed nested BER inside ANY — stored verbatim, consistent with standard behaviour).

The asn1c XER→UPER→XER vector suite for schema 119 (25 vectors): 11 pass, 14 skipped
(PER-incompatible inputs — alphabet/size constraint violations expected to fail encode).

### UPER (PER) Codec

UPER encode and decode are complete for all types present in 3GPP TS 25.331 (RRC):

- SEQUENCE preamble bitmap (root optional members)
- DEFAULT suppression per X.691 §18.5
- Constrained INTEGER encoding (bit-packed)
- CONSTRAINED ENUMERATED encoding (index-packed)
- CHOICE canonical-index dispatch (generator emits alternatives in canonical tag order;
  runtime uses array index directly)
- SEQUENCE OF with SIZE constraints
- Extension bitmap (root extension flag)
- Extension member open-type wrapping (X.691 §12): encode present members, decode with
  skip of unknown alternatives

Cross-validation: **40,000/40,000** records (2,000 × 4 RRC types × 5 paths) against
asn1c UPER.

The asn1c XER→UPER vector suite for schema 126 (21 vectors): 20 pass, 1 known-permissive
(file 04-P: encoded with older 2-extension schema; our decoder accepts it via
forward-compatible extension skipping, asn1c rejects it).

### XER Codec

XER encode and decode are complete. Entity escaping (`&amp;`, `&lt;`, `&gt;`,
`&apos;`, `&quot;`, numeric references) is implemented per X.693. BmpString and
UniversalString transcode between UCS-2BE/UCS-4BE and UTF-8.

A SEQUENCE OF / SET OF whose elements are BOOLEAN, ENUMERATED or NULL, also
through a type reference or a tag, uses the XMLValueList form (X.680 §25.5
Table 5): each value is written bare, with no element tag, and a NULL value is
the empty element of its type name. The layout follows asn1c: SEQUENCE OF
values stay on the opening tag's line, while SET OF values and NULL values each
start a new line:

```xml
<ec><green/><green/>    </ec>
<bt>
        <false/>
        <true/>    </bt>
<na>
        <ANull/>    </na>
```

Other elements are each enclosed in a tag. When the SEQUENCE OF / SET OF names
its element (`rows SEQUENCE OF row SEQUENCE OF INTEGER`, `SEQUENCE OF item
SEQUENCE { … }`), that identifier is the tag (`<row>`, `<item>`, X.680 §25.10);
otherwise it is the element's type reference or the built-in type's XML name
(`<SEQUENCE>`, `<SEQUENCE_OF>`, `<INTEGER>`, §25.11).

A CHOICE value encoded as the document root is wrapped in its type name
(X.693 §8.3.1). The closing tag follows the alternative's line directly, as in
asn1c's output:

```xml
<Pick>
    <num>5</num>
</Pick>
```

A SEQUENCE OF / SET OF CHOICE writes each element as the chosen alternative's
element, with an empty line between elements, as asn1c does:

```xml
<items>
        <num>3</num>

        <flag><true/></flag>
</items>
```

The decoder defaults to strict BASIC-XER (X.693 §8). Pass `XerDecodeMode::Lenient`
to `XerDecodeStream` to additionally accept non-standard asn1c extensions: BOOLEAN
text content (`true`/`false`) and hex BIT STRING (`AABBCC…` pairs). See §6 for
details.

### Constraint Validation

Constraint validation runs at encode and decode time in Debug builds. Supported:

- Integer range constraints (inclusive bounds, root + extension)
- Size constraints (OCTET STRING, BIT STRING, SEQUENCE OF, all string types)
- FROM alphabet constraints (IA5String, PrintableString, VisibleString,
  NumericString, and custom alphabets)
- Path tracking (`ValidationReport`) for locating violations in nested structures

---

## 15. Known Limitations

| Area | Limitation |
|------|-----------|
| **WITH COMPONENTS / PATTERN** | WITH COMPONENTS and PATTERN constraints are not enforced by the validator. Neither is PER-visible, so PER encoding is unaffected. Not present in ETSI LI or 3GPP RRC schemas. |
| **BigInteger / ArbitraryInteger** | Unconstrained INTEGER values that exceed int64_t / uint64_t range have stub types with deleted constructors. Codec cannot encode or decode these. Not used by supported schemas. A constrained INTEGER must fit int64 (−2^63..2^63−1) or, when its lower bound is non-negative, uint64 (0..2^64−1). Anything else — a bound below −2^63 (e.g. `INTEGER (-2^64..2^64-1)`) or a range mixing negative values with values above 2^63−1 (e.g. `INTEGER (-1..2^64-1)`) — is deliberately not implemented; supporting it would mean promoting such a member to a big-integer type with its own PER path ([Issue #754](https://github.com/Schramp/gambas-asn1/issues/754)). Full 64-bit ranges such as `(0..2^64-1)` and `(-2^63..2^63-1)` are encoded as 64-bit constrained whole numbers in PER. |
| **32-bit platforms not supported** | asn1cpp requires a 64-bit host. Both the compiler and the generated runtime use 64-bit `long`/`uint64_t` types. Building or running on a 32-bit CPU is untested and unsupported. |
| **-flong-size cross-compilation** | asn1cpp compiled for a 64-bit host generates code assuming 64-bit `long`. Cross-compilation to 32-bit targets may produce wrong native INTEGER storage types ([Issue #15](https://github.com/Schramp/gambas-asn1/issues/15)). |
| **SET member ordering** | SET members are decoded in tag order (same as SEQUENCE). The standard permits any order; out-of-order SETs from other encoders are not handled. |
| **Indefinite-length encode** | Decoder accepts indefinite-length BER. Encoder always uses definite-length encoding. |
| **RandomFiller coverage** | ENUMERATED fill, UInteger, Real, Null, OID, UTCTime, and GeneralizedTime fill paths have zero test coverage. |

---

## 16. Performance Figures

Benchmarks run on an AMD system under WSL2, Release build (`-O3`), using
randomly generated `EncryptedPayload` records (BER, seed=42, `etsitools/asn1cpp/perf/perf_ber`
and `etsitools/asn1c/perf/perf_ber_c`).

### asn1cpp vs asn1c (10,000 records, 15.57 MB)

| Operation | asn1cpp | asn1c | Ratio |
|-----------|---------|-------|-------|
| BER decode | 72.5 MB/s | 46.4 MB/s | 1.6× faster |
| BER decode (object reuse) | 78.8 MB/s | — | — |
| BER encode | 148.6 MB/s | 5.0 MB/s | ~30× faster |
| XER encode | 326.8 MB/s | — | — |
| XER decode | 200.8 MB/s | — | — |
| JER encode | 182.2 MB/s | 165.9 MB/s | 1.1× faster |
| JER decode | 86.7 MB/s | 56.3 MB/s | 1.5× faster |

asn1c BER encode is slow because it generates a temporary buffer per nested construct
and uses repeated `realloc`. gambas-asn1's reserve-and-patch approach avoids this.

### BerProjection vs full decode/encode (perf_projection, 706,270 PS-PDU frames, 208 MB)

`BerProjection` reads and rewrites specific fields directly in the BER wire bytes,
without decoding the surrounding SEQUENCE/CHOICE tree into objects. A projection
is set up once (a set of paths, e.g. `"pSHeader/lawfulInterceptionIdentifier"`,
compiled into a trie of tag offsets against a `TypeDescriptor`), then applied
per-record: `apply()` walks the trie against one frame's bytes and hands back
`Asn1Optional<T>` views bound to each path; `commit()` re-encodes a modified
field and patches it back into the frame in place (same-size replacement, no
buffer growth for BER's TLV length fields). This is the same mechanism behind
`etsi-pcap`'s and `pseudonimiser`'s ability to touch a handful of fields across
millions of records without paying for a full object graph each time.

`perf_projection` benchmarks this against full decode+modify+encode on real
PS-PDU capture data, projecting two fields per PS-PDU header:

- `pSHeader/lawfulInterceptionIdentifier` — the LIID, rewritten (first byte
  XOR'd, same byte length) as a stand-in for anonymisation/relabelling
- `pSHeader/microSecondTimeStamp/seconds` — the timestamp, rewritten (+20s) as
  a stand-in for clock adjustment/normalisation

Both are single-field, same-size, in-place rewrites — the case `BerProjection`
is built for. Fields not on a projected path are left untouched in the wire
bytes; the rest of the PS-PDU tree (payload, CHOICE alternatives, nested
SEQUENCE OFs) is never decoded at all.

| Path                               | Throughput   | Records/s |
|------------------------------------|--------------|-----------|
| Full decode + encode               | 222.1 MB/s   | 753,719   |
| BerProjection (lazy field access)  | 1,048.2 MB/s | 3,556,692 |


4.7× speedup for selective field reads/rewrites that avoid materialising the
full object tree. The gain scales with how much of the record is *not* on a
projected path — a projection touching most fields of a small record sees
less benefit than this two-field-in-a-large-PS-PDU case.

### Real-World Throughput (perf_pspdu, operator-captured ETSI LI data)

Processing real operator-captured ETSI LI files (4,761 records, 1.57 MB per pass):

| Operation | Throughput |
|-----------|-----------|
| BER decode | 150 MB/s |
| Object copy (deep copy) | 505 MB/s |
| BER encode | 66 MB/s |

Deep copy throughput reflects the `TypeDescriptor`-driven deep copy path, which uses
`memcpy` for fixed-size members and `std::string` copy for variable-length fields.

### Notes on Measurement

WSL2 introduces 15–30% run-to-run timing variance. The `asn1cpp` vs `asn1c` and
`perf_projection` figures above are single runs (`make perf-run`, runtime rebuilt with
`-DCMAKE_BUILD_TYPE=Release`); the real-world `perf_pspdu` figures are medians over 8
rounds from an earlier session. Small optimisations (< 10% expected gain) are not
reliably distinguishable from noise in this environment. The figures should be treated
as order-of-magnitude characterisations, not precise benchmarks.

For rigorous measurement, rebuild the runtime with `-DCMAKE_BUILD_TYPE=Release` and
run on native Linux.

---

## 17. Contributing

Contributions are welcome. The project follows these conventions:

### Code Style

- C++20. No exceptions in runtime hot paths. `Expected<T, E>` for fallible operations.
- No `void *` in codec interfaces. Use `Asn1Object *` or a typed base class.
- No generated codec logic. Tables only in generated files.
- No comments that say what the code does. Comments explain *why* when the reason
  is non-obvious.

### Adding a Target Language

A new codegen backend plus runtime follows [`doc/backend-guide.md`](backend-guide.md):
the Backend contract, the shared descriptor-table model every backend renders,
the runtime shape, language-mapping decisions, naming rules, the construct order,
and the validation ladder (including the cross-language table dump format).

The Java runtime (`java-runtime/`, in progress) is a Gradle build with the
wrapper committed and a Java 21 toolchain:

```bash
./java-runtime/gradlew -p java-runtime test
```

`cmake` finds a JDK 21 or newer and turns on `WITH_JAVA_RUNTIME_TEST`, so the
same run is the ctest `java_runtime_test`. The first run downloads Gradle and
the test dependencies.

The Java backend (`--target=java`) keeps ASN.1 names as the other backends
do (hyphen to underscore, no recasing). A name that is a Java keyword,
literal (`true`, `false`, `null`) or contextual keyword (`record`, `var`,
`yield`, ...) gets a trailing underscore: `class` becomes `class_`.

A builtin type assignment (`Flag ::= BOOLEAN`) becomes a class holding the
runtime's builtin wrapper in its `value` field; `BerObject.encode`/`decode`
encode any generated value with its type's own tagging:

```java
Flag f = new Flag();
f.value.set(true);
byte[] der = BerObject.encode(f);   // 01 01 FF
BerObject.decode(f, der);
```

An INTEGER type assignment holds an `Asn1Integer` (signed 64-bit `long`)
and gets one `long` constant per named number (`Named.minus_one`). An
ENUMERATED type assignment is a class whose nested enum `Value` lists the
items in declaration order; `get()`/`set(Value)` read and change the item,
and decoding a value that is not one of the items is an error:

```java
Color c = new Color();
c.set(Color.Value.blue);
byte[] der = BerObject.encode(c);   // 0A 01 05
```

OCTET STRING and BIT STRING type assignments hold an `Asn1OctetString`
(`byte[]`) or an `Asn1BitString` (packed `byte[]` plus the unused-bit
count of the last octet), with their SIZE constraint in `CONSTRAINTS`.
Like the C++ and Rust runtimes, BER decode accepts only the primitive form
of these strings (gambas-asn1#929).

So far the Java backend emits BOOLEAN, NULL, INTEGER (64-bit storage),
ENUMERATED, OCTET STRING and BIT STRING type assignments. The Java
legs of the codec tests (`tests/java/`, ctest `java_legs`) check the
generated code against asn1c's DER in `tests/vectors/`.

### Commits

- One logical change per commit.
- Commit message subject: `area: short description` (e.g. `codegen: fix CHOICE tag emission`).
- No `Co-Authored-By` lines.

### Tests

Before submitting:

```bash
cmake --build build --parallel $(nproc)
ctest --test-dir build/tests --output-on-failure
python3 asn1cpp-validation-tools/compare_random.py --count 10 --seed 1 7 42 99
```

440/440 xval and 41/41 ctest must pass.

### Release Testing

Before tagging a release or merging to `main`, run the smoke matrix in addition to the
standard suite. The smoke matrix compiles 17 ASN.1 built-in types under four flag
combinations (`-fprefix=`, `-pdu=`, and both combined) and verifies the generated C++
compiles without error — 68 checks total.

Enable and run:

```bash
cmake -S . -B build -DWITH_SMOKE_MATRIX=ON
cmake --build build
ctest --test-dir build/tests --output-on-failure
```

The `smoke_matrix` test takes ~2 minutes. It is disabled by default
(`-DWITH_SMOKE_MATRIX=OFF`) so routine development cycles stay fast. CI enables it
automatically on pushes to `main`.

### Open Work

Open issues are tracked at https://github.com/Schramp/gambas-asn1/issues.
See `CLAUDE.md` in the repository root for detailed technical context on each item.

---

## 18. References

**Standards**

- ITU-T X.680 (2021): *Abstract Syntax Notation One (ASN.1): Specification of basic notation*
- ITU-T X.690 (2021): *ASN.1 encoding rules: Specification of Basic Encoding Rules (BER),
  Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)*
- ITU-T X.691 (2021): *ASN.1 encoding rules: Specification of Packed Encoding Rules (PER)*
- ITU-T X.693 (2021): *ASN.1 encoding rules: XML Encoding Rules (XER)*
- ETSI TS 102 232-1 V3.32.1 (2024-07): *Lawful Interception (LI); Handover Interface and
  Service-Specific Details (SSD) for IP delivery; Part 1: Framework and instruction*
- 3GPP TS 25.331 V17.x: *Radio Resource Control (RRC); Protocol specification*
- RFC 5280: *Internet X.509 Public Key Infrastructure Certificate and
  Certificate Revocation List (CRL) Profile*

**Tools and Libraries**

- asn1c (Lev Walkin): https://github.com/vlm/asn1c
- asn1c fork (Mouse): https://github.com/mouse07410/asn1c
- RE/flex: https://github.com/Genivia/RE-flex
- GNU Bison: https://www.gnu.org/software/bison/
- gperftools (Google Performance Tools): https://github.com/gperftools/gperftools

**This Project**

- gambas-asn1: https://github.com/Schramp/gambas-asn1
