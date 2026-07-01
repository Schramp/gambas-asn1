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
| `ENUMERATED` | Named integer values | generated `enum class` |
| `BIT STRING` | Sequence of bits with an optional named-bits table | `asn1::BitString` |
| `OCTET STRING` | Raw byte sequence | `asn1::OctetString` |
| `OBJECT IDENTIFIER` | Globally unique dotted-arc identifier | `asn1::Oid` |
| `RELATIVE-OID` | OID relative to a known base arc | `asn1::RelativeOid` |
| `UTCTime` | Date/time in YYMMDDHHmmssZ format | `asn1::UtcTime` |
| `GeneralizedTime` | Date/time in YYYYMMDDHHMMSS.fff format | `asn1::GeneralizedTime` |

String types — `UTF8String`, `PrintableString`, `IA5String`, `VisibleString`,
`NumericString`, `BMPString`, `UniversalString`, and others — all map to
`asn1::AsnString<tag>` and share a single string-handling runtime path.

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

Unaligned PER (UPER) packs values at bit boundaries with no byte alignment. Aligned PER
(APER) byte-aligns certain constructs. 3GPP uses UPER for radio interface protocols.

The payoff is density: a typical 3GPP RRC message that takes 50 bytes in BER takes 5–10
bytes in UPER.

**PER encode-time constraint validation.** `PerEncodeStream` rejects values that violate
string constraints at encode time: a `FROM` alphabet constraint means every character must
come from the declared set; a `SIZE(lower..upper)` constraint means the string length must
fall within the declared range (including fixed-size `SIZE(n)` where lower equals upper).
Violations set an internal flag rather than throwing:

```cpp
std::vector<uint8_t> buf;
asn1::PerEncodeStream s{buf};
asn1::PerCodec::instance().encode(s, MyType::asn_DEF, &val);
if (s.encode_failed()) {
    // value violates a PER string constraint (FROM alphabet or SIZE)
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

JER maps ASN.1 to JSON. It is not yet implemented in gambas-asn1 (stub only).

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
        phone    PhoneNumber                OPTIONAL,
        address  Address                    OPTIONAL
    }

    ContactList ::= SEQUENCE OF Contact

END
```

This schema defines four types. `Contact` has one mandatory field (`name`) and three
optional fields. `ContactList` is an unbounded list of contacts.

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
| `-pdu=<TypeName>` | Limit generation to `<TypeName>` and all types reachable from it (transitive BFS through TypeRef edges). May be specified multiple times. `-pdu=all` generates all types (same as omitting the flag). Note: types embedded as `OCTET STRING` bytes (two-level nested BER, e.g. `EncryptedPayload` inside `PS-PDU`) are not TypeRef dependencies and must be listed as separate `-pdu=` roots if needed. |

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
Corrupted-record variants (`BerCorruptor`) test that the decoder never crashes or
asserts on malformed input.

### Fully Table-Based: Minimal Generated Code

The fundamental principle is that generated files are data, not code. No `switch`
statements. No inline encode/decode logic. No type-specific codec helpers.

The benefit is proportional to schema size. A schema with 300 types generates 300 ×
(a few hundred lines of tables). The runtime is compiled once. Adding a new codec rule —
say, strict DER ordering — means changing one file in the runtime, not touching 300
generated files.

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
| **NamedBits / WITH COMPONENTS / PATTERN** | BIT STRING named-bit constraints, WITH COMPONENTS, and PATTERN constraints are not enforced by the validator and not used during PER encoding. Not present in ETSI LI or 3GPP RRC schemas. |
| **BigInteger / ArbitraryInteger** | Unconstrained INTEGER values that exceed int64_t / uint64_t range have stub types with deleted constructors. Codec cannot encode or decode these. Not used by supported schemas. |
| **JER (JSON Encoding Rules)** | Stub only — returns `not_implemented`. |
| **32-bit platforms not supported** | asn1cpp requires a 64-bit host. Both the compiler and the generated runtime use 64-bit `long`/`uint64_t` types. Building or running on a 32-bit CPU is untested and unsupported. |
| **-flong-size cross-compilation** | asn1cpp compiled for a 64-bit host generates code assuming 64-bit `long`. Cross-compilation to 32-bit targets may produce wrong native INTEGER storage types ([Issue #15](https://github.com/Schramp/gambas-asn1/issues/15)). |
| **SET member ordering** | SET members are decoded in tag order (same as SEQUENCE). The standard permits any order; out-of-order SETs from other encoders are not handled. |
| **Indefinite-length encode** | Decoder accepts indefinite-length BER. Encoder always uses definite-length encoding. |
| **RandomFiller coverage** | ENUMERATED fill, UInteger, Real, Null, OID, UTCTime, and GeneralizedTime fill paths have zero test coverage. |

---

## 16. Performance Figures


Benchmarks run on an AMD system under WSL2, Release build (`-O3 -flto`), using
randomly generated ETSI LI PS-PDU records (BER, seed=1).

### asn1cpp vs asn1c (1,000 records, ~1.55 MB)

| Operation | asn1cpp | asn1c | Ratio |
|-----------|---------|-------|-------|
| BER decode | ~57 MB/s | ~48 MB/s | 1.2× faster |
| BER decode (object reuse) | ~61 MB/s | — | — |
| BER encode | ~53 MB/s | ~5 MB/s | 10× faster |
| XER encode | ~175 MB/s | — | — |
| XER decode | ~200 MB/s | — | — |

asn1c BER encode is slow because it generates a temporary buffer per nested construct
and uses repeated `realloc`. gambas-asn1's reserve-and-patch approach avoids this.

### Real-World Throughput (perf_pspdu, Colt ETSI data)

Processing real operator-captured ETSI LI files (4,761 records, 1.57 MB per pass):

| Operation | Throughput |
|-----------|-----------|
| BER decode | 150 MB/s |
| Object copy (deep copy) | 505 MB/s |
| BER encode | 66 MB/s |

Deep copy throughput reflects the `TypeDescriptor`-driven deep copy path, which uses
`memcpy` for fixed-size members and `std::string` copy for variable-length fields.

### Notes on Measurement

WSL2 introduces 15–30% run-to-run timing variance. All figures above are medians
over 8 rounds. Small optimisations (< 10% expected gain) are not reliably distinguishable
from noise in this environment. The figures should be treated as order-of-magnitude
characterisations, not precise benchmarks.

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
