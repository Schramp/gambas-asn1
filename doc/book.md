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
15. [Performance Figures](#15-performance-figures)
16. [Contributing](#16-contributing)
17. [References](#17-references)

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
| GCC or Clang | C++20 | GCC 13+ recommended |
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

Every ASN.1 type has a tag — a class and number that identify it on the wire. Universal
tags are standardised (INTEGER is `[UNIVERSAL 2]`, SEQUENCE is `[UNIVERSAL 16]`).

When a SEQUENCE has two OPTIONAL members of the same type, the decoder cannot tell them
apart by tag alone. ASN.1 resolves this with explicit or implicit tagging:

```asn1
Wrapper ::= SEQUENCE {
    first   [0] IMPLICIT UTF8String  OPTIONAL,
    second  [1] IMPLICIT UTF8String  OPTIONAL
}
```

IMPLICIT tagging replaces the original tag. EXPLICIT tagging wraps it in an outer tag.
The choice matters for BER encoding and is tracked in the `MemberDescriptor` table.

### Constraints

ASN.1 constraints restrict the set of valid values:

```asn1
SmallInt  ::= INTEGER (0..255)
ShortStr  ::= UTF8String (SIZE (1..64))
PortNum   ::= INTEGER (0..65535)
```

Constraints are compiled into `Constraints` structs in the descriptor tables. They are
used by the constraint validator and, for PER, determine the minimum number of bits
needed to encode a value.

---

## 6. BER, PER, XER and Other Encoding Flavours

### Basic Encoding Rules (BER)

BER encodes every value as a Tag-Length-Value triple. The tag identifies the type, the
length gives the number of value bytes, and the value bytes encode the content according
to type-specific rules. Nested structures encode as constructed TLVs whose value bytes
are themselves TLVs.

BER is self-describing: a decoder that does not know the schema can still traverse the
structure, read tag numbers and lengths, and skip unknown fields. This makes it robust
to schema evolution.

The price is space: every field carries a tag (1–4 bytes) and a length (1–5 bytes)
regardless of how small the value is. A BOOLEAN takes 3 bytes. A single-byte INTEGER
takes 3 bytes.

Distinguished Encoding Rules (DER) are a canonical subset of BER: lengths always use
the shortest encoding, constructed strings are forbidden, SET members are sorted by tag.
DER is used wherever byte-for-byte reproducibility matters — chiefly in digital
signatures.

### Packed Encoding Rules (PER / UPER / APER)

PER dispenses with self-description entirely. The encoder and decoder must both know the
schema; the encoded bits carry only the minimum information needed to reconstruct the
value.

A constrained INTEGER (0..7) needs 3 bits. A BOOLEAN needs 1 bit. A SEQUENCE with
three OPTIONAL members has a 3-bit preamble bitmap before any values. CHOICE alternatives
are identified by an index into the alternative list, encoded in log₂(n) bits.

Unaligned PER (UPER) packs values at bit boundaries with no byte alignment. Aligned PER
(APER) byte-aligns certain constructs. 3GPP uses UPER for radio interface protocols.

The payoff is density: a typical 3GPP RRC message that takes 50 bytes in BER takes 5–10
bytes in UPER.

### XML Encoding Rules (XER)

XER transcodes ASN.1 values to XML. Each type has a canonical XML representation:
SEQUENCE becomes a parent element whose child elements are the member values; CHOICE
becomes a single child element named after the chosen alternative; OCTET STRING becomes
uppercase hex; BIT STRING becomes a space-separated bit string.

XER is used for logging, debugging, and human-readable diagnostics. It is not compact —
the XER encoding of a typical ETSI record is 10–20× larger than its BER encoding — but
it is legible.

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

Create a file `contact.asn1`:

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
./build/compiler/asn1cpp contact.asn1 -o generated/
```

The compiler emits:

```
generated/
  PhoneNumber.hpp   PhoneNumber.cpp
  Address.hpp       Address.cpp
  Contact.hpp       Contact.cpp
  ContactList.hpp   ContactList.cpp
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
#include <asn1cpp/codec/BerCodec.hpp>
#include <fstream>

int main() {
    Contact c{};
    c.set_name("Alice");
    c.set_email("alice@example.com");

    // Encode to BER
    std::vector<uint8_t> buf;
    asn1::BerCodec::instance().encode(buf, asn_DEF_Contact, &c);

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
    asn1::BerDecodeStream s{buf};
    auto result = asn1::BerCodec::instance().decode(s, asn_DEF_Contact, &c);
    if (!result) {
        std::cerr << "Decode error: " << result.error().message << "\n";
        return 1;
    }

    std::cout << "Name: " << std::string(c.name()) << "\n";
    if (c.has_email())
        std::cout << "Email: " << std::string(c.email()) << "\n";
}
```

### XER (Human-readable) Output

```cpp
#include <asn1cpp/codec/XerCodec.hpp>

std::string xml;
asn1::XerCodec::instance().encode(xml, asn_DEF_Contact, &c);
std::cout << xml;
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
asn1cpp <file.asn1> [<file2.asn1> ...] -o <outdir>
```

Reads one or more ASN.1 module files, resolves cross-module references, and generates
one `.hpp` + `.cpp` pair per type in the output directory.

**Options:**

| Flag | Effect |
|------|--------|
| `-o <dir>` | Output directory (required) |
| `-fallow-newer-modules` | Accept module version mismatches silently |

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

```bash
# Trace BER encoding:
ASN1CPP_DEBUG=0x10 ./my-encoder input.ber

# Trace CHOICE dispatch during decode:
ASN1CPP_DEBUG=0x01 ./my-decoder input.ber

# Enable all:
ASN1CPP_DEBUG=0xff ./my-tool input.ber
```

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

Cross-validation against asn1c is the primary correctness mechanism. For every random
test record, both encoders produce BER; both decoders produce XER; the XER outputs are
compared. 440 records × 4 seeds × 11 checks per record = over 19,000 assertions per
cross-validation run.

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
the best available reference implementation. Rather than rewriting it, gambas-asn1 ports
it — with the smallest possible changes needed for RE/flex and Bison C++ mode.

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

This was a 16-file refactor that touched the codec interface, all handler overrides,
optional-member function pointers, CHOICE accessors, and generated helpers. It took one
session and broke nothing that the test suite didn't immediately catch.

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

### No Runtime VTables in Generated Types

Generated types do not use `virtual` methods for their own operations (getting members,
setting members, querying presence). This is a deliberate choice: virtual dispatch adds
a pointer indirection per call, and per-member accessors are called in tight loops
during encode and decode.

Instead, generated SEQUENCE types expose plain `get_<member>()` and `set_<member>()`
methods. CHOICE types expose `get_<alt>()` and `set_<alt>()` plus an index accessor.

The downside: generated types are not polymorphic in the OOP sense. You cannot hold a
`MySeq *` and call `encode()` on it without also knowing its `TypeDescriptor`. The
`TypeDescriptor` carries that information — so callers pass both. This is a slightly
unusual API but is consistent throughout the runtime.

The `Asn1Object` base class does have a virtual destructor — the minimum needed for
correct polymorphic deletion. Nothing else is virtual.

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

UPER extension handling (the `...` marker in ASN.1) is implemented for SEQUENCE preamble
bitmaps and CHOICE index encoding. Extension member encoding (open-type wrapping per
X.691 §12) is a stub. The 3GPP RRC cross-validation passes because the test records
do not exercise extension alternatives — but schemas that actually populate extension
members will fail silently in PER.

This is documented in `CLAUDE.md` and is not a hidden gotcha, but it is a real gap for
anyone using PER with extensible types in production.

---

## 14. Status and Conformance

### Compiler

The compiler reads and processes all ASN.1 modules in both ETSI TS 102 232 and
3GPP TS 25.331 without error. It passes all 145 asn1c parser pass-tests and all
3 reject-tests. 34 of 35 semantic-error tests are correctly handled.

Parser conformance is tracked by `validate_parser.py`, which runs the asn1cpp compiler
and asn1c side by side on ~200 test files and compares pass/fail outcomes.

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

### UPER (PER) Codec

UPER encode and decode are complete for all types present in 3GPP TS 25.331 (RRC):

- SEQUENCE preamble bitmap (root optional members)
- DEFAULT suppression per X.691 §18.5
- Constrained INTEGER encoding (bit-packed)
- CONSTRAINED ENUMERATED encoding (index-packed)
- CHOICE canonical-index dispatch
- SEQUENCE OF with SIZE constraints
- Extension bitmap (root extension flag)

Cross-validation: **40,000/40,000** records (2,000 × 4 RRC types × 5 paths) against
asn1c UPER.

Extension member open-type encoding is not yet implemented (see §13).

### XER Codec

XER encode and decode are complete. Entity escaping (`&amp;`, `&lt;`, `&gt;`,
`&apos;`, `&quot;`, numeric references) is implemented per X.693. BmpString and
UniversalString transcode between UCS-2BE/UCS-4BE and UTF-8.

### Constraint Validation

Constraint validation runs at encode and decode time in Debug builds. Supported:

- Integer range constraints (inclusive bounds, root + extension)
- Size constraints (OCTET STRING, BIT STRING, SEQUENCE OF, all string types)
- FROM alphabet constraints (IA5String, PrintableString, VisibleString,
  NumericString, and custom alphabets)
- Path tracking (`ValidationReport`) for locating violations in nested structures

---

## 15. Performance Figures

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

## 16. Contributing

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

440/440 xval and 24/24 ctest must pass.

### Open Work

See `CLAUDE.md` in the repository root for the current backlog, ranked by impact and
effort. The highest-priority open items are:

- **BER vector ctests for data-70, data-119, data-126, data-202** — mirror of the
  existing data-62 test.
- **PER extension member open-type encoding** — needed for schemas that populate
  extension alternatives in UPER.
- **NamedBits / WITH COMPONENTS / PATTERN constraints** — not used by ETSI or 3GPP
  RRC but needed for full ASN.1 conformance.

---

## 17. References

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
