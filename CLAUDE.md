# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## XER output fidelity

XER output matches asn1c reference.

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

Run all tests (BER + parser conformance):
```bash
ctest --test-dir build/tests
```

asn1c cross-validation is enabled automatically when `asn1c` is on `PATH` or in
`/usr/local/bin`. To point at a custom build:
```bash
cmake -B build -DASN1C_BIN_DIR=/path/to/asn1c/build
# or
ASN1C_BIN_DIR=/path/to/asn1c/build cmake -B build
```

Run compiler:
```bash
./build/compiler/asn1cpp <file.asn1> -o <outdir>
```

## Runtime debug logging

Set `ASN1CPP_DEBUG` to a hex bitmask before running any binary that links `libasn1cpp_runtime`.
The value is read once on first call to `asn1::debug_flags()`; no rebuild needed.

| Bit | Flag constant | What it traces |
|-----|---------------|----------------|
| `0x01` | `DBG_BER_CHOICE` | CHOICE tag misses — prints type name, peek tag, all alternative tags |
| `0x02` | `DBG_BER_SEQ` | SEQUENCE EXPLICIT wrap/unwrap — outer tag + first value byte |
| `0x04` | `DBG_XER` | XER parse / emit (reserved, not yet wired) |
| `0x08` | `DBG_PER` | PER bit-level ops (reserved, not yet wired) |

```bash
# Enable CHOICE + SEQUENCE traces:
ASN1CPP_DEBUG=0x03 ./nested-decoder input.ber

# Enable all:
ASN1CPP_DEBUG=0xff ./nested-decoder input.ber
```

Flag definitions and `debug_flags()` live in `runtime/include/asn1cpp/codec/Debug.hpp`.

## Architecture

```
asn1cpp/
  CMakeLists.txt          # top-level; finds Bison, RE/flex, sets C++20
  compiler/
    grammar/
      asn1.l              # RE/flex lexer (ported from asn1c/libasn1parser/asn1p_l.l)
      asn1.y              # Bison C++ LALR grammar (ported from asn1p_y.y)
      Lexer.hpp           # thin wrapper including RE/flex generated header
    src/
      ast/                # C++ AST: TypeDef, Module, Constraint, Value, Tag, Node
      sema/Resolver.hpp   # cross-module type resolution
      codegen/Generator.{hpp,cpp}  # emits one .hpp + .cpp per ASN.1 type
      main.cpp
  runtime/include/asn1cpp/
    types/                # Integer, OctetString, BitString, Boolean, Null, Real, Oid, etc.
    codec/
      BerWriter.hpp       # low-level TLV write helpers
      BerReader.hpp       # low-level TLV read helpers
    asn1cpp.hpp           # umbrella include
  tests/
    ber/                  # BER round-trip unit tests
  examples/               # shared ASN.1 example files (also used by asn1c sibling project)
```

### Compiler pipeline
1. **Lexer** (RE/flex, `bison-complete` mode) → `yy::parser::symbol_type` tokens
2. **Parser** (Bison C++ LALR, `api.token.constructor`, `api.value.type variant`) → `ast::Module`
3. **Sema** (`Resolver`) → resolved type references
4. **Codegen** (`Generator`) → one `.hpp` + `.cpp` pair per type

### Generated code design — tables only, no inline codec logic

Generated `.hpp`/`.cpp` files contain **only static descriptor tables and thin wrapper
functions**. They never contain encoding/decoding logic. All encode/decode is delegated to
the runtime via the `TypeDescriptor` tables.

**What goes in generated files:**
- `asn_MAP_<T>[]`  — `EnumEntry` value↔name table (ENUMERATED)
- `asn_MBR_<T>[]`  — `MemberDescriptor` table (SEQUENCE, SET, CHOICE)
- `asn_SPC_<T>`    — type-specific spec struct (`EnumSpec`, `SequenceSpec`, `ChoiceSpec`)
- `asn_DEF_<T>`    — top-level `TypeDescriptor` (name, tag, pointer to spec)
- Thin `encode()`/`decode()` wrappers that call into the runtime, passing `asn_DEF_<T>`

**What stays in the runtime (never in generated files):**
- All TLV read/write logic
- All XML read/write logic
- Generic SEQUENCE/CHOICE/ENUMERATED encode+decode driven by `TypeDescriptor` tables

### Codec interface — `ICodec` virtual interface, not templates

All encodings share a single abstract interface. The codec is an object, not a compile-time
parameter, so it can be passed around, swapped, and stubbed without template explosion.

```cpp
// runtime/include/asn1cpp/codec/ICodec.hpp

class IEncodeStream;   // abstract output sink (binary buffer, XML writer, etc.)
class IDecodeStream;   // abstract input source

class ICodec {
public:
    virtual ~ICodec() = default;
    virtual const char* name() const = 0;

    // Encode a value (described by def) from src into dst.
    virtual void encode(IEncodeStream& dst,
                        const TypeDescriptor& def,
                        const void* src) const = 0;

    // Decode a value (described by def) from src into dest.
    virtual Expected<void, DecodeError> decode(IDecodeStream& src,
                                               const TypeDescriptor& def,
                                               void* dest) const = 0;
};
```

Concrete implementations:

| Class | Encoding | Status | Files |
|-------|----------|--------|-------|
| `BerCodec` | BER / DER | implemented | `codec/BerCodec.{hpp,cpp}` |
| `XerCodec` | XER (XML) | implemented | `codec/XerCodec.{hpp,cpp}` |
| `JerCodec` | JER (JSON) | stub — returns `not_implemented` | `codec/JerCodec.hpp` |
| `PerCodec` | PER / UPER | empty stub — see PER architecture section | `codec/PerCodec.hpp` |

`BerCodec` and `XerCodec` use `IEncodeStream`/`IDecodeStream` subclasses that wrap
`BerWriter`/`BerReader` and a simple XML writer/reader respectively. The generic logic
in `BerCodec::encode()` inspects `def.sequence_spec`, `def.enum_spec`, etc. to iterate
members — **no generated switch/if chains**.

Generated files contain only descriptor tables (`asn_MAP_`, `asn_MBR_`, `asn_SPC_`, `asn_DEF_`). No codec wrappers. Callers use the codec directly:

```cpp
// caller — decode a generated type
MySeq result{};
asn1::BerDecodeStream s{reader};
auto ok = asn1::BerCodec::instance().decode(s, asn_DEF_MySeq, &result);
```

### PER architecture

PER has its own codec class — `PerCodec` in `codec/PerCodec.hpp` (currently a stub).
It is completely separate from `BerCodec`. The `BerCodec` neither includes nor references
PER logic; it ignores all PER-specific fields in the descriptor tables.

The descriptor structs in `TypeDescriptor.hpp` carry PER *metadata* as nullable/zero
fields so that generated tables don't need to be regenerated when `PerCodec` is
eventually implemented. `BerCodec` and `XerCodec` skip these fields entirely.

PER is fundamentally different from BER/XER and forces richer descriptor tables.
This was validated by reading `constr_SEQUENCE_aper.c`, `constr_CHOICE_aper.c`, and
`asn1c_C.c` in the reference asn1c implementation.

#### BER vs PER iteration strategy

| Aspect | BER | PER |
|--------|-----|-----|
| Member identification | Tag on each TLV; out-of-order capable | Strictly positional; no tags |
| OPTIONAL detection | Tag present/absent in stream | Packed bitmap before any values (`roms_count` bits) |
| CHOICE index | Not applicable (decode recursively) | `range_bits`-wide integer (constrained) or unbounded int (extended) |
| Extension members | Tagged, skip unknown by tag | Bitmap + open-type (length-prefixed) wrapping; skip unknown by length |
| Stream granularity | Byte-aligned | Bit-aligned; needs `get_bits(n)`, `get_bitmap(n)`, alignment primitives |
| Per-member constraints | Ignored | Mandatory: value range, SIZE, alphabet, extensibility flag |

#### IDecodeStream / IEncodeStream

Both BER and PER subclass `IDecodeStream` / `IEncodeStream`. PER subclasses need
bit-level operations that BER subclasses expose but never call:

```cpp
class IDecodeStream {
public:
    virtual Expected<uint64_t, DecodeError> get_bits(int n) = 0;  // PER: read n bits
    virtual Expected<void, DecodeError>     align() = 0;           // PER: byte-align
    // BER uses read_tlv() via dynamic_cast or a separate byte-stream method
};
```

#### Descriptor table fields required for PER — add now, not later

Changing table structure after code generation requires regenerating every file.
Add PER fields as nullable pointers / zeros from the start:

**`SequenceSpec` additions:**
```cpp
struct SequenceSpec {
    const MemberDescriptor* members;
    int count;
    int ext_at;          // index of first extension member; -1 = none

    // PER-specific (nullptr / 0 until PER codegen is implemented)
    int roms_count;      // root optional member count (width of preamble bitmap)
    int aoms_count;      // extension optional member count
    const int* oms;      // array of optional-member indices (length = roms_count + aoms_count)
};
```

**`MemberDescriptor` additions:**
```cpp
struct MemberDescriptor {
    const char*  name;
    Tag          tag;
    bool         optional;
    bool         has_default;
    std::size_t  offset;
    const void*  type_descriptor;

    // PER-specific (nullptr / false until PER codegen is implemented)
    const PerConstraints* per_constraints;  // value range, size, alphabet, flags
    bool is_extension;                      // needs open-type wrapping in PER
    int  (*default_value_cmp)(const void*); // suppress DEFAULT-valued fields in PER
};
```

**`ChoiceSpec` addition:**
```cpp
struct ChoiceSpec {
    const MemberDescriptor* alternatives;
    int count;
    int ext_at;

    // PER-specific
    const PerConstraints* per_constraints;  // range_bits for constrained CHOICE index
};
```

**`PerConstraints` struct** (separate header `codec/PerConstraints.hpp`):
```cpp
struct PerConstraints {
    enum Flags { CONSTRAINED = 1, SEMI_CONSTRAINED = 2, EXTENSIBLE = 4 };
    int      flags;
    int      range_bits;   // bits needed to encode (upper - lower + 1) values
    int64_t  lower_bound;
    int64_t  upper_bound;
    // Size constraint (for OCTET STRING, BIT STRING, strings)
    int      size_range_bits;
    int64_t  size_lower;
    int64_t  size_upper;
};
```

#### PER codec implementation complexity

`PerCodec` (stub for now) will eventually need:
1. Read/write `roms_count`-bit preamble bitmap before any SEQUENCE member
2. For each optional root member: check bitmap bit, skip if absent
3. If extension flag set: read extension bitmap (length-prefixed), then per-present
   extension member as open-type (length-prefixed octet string)
4. CHOICE: read `range_bits` bits → member index; handle extension path
5. INTEGER/ENUMERATED/strings: use `per_constraints` for minimal-bit encoding

This is significantly more complex than BER but is **fully hideable behind `ICodec`**.
The generated tables carry the metadata; the codec interprets it. Generated files stay
table-only with no PER-specific logic.

### RE/flex quirks (6.1.0)
- Use `%option bison-complete` (not `bison-cc`). `bison-cc-parser` causes double-namespace `yy::yy`.
- Grouped state blocks `<s>{ ... }` generate broken C++ — expand to individual `<s>rule` lines.
- `text()` returns `const char*`, not `std::string`.

### Grammar portability rule
`asn1c/libasn1parser/asn1p_l.l` and `asn1p_y.y` are the **immutable reference grammar**. Port them with the smallest possible changes needed for Bison C++ mode and RE/flex. `asn1c` (installed at `/usr/local/bin/asn1c`) is the cross-validation ground truth — test ASN.1 files against it before debugging the asn1cpp parser.

## Testing

### Goal

All asn1c parser and BER tests must run automatically inside the asn1cpp codebase.
The asn1c test suite is the ground truth; asn1cpp must pass every test it passes.

### Test layout

```
tests/
  asn1/                          # asn1cpp-authored codec round-trip schemas
  asn1c-tests/                   # mirror of asn1c test tree (copied verbatim)
    tests-asn1c-compiler/        # 188 parser tests (*-OK, *-NP, *-SE)
    tests-c-compiler/            # BER/DER test vectors + schemas
      data-62/                   # 33 .ber + 33 .xbr vectors (ANY/CHOICE/SET/SEQUENCE)
      data-70/
      data-119/
      data-126/
      data-202/
```

### Current status

| Suite | Pass | Total | Notes |
|-------|------|-------|-------|
| Parser (-OK) | 145 | 145 | all pass |
| Parser (-NP) | 3 | 3 | correctly rejected |
| Parser (-SE) | 34 | 35 | semantic errors not yet validated |
| BER vectors (data-62) | 0 | 33 | not yet wired into ctest |

### BER codec coverage gaps (vs asn1c tests)

Constructs present in asn1c tests, absent from asn1cpp BER round-trip tests:

| Construct | asn1c test files | Priority |
|-----------|-----------------|----------|
| SET / SET OF | 31, 35, 47, 94 | high — different codec logic from SEQUENCE |
| DEFAULT values | 50, 81, 148 | high — suppress on encode, fill on decode |
| EXPLICIT / IMPLICIT tagging | 17, 21, 22, 29, 65, 86 | high — changes BER structure |
| Basic ENUMERATED (non-extensible) | 03, 68, 88, 129, 130 | medium — only ext variant tested |
| Recursive types | 43, 73, 92 | medium — self-ref pointer handling |
| WITH COMPONENTS | 55, 57, 82, 83, 150 | low |

## Commits

Do not add `Co-Authored-By` lines to commits in this repository.
