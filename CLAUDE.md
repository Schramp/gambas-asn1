# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

Run BER tests:
```bash
ctest --test-dir build/tests
```

Run compiler:
```bash
./build/compiler/asn1cpp <file.asn1> -o <outdir>
```

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

### RE/flex quirks (6.1.0)
- Use `%option bison-complete` (not `bison-cc`). `bison-cc-parser` causes double-namespace `yy::yy`.
- Grouped state blocks `<s>{ ... }` generate broken C++ — expand to individual `<s>rule` lines.
- `text()` returns `const char*`, not `std::string`.

### Grammar portability rule
`asn1c/libasn1parser/asn1p_l.l` and `asn1p_y.y` are the **immutable reference grammar**. Port them with the smallest possible changes needed for Bison C++ mode and RE/flex. `asn1c` (installed at `/usr/local/bin/asn1c`) is the cross-validation ground truth — test ASN.1 files against it before debugging the asn1cpp parser.

## Commits

Do not add `Co-Authored-By` lines to commits in this repository.
