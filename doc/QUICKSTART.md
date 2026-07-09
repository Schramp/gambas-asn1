# asn1cpp

A modern C++20 ASN.1 compiler. Reads ASN.1 schemas and generates C++ type
definitions with BER, XER, and PER codec support via a runtime library.

## Features

- BER and XER encode/decode
- UPER (PER) encode/decode for constrained types
- Generated code is descriptor-table-only — no codec logic in generated files
- Constraint validation with optional path tracking
- Cross-validated against the asn1c reference compiler

## Dependencies

| Tool | Version | Notes |
|------|---------|-------|
| CMake | ≥ 3.20 | |
| GCC / Clang | C++20 | GCC 13+ recommended |
| Bison | ≥ 3.8 | GNU Bison |
| RE/flex | 6.1.0 | Must be built from source — see below |

### Install RE/flex

```bash
git clone --branch v6.1.0 --depth 1 https://github.com/Genivia/RE-flex
cd RE-flex
./build.sh
sudo cp bin/reflex /usr/local/bin/
sudo cp -r include/reflex /usr/local/include/
sudo cp lib/libreflex.a /usr/local/lib/
```

### Install Bison (Ubuntu / Debian)

```bash
sudo apt-get install bison
```

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel $(nproc)
```

The compiler binary is at `build/compiler/asn1cpp`.

## Run

```bash
./build/compiler/asn1cpp path/to/schema.asn1 -o output/dir/
```

Generates one `.hpp` + `.cpp` pair per ASN.1 type in the output directory.

## Test

```bash
ctest --test-dir build --output-on-failure
```

## Build the ETSI LI example library

Compiles all ETSI TS 102 232 / TS 101 909 schemas into a static library
(`lib/libasn1cpp_etsi.a`):

```bash
make -C examples/sample.source.ETSI-LI-PS-PDU -j$(nproc)
```

## Optional: asn1c cross-validation

Set `ASN1C_BIN_DIR` to enable cross-validation tests against the asn1c
reference compiler:

```bash
cmake -B build -DASN1C_BIN_DIR=/path/to/asn1c/build
```

## Runtime debug tracing

Set `ASN1CPP_DEBUG` to a hex bitmask at runtime — no recompile needed:

| Bit | What it traces |
|-----|---------------|
| `0x01` | CHOICE tag misses |
| `0x02` | SEQUENCE EXPLICIT wrap/unwrap |
| `0x08` | PER bit-level ops |
| `0x10` | BER encode: members, tags, byte counts |

```bash
ASN1CPP_DEBUG=0x10 ./ber-to-xer --type MyType input.ber
```

## License

BSD 2-Clause — see [LICENSE](../LICENSE).
