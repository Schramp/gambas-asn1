# Installing gambas-asn1

gambas-asn1 is a compiler (`asn1cpp`) plus one runtime for each target
language: C++ (`runtime/`), Rust (`rust-runtime/wire/`) and Java
(`java-runtime/`). Generated code uses the runtime API of the compiler commit
that produced it, so install the compiler and the runtimes from the same
checkout, and install them again after you update it.

## 1. Build

Needs CMake ≥ 3.20, GCC or Clang with C++20, Bison ≥ 3.8 and RE/flex 6.1.0.
How to install those is in [doc/QUICKSTART.md](doc/QUICKSTART.md#dependencies).

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build --parallel $(nproc)
```

You can also run the compiler straight from the build tree
(`build/compiler/asn1cpp`), without installing.

## 2. Install the compiler, the C++ runtime and the Rust runtime

```bash
sudo cmake --install build             # or: cmake --install build --prefix ~/.local
```

This installs, under the prefix:

| Path | What |
|---|---|
| `bin/asn1cpp` | the compiler |
| `share/asn1cpp/predefined/` | the predefined-classes module the compiler reads before every input (TYPE-IDENTIFIER, ABSTRACT-SYNTAX, EXTERNAL) |
| `include/asn1cpp/` | C++ runtime headers |
| `lib/libasn1cpp_runtime.a` | C++ runtime library |
| `lib/cmake/asn1cpp/` | CMake package files for `find_package(asn1cpp)` |
| `share/asn1cpp/rust-runtime/wire/` | Rust runtime crate `asn1cpp-wire`, as source |

The installed compiler finds `share/asn1cpp/predefined` relative to its own
location, so you can move the whole prefix (`--stdlib-dir` overrides it). On a
Debian-style multiarch prefix, `lib` may be `lib/x86_64-linux-gnu`
(GNUInstallDirs).

Build options the C++ runtime was built with are also passed on to programs
that use it through `find_package`. These are the `ASN1CPP_VALIDATE*`
switches and `-DASN1CPP_MAX_ZERO_WIDTH_ITEMS=N`, the PER limit on list items
encoded in zero bits (see Known Limitations in [doc/book.md](doc/book.md)).

### Using the C++ runtime

With CMake:

```cmake
find_package(asn1cpp 0.1 REQUIRED)    # sets ASN1CPP_EXECUTABLE too

set(GEN ${CMAKE_CURRENT_BINARY_DIR}/gen)
execute_process(COMMAND ${ASN1CPP_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/contact.asn1 -o ${GEN}
                COMMAND_ERROR_IS_FATAL ANY)
file(GLOB GEN_SRCS ${GEN}/*.cpp)

add_executable(app main.cpp ${GEN_SRCS})
target_include_directories(app PRIVATE ${GEN})
target_link_libraries(app PRIVATE asn1cpp::runtime)
```

For a prefix outside the default search path, configure with
`-DCMAKE_PREFIX_PATH=<prefix>`.

Without CMake:

```bash
asn1cpp contact.asn1 -o gen
g++ -std=c++20 -Igen -I/usr/local/include main.cpp gen/*.cpp \
    /usr/local/lib/libasn1cpp_runtime.a -o app
```

`examples/contact-book/` is a complete C++ example (`make run`). It builds
against the build tree.

### Using the Rust runtime

Generate the types into a crate's `src/`. The generated `lib.rs` is the crate
root, with one module per type:

```bash
asn1cpp --target=rust contact.asn1 -o src
```

and depend on the installed crate by path in `Cargo.toml`:

```toml
[lib]
path = "src/lib.rs"

[dependencies]
asn1cpp-wire = { path = "/usr/local/share/asn1cpp/rust-runtime/wire" }
```

The crate has no dependencies of its own. Use it from a binary with, for
example, `asn1cpp_wire::ber::object::{decode_pdu, encode_pdu}`.

### Uninstalling

CMake records every installed file in `build/install_manifest.txt`:

```bash
sudo xargs rm -f < build/install_manifest.txt
```

## 3. Install the Java runtime into the local Maven repository

Needs JDK 21. The Gradle wrapper is checked in, so you do not need to install
Gradle. `cmake --install` does not install the Java runtime; Maven and Gradle
take it from the local Maven repository:

```bash
./java-runtime/gradlew -p java-runtime publishToMavenLocal
```

This installs `io.github.schramp.gambasasn1:gambasasn1-wire:0.1.0-SNAPSHOT`
into `~/.m2/repository/io/github/schramp/gambasasn1/gambasasn1-wire/`: the jar,
its POM and Gradle module file, and the `-sources` and `-javadoc` jars. No
signing key is needed for a local install. Options:

- `-Pversion=X.Y.Z` installs under another version.
- `-Dmaven.repo.local=<dir>` installs into another local repository instead of
  `~/.m2/repository`.

Run the command as the user whose `~/.m2` you want, not with `sudo`. Run it
again after you update the checkout.

### Maven

```xml
<dependency>
  <groupId>io.github.schramp.gambasasn1</groupId>
  <artifactId>gambasasn1-wire</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Maven looks in `~/.m2/repository` first, so this needs no extra repository
entry.

### Gradle (Kotlin DSL)

```kotlin
repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("io.github.schramp.gambasasn1:gambasasn1-wire:0.1.0-SNAPSHOT")
}
```

### Generating Java

```bash
asn1cpp --target=java --package=contacts contact.asn1 -o src/main/java/contacts
```

The generated sources need nothing but `gambasasn1-wire` on the class path.
`examples/contact-book/maven/` is a complete Maven project. `make test` there
installs the runtime into a private repository (`m2/`), generates the
classes, compiles them with Maven and checks the output.

To uninstall:

```bash
rm -rf ~/.m2/repository/io/github/schramp/gambasasn1
```
