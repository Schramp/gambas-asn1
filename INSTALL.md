# Installing gambas-asn1

gambas-asn1 is a compiler (`asn1cpp`) plus one runtime for each target
language: C++ (`runtime/`), Rust (`rust-runtime/wire/`) and Java
(`java-runtime/`). Generated code uses the runtime API of the compiler commit
that produced it, so install the compiler and the runtimes from the same
checkout, and install them again after you update it.

The top-level `VERSION` file holds the one version of the compiler and all
runtimes. CMake and Gradle read it. The CMake configure step stops when one
of these copies, which cannot read the file, has another version:

- `rust-runtime/wire/Cargo.toml` (`version = "X.Y.Z"`, which every
  generated Rust file asserts on at compile time);
- `runtime/include/asn1cpp/Version.hpp` (the `ASN1CPP_RUNTIME_VERSION*`
  macros, which every generated C++ header `static_assert`s on, and the
  library symbol `asn1::runtime_version_X_Y_Z` they name, which every
  generated C++ source refers to);
- the Java runtime's marker class
  `java-runtime/src/main/java/io/github/schramp/gambasasn1/wire/RuntimeVersion_X_Y_Z.java`,
  which every generated Java class refers to (Gradle also checks it is the
  only one, so a release cannot ship a stale marker);
- `examples/contact-book/maven/pom.xml`'s default `gambasasn1.version`
  (`X.Y.Z-SNAPSHOT`; the example's Makefile reads `VERSION` itself).

A Java runtime built from a checkout is `VERSION` plus `-SNAPSHOT`; a release
is published from tag `java-runtime-vX.Y.Z` only when `X.Y.Z` is the
`VERSION` of that commit.

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

By hand:

```bash
asn1cpp --target=java --package=contacts contact.asn1 -o src/main/java/contacts
```

The generated sources need nothing but `gambasasn1-wire` on the class path.

From Maven, so that `mvn compile` regenerates the code with the matching
compiler: run `asn1cpp` in the `generate-sources` phase with
`-require-version=${gambasasn1.version}` and add its output as a source root.
`-require-version` stops the build when the compiler (`asn1cpp --version`) is
not the version of the runtime:

```xml
<properties>
  <gambasasn1.version>0.1.0-SNAPSHOT</gambasasn1.version>
  <asn1cpp.executable>asn1cpp</asn1cpp.executable>
  <asn1cpp.generated>${project.build.directory}/generated-sources/asn1cpp</asn1cpp.generated>
</properties>

<plugin>
  <groupId>org.codehaus.mojo</groupId>
  <artifactId>exec-maven-plugin</artifactId>
  <version>3.5.0</version>
  <executions>
    <execution>
      <id>asn1cpp</id>
      <phase>generate-sources</phase>
      <goals><goal>exec</goal></goals>
      <configuration>
        <executable>${asn1cpp.executable}</executable>
        <arguments>
          <argument>-require-version=${gambasasn1.version}</argument>
          <argument>-target=java</argument>
          <argument>-package=contacts</argument>
          <argument>${project.basedir}/src/main/asn1/contact.asn1</argument>
          <argument>-o</argument>
          <argument>${asn1cpp.generated}/contacts</argument>
        </arguments>
      </configuration>
    </execution>
  </executions>
</plugin>
<plugin>
  <groupId>org.codehaus.mojo</groupId>
  <artifactId>build-helper-maven-plugin</artifactId>
  <version>3.6.0</version>
  <executions>
    <execution>
      <id>asn1cpp-sources</id>
      <phase>generate-sources</phase>
      <goals><goal>add-source</goal></goals>
      <configuration>
        <sources><source>${asn1cpp.generated}</source></sources>
      </configuration>
    </execution>
  </executions>
</plugin>
```

Pass `-Dasn1cpp.executable=<path>` when the compiler is not on the `PATH`.
`examples/contact-book/maven/` is the complete project. Its `pom.xml` also
checks the compiler before generating (maven-antrun-plugin, `initialize`
phase): when the compiler is missing or another version, the build stops
with the git ref to build (`main` for a `-SNAPSHOT` runtime, tag
`java-runtime-vX.Y.Z` for a release) and the commands from this file. Copy
that plugin and the `regex-property` execution too for the same message in
your own project.

Two ways to keep a project's generated code:

- **ASN.1 checked in, compiler needed** (the default above): every build
  checks the compiler and regenerates into `target/generated-sources`.
- **Generated code checked in, runtime only**: set `asn1cpp.skip` to `true`
  and `asn1cpp.generated` to a committed directory. A plain build then needs
  no compiler and compiles the committed code; `mvn -Dasn1cpp.skip=false
  generate-sources` regenerates it with the checked compiler, after which you
  commit the result. The committed code still refers to its runtime's
  version marker, so it does not compile against a runtime of another
  version, and each file's first line names the compiler version that
  produced it.

`make test` in `examples/contact-book/maven/` builds both ways. `make test` there
installs the runtime into a private repository (`m2/`), runs `mvn compile`
and checks the output.

To uninstall:

```bash
rm -rf ~/.m2/repository/io/github/schramp/gambasasn1
```
