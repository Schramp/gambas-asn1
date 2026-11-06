#!/usr/bin/env bash
# cmake --install into a scratch prefix, move the prefix, then use it the
# way INSTALL.md describes: the compiler must find its predefined module
# relative to itself, and a C++ program built from generated code against
# the installed headers and libasn1cpp_runtime.a must run.
set -euo pipefail
build_dir=$1
source_dir=$2
cxx=${3:-c++}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cmake --install "$build_dir" --prefix "$work/prefix" > /dev/null
mv "$work/prefix" "$work/moved"
p=$work/moved

"$p/bin/asn1cpp" --help | grep -q "Default: $p/share/asn1cpp/predefined" \
    || { echo "installed compiler does not read $p/share/asn1cpp/predefined"; exit 1; }
for f in lib/libasn1cpp_runtime.a lib/cmake/asn1cpp/asn1cppConfig.cmake \
         include/asn1cpp/asn1cpp.hpp share/asn1cpp/rust-runtime/wire/Cargo.toml; do
    [ -e "$p/$f" ] || [ -e "$p/${f/lib\//lib64/}" ] || { echo "missing $f"; exit 1; }
done

cd "$work"
cp "$source_dir/examples/contact-book/contact.asn1" "$source_dir/examples/contact-book/main.cpp" .
"$p/bin/asn1cpp" contact.asn1 -o gen > /dev/null
lib=$(ls "$p"/lib*/libasn1cpp_runtime.a | head -1)
"$cxx" -std=c++20 -Igen -I"$p/include" main.cpp gen/*.cpp "$lib" -o app
./app | grep -q "<name>Alice Example</name>" || { echo "consumer output wrong"; exit 1; }
echo "install smoke: OK"
