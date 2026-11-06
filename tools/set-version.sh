#!/bin/sh
# set-version.sh X.Y.Z: set the version of the compiler and every runtime.
#
# VERSION is the one version; this rewrites the copies that cannot read it
# (see INSTALL.md): rust-runtime/wire/Cargo.toml and every tracked
# Cargo.lock that pins asn1cpp-wire, the runtime/include/asn1cpp/Version.hpp
# macros, the Java runtime's RuntimeVersion_X_Y_Z marker class (renamed with
# git mv) and the Maven example's default gambasasn1.version. The CMake
# configure step's version checks then run against a scratch build
# directory, unless --no-check is given.
set -eu

usage() { echo "usage: $0 [--no-check] X.Y.Z" >&2; exit 2; }

check=1
[ "${1:-}" = "--no-check" ] && { check=0; shift; }
[ $# -eq 1 ] || usage
v=$1
printf '%s' "$v" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || { echo "not a version X.Y.Z: '$v'" >&2; exit 2; }
major=${v%%.*}; rest=${v#*.}; minor=${rest%%.*}; patch=${rest#*.}
ident=$(printf '%s' "$v" | tr . _)

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
old=$(cat VERSION)

printf '%s\n' "$v" > VERSION

sed -i "s/^version = \".*\"/version = \"$v\"/" rust-runtime/wire/Cargo.toml
# In a lock file, the version line right after the asn1cpp-wire package name.
git ls-files '*Cargo.lock' | while read -r lock; do
    sed -i "/^name = \"asn1cpp-wire\"\$/{n;s/^version = \".*\"/version = \"$v\"/}" "$lock"
done

h=runtime/include/asn1cpp/Version.hpp
sed -i -e "s/^#define ASN1CPP_RUNTIME_VERSION_MAJOR .*/#define ASN1CPP_RUNTIME_VERSION_MAJOR $major/" \
       -e "s/^#define ASN1CPP_RUNTIME_VERSION_MINOR .*/#define ASN1CPP_RUNTIME_VERSION_MINOR $minor/" \
       -e "s/^#define ASN1CPP_RUNTIME_VERSION_PATCH .*/#define ASN1CPP_RUNTIME_VERSION_PATCH $patch/" \
       -e "s/^#define ASN1CPP_RUNTIME_VERSION \".*\"/#define ASN1CPP_RUNTIME_VERSION \"$v\"/" "$h"

dir=java-runtime/src/main/java/io/github/schramp/gambasasn1/wire
new_marker=$dir/RuntimeVersion_$ident.java
for m in "$dir"/RuntimeVersion_*.java; do
    [ "$m" = "$new_marker" ] || git mv "$m" "$new_marker"
done
sed -i -e "s/RuntimeVersion_[0-9_]*/RuntimeVersion_$ident/g" \
       -e "s/Marks this runtime as version [0-9.]*\./Marks this runtime as version $v./" "$new_marker"
git add "$new_marker"

sed -i "s|<gambasasn1.version>.*</gambasasn1.version>|<gambasasn1.version>$v-SNAPSHOT</gambasasn1.version>|" \
    examples/contact-book/maven/pom.xml

echo "version $old -> $v"

if [ $check -eq 1 ]; then
    scratch=$(mktemp -d)
    trap 'rm -rf "$scratch"' EXIT
    if ! cmake -S "$root" -B "$scratch" > "$scratch/configure.log" 2>&1; then
        grep -A3 "CMake Error" "$scratch/configure.log" >&2 || cat "$scratch/configure.log" >&2
        echo "the configure step's version checks failed" >&2
        exit 1
    fi
    echo "configure step's version checks pass"
fi
