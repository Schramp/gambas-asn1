#!/usr/bin/env python3
"""
run_smoke_matrix.py — smoke-test the asn1cpp compiler against a type × flag matrix.

For each ASN.1 built-in type: generate a minimal one-type schema, run asn1cpp,
then compile the generated C++ with g++ to verify no codegen or compile errors.

Usage:
    python3 run_smoke_matrix.py --compiler <path/to/asn1cpp> \\
                                --runtime-inc <path/to/runtime/include>

Exit 0 if all combinations pass, 1 otherwise.
"""

import argparse
import glob
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# 17 types mirroring the asn1c smoke test suite.
TYPES = [
    "INTEGER",
    "INTEGER (0..1)",
    "ENUMERATED { foo, bar }",
    "NULL",
    "BOOLEAN",
    "BIT STRING",
    "OBJECT IDENTIFIER",
    "RELATIVE-OID",
    "SEQUENCE { f INTEGER }",
    "CHOICE { f INTEGER, g NULL }",
    "OCTET STRING",
    "IA5String",
    "IA5String (SIZE (1..10))",
    "UTF8String",
    "REAL",
    "SET OF INTEGER",
    "SEQUENCE OF INTEGER",
]

# Flag combinations to test.  Each is a list of extra args for asn1cpp.
FLAG_SETS = [
    ([], "no-flags"),
    (["-fprefix=myns"], "-fprefix"),
    (["-pdu=T"], "-pdu"),
    (["-fprefix=myns", "-pdu=T"], "-fprefix-and-pdu"),
]


def run_cmd(args, **kwargs):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30, **kwargs)


def type_label(t):
    return t.replace(" ", "_").replace("(", "").replace(")", "") \
            .replace("{", "").replace("}", "").replace("..", "").replace(",", "")


def smoke_one(compiler, runtime_inc, asn_type, extra_flags, workdir):
    schema = (
        "Module DEFINITIONS IMPLICIT TAGS ::= BEGIN\n"
        f"    T ::= {asn_type}\n"
        "END\n"
    )
    schema_file = workdir / "T.asn1"
    gen_dir = workdir / "gen"
    obj_dir = workdir / "obj"
    schema_file.write_text(schema)
    gen_dir.mkdir()
    obj_dir.mkdir()

    # Step 1: generate C++
    r = run_cmd([str(compiler)] + extra_flags + [str(schema_file), "-o", str(gen_dir)])
    if r.returncode != 0:
        return False, f"asn1cpp exit {r.returncode}\n" + r.stderr.decode()

    # Step 2: compile every generated .cpp
    cpps = list(gen_dir.glob("*.cpp"))
    if not cpps:
        return False, "asn1cpp produced no .cpp files"

    for cpp in cpps:
        obj = obj_dir / (cpp.stem + ".o")
        r = run_cmd([
            "g++", "-std=c++20", "-c",
            "-I", str(gen_dir),
            "-I", str(runtime_inc),
            str(cpp), "-o", str(obj),
        ])
        if r.returncode != 0:
            return False, f"g++ failed on {cpp.name}\n" + r.stderr.decode()

    return True, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compiler", required=True)
    ap.add_argument("--runtime-inc", required=True)
    args = ap.parse_args()

    compiler = Path(args.compiler)
    runtime_inc = Path(args.runtime_inc)

    if not compiler.exists():
        print(f"ERROR: compiler not found: {compiler}", file=sys.stderr)
        sys.exit(1)

    passes = 0
    failures = []

    tmpbase = Path(tempfile.mkdtemp(prefix="asn1cpp_smoke_"))
    try:
        for asn_type in TYPES:
            for flags, flag_label in FLAG_SETS:
                label = f"{type_label(asn_type)} [{flag_label}]"
                workdir = tmpbase / f"{type_label(asn_type)}_{flag_label}"
                workdir.mkdir()
                ok, msg = smoke_one(compiler, runtime_inc, asn_type, flags, workdir)
                if ok:
                    passes += 1
                    print(f"  PASS  {label}")
                else:
                    failures.append((label, msg))
                    print(f"  FAIL  {label}")
                    for line in msg.strip().splitlines():
                        print(f"        {line}")
    finally:
        shutil.rmtree(tmpbase, ignore_errors=True)

    total = len(TYPES) * len(FLAG_SETS)
    print(f"\n{passes}/{total} passed", end="")
    if failures:
        print(f", {len(failures)} failed")
        sys.exit(1)
    else:
        print()


if __name__ == "__main__":
    main()
