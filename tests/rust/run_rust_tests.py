#!/usr/bin/env python3
"""Compile-and-run check for tests/rust/*.rs against the actual patterns
RustBackend emits (see compiler/src/codegen/RustBackend.cpp and
tests/codegen/test_backend_naming.cpp, which the .rs files here mirror by
hand). Each file must compile warning-free under `-D warnings` and print
"ok" when run.

Usage: run_rust_tests.py --rustc /path/to/rustc [--verbose]
"""
import argparse
import pathlib
import subprocess
import sys
import tempfile


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rustc", required=True)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    src_dir = pathlib.Path(__file__).parent
    rs_files = sorted(src_dir.glob("*.rs"))
    if not rs_files:
        print("no .rs files found", file=sys.stderr)
        return 1

    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for rs in rs_files:
            out_bin = pathlib.Path(tmp) / rs.stem
            compile_cmd = [
                args.rustc, "--edition", "2021", "-W", "unused", "-D", "warnings",
                str(rs), "-o", str(out_bin),
            ]
            if args.verbose:
                print(f"[compile] {rs.name}")
            r = subprocess.run(compile_cmd, capture_output=True, text=True)
            if r.returncode != 0:
                failures.append((rs.name, "compile", r.stderr))
                continue

            if args.verbose:
                print(f"[run]     {rs.name}")
            r = subprocess.run([str(out_bin)], capture_output=True, text=True)
            if r.returncode != 0 or "ok" not in r.stdout:
                failures.append((rs.name, "run", r.stdout + r.stderr))
                continue

            print(f"  PASS  {rs.name}")

    if failures:
        for name, stage, detail in failures:
            print(f"  FAIL  {name} ({stage})\n{detail}", file=sys.stderr)
        print(f"\n{len(failures)}/{len(rs_files)} failed", file=sys.stderr)
        return 1

    print(f"\nAll {len(rs_files)} Rust patterns compiled and ran correctly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
