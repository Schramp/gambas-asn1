#!/usr/bin/env python3
"""
Validate asn1cpp's Rust backend (--target=rust) against this repo's own
test ASN.1 corpus (tests/asn1/*.asn1) — the Rust-codegen equivalent of
asn1cpp-validation-tools/validate_parser.py's C++ parser-conformance
sweep, gambas-asn1#309. Part of the normal asn1cpp build/test process
(wired into ctest, tests/CMakeLists.txt), not a separate external tool.

For each *.asn1 file:
  1. Run asn1cpp --target=rust into a fresh scratch directory.
     - Non-zero exit / crash -> FAIL, category "codegen" (a real compiler
       bug: codegen should never crash regardless of construct coverage).
  2. Otherwise, scaffold a throwaway Cargo crate depending on
     rust-runtime/ber and `cargo build` it.
     - Non-zero exit -> FAIL, category "compile" (construct not yet
       supported by the table-driven runtime, or a real codegen bug —
       most of these are *expected* at this stage, not exit-code failures).
  3. Otherwise -> PASS.

No requirement that every file passes (per gambas-asn1#309: this is a
wiring/reporting tool, not a gate) - exits non-zero only on a "codegen"
category failure (crash), never on a "compile" category failure (known
gap) - so the wrapping ctest stays green as coverage gaps are found and
fixed incrementally, only turning red on an actual compiler crash.
Prints a validate_parser.py-style summary table plus an aggregate N/M line.

Usage:
    python3 validate_rust_codegen.py --asn1cpp-bin build/compiler/asn1cpp [--verbose]
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]  # asn1cpp/
RUST_RUNTIME_BER = REPO / "rust-runtime/ber"
TEST_DIR = REPO / "tests/asn1"

CARGO_TOML_TEMPLATE = """\
[package]
name = "validate-rust-codegen-{name}"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
path = "src/lib.rs"

[dependencies]
asn1cpp-ber = {{ path = "{rust_runtime_ber}" }}
"""


def expects_failure(asn1_file: Path) -> bool:
    """Some tests/asn1/ fixtures are deliberately invalid ASN.1 (e.g.
    missing_module_test.asn1: 'Should fail: error on missing module.') —
    unlike asn1c's tests-asn1c-compiler corpus, this repo's own fixtures
    have no -OK/-SE/-NP filename convention, so detect intent from a
    leading comment instead. A non-zero asn1cpp exit on one of these is
    correct behavior, not a codegen crash."""
    head = asn1_file.read_text(errors="replace")[:500].lower()
    return "should fail" in head or "expected to fail" in head or "must fail" in head


def run_codegen(asncpp: Path, asn1_file: Path, out_dir: Path, verbose: bool) -> tuple[bool, str]:
    r = subprocess.run(
        [str(asncpp), str(asn1_file), "--target=rust", "-o", str(out_dir)],
        capture_output=True, text=True, timeout=30,
    )
    if verbose:
        print(r.stdout, end="")
        print(r.stderr, end="", file=sys.stderr)
    if r.returncode != 0:
        first_line = (r.stderr or r.stdout).strip().splitlines()[:1]
        return False, (first_line[0] if first_line else f"exit {r.returncode}")
    if not any(out_dir.glob("*.rs")):
        return False, "no .rs files generated"
    return True, ""


def run_cargo_build(cargo: str, crate_dir: Path, verbose: bool) -> tuple[bool, str]:
    r = subprocess.run(
        [cargo, "build", "--quiet"],
        cwd=crate_dir, capture_output=True, text=True, timeout=120,
    )
    if verbose:
        print(r.stdout, end="")
        print(r.stderr, end="", file=sys.stderr)
    if r.returncode != 0:
        for line in r.stderr.splitlines():
            line = line.strip()
            if line.startswith("error"):
                return False, line[:100]
        return False, f"exit {r.returncode}"
    return True, ""


def validate_one(asncpp: Path, cargo: str, asn1_file: Path, verbose: bool) -> tuple[str, str, str]:
    """Returns (verdict, category, detail)."""
    with tempfile.TemporaryDirectory(prefix="rustcodegen_") as tmp:
        tmp_path = Path(tmp)
        gen_dir = tmp_path / "crate" / "src"
        gen_dir.mkdir(parents=True)

        ok, detail = run_codegen(asncpp, asn1_file, gen_dir, verbose)
        if not ok:
            if expects_failure(asn1_file):
                return "SKIP", "expected-fail", detail
            return "FAIL", "codegen", detail

        crate_dir = tmp_path / "crate"
        (crate_dir / "Cargo.toml").write_text(
            CARGO_TOML_TEMPLATE.format(
                name=asn1_file.stem.lower().replace("_", "-"),
                rust_runtime_ber=RUST_RUNTIME_BER,
            )
        )

        ok, detail = run_cargo_build(cargo, crate_dir, verbose)
        if not ok:
            return "FAIL", "compile", detail

        return "PASS", "", ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asn1cpp-bin", required=True, help="path to the asn1cpp compiler binary")
    ap.add_argument("--cargo", default="cargo", help="cargo executable (default: cargo on PATH)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    asncpp = Path(args.asn1cpp_bin).resolve()
    if not asncpp.exists():
        print(f"asn1cpp binary not found: {asncpp}", file=sys.stderr)
        return 1
    if not RUST_RUNTIME_BER.exists():
        print(f"rust-runtime/ber not found: {RUST_RUNTIME_BER}", file=sys.stderr)
        return 1

    files = sorted(TEST_DIR.glob("*.asn1"))
    if not files:
        print(f"No .asn1 files in {TEST_DIR}", file=sys.stderr)
        return 1

    results = []
    codegen_crashes = 0
    for f in files:
        verdict, category, detail = validate_one(asncpp, args.cargo, f, args.verbose)
        results.append((f.name, verdict, category, detail))
        if verdict == "FAIL" and category == "codegen":
            codegen_crashes += 1

    name_w = max(len(r[0]) for r in results)
    colors = {"PASS": "\033[32m", "FAIL": "\033[31m", "SKIP": "\033[33m"}
    for name, verdict, category, detail in results:
        color = colors.get(verdict, "")
        tag = f"[{category}] " if category else ""
        print(f"  {color}{verdict:4}\033[0m  {name:<{name_w}}  {tag}{detail}")

    passed = sum(1 for r in results if r[1] == "PASS")
    skipped = sum(1 for r in results if r[1] == "SKIP")
    counted = len(results) - skipped
    print(f"\n{passed}/{counted} passed" + (f" ({skipped} skipped, expected-fail fixtures)" if skipped else ""))
    if codegen_crashes:
        print(f"{codegen_crashes} codegen crash(es) — real compiler bug(s), not a coverage gap", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
