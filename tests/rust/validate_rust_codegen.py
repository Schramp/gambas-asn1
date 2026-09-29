#!/usr/bin/env python3
"""
Validate asn1cpp's Rust backend (--target=rust) against this repo's own
test ASN.1 corpus — the Rust-codegen equivalent of asn1cpp-validation-
tools/validate_parser.py's C++ parser-conformance sweep, gambas-asn1#309.
Part of the normal asn1cpp build/test process (wired into ctest,
tests/CMakeLists.txt), not a separate external tool.

Two corpora, selected with --corpus:
  - "asn1" (default): tests/asn1/*.asn1, this repo's own hand-authored
    fixtures. No -OK/-SE/-NP naming convention; a fixture that's meant to
    be rejected says so in a leading comment (see expects_failure()).
  - "asn1c-compiler": tests/tests-asn1c-compiler/*.asn1, the ~207-file
    mirror of asn1c's own test suite (parser_conformance already runs
    these through the parser for both backends equally; this sweep is the
    first thing that actually generates + compiles Rust for the whole
    corpus, not just the curated handful in validation-tools/xval_sweep/
    targets.txt). -SE/-NP files are expected to fail codegen (semantic/
    parse error, X.680 violation) — treated as SKIP via the filename
    suffix, same convention parser_conformance itself relies on. A name
    listed in parser_known_failures.txt (the same file CMakeLists.txt and
    validate_parser.py already read — see that file's own header) is also
    SKIP: an already-tracked parser gap, not a new Rust-codegen finding.
    Separately, a name listed in tests/rust_codegen_known_crashes.txt is
    SKIP'd specifically for a hard crash (see is_hard_crash()) that's
    already filed as an issue — that file's own header explains why this
    is a distinct list from parser_known_failures.txt (a crash, not a
    graceful parser rejection).
  - "all": both, concatenated.

For each *.asn1 file:
  1. Run asn1cpp --target=rust into a fresh scratch directory.
     - A hard crash (aborted/segfaulted/uncaught C++ exception, see
       is_hard_crash()) -> FAIL, category "codegen" (a real compiler bug:
       codegen should never crash regardless of construct coverage) —
       unless expects_failure() says this file is supposed to be rejected.
     - A graceful `error: ...`-and-exit-1 rejection that isn't expected ->
       FAIL, category "reject" (real gap, but not a crash — most common on
       --corpus=asn1c-compiler, real-world schemas the compiler was never
       specifically written against).
  2. Otherwise, scaffold a throwaway Cargo crate depending on
     rust-runtime/wire and `cargo build` it.
     - Non-zero exit -> FAIL, category "compile" (construct not yet
       supported by the table-driven runtime, or a real codegen bug —
       most of these are *expected* at this stage, not exit-code failures).
  3. Otherwise -> PASS.

Every per-file crate builds against one shared CARGO_TARGET_DIR for the
whole run (set once, cleaned up at exit) instead of each getting its own
throwaway target/ — asn1cpp-wire itself compiles once and is then reused
incrementally by every subsequent file, instead of a full from-scratch
rebuild per file. This is what keeps a several-times-larger corpus
(--corpus=all is ~275 files, versus 68 for the default) from multiplying
wall-clock time by the same factor — see the CARGO_TARGET_DIR env var
passed to run_cargo_build().

No requirement that every file passes (per gambas-asn1#309: this is a
wiring/reporting tool, not a gate) - exits non-zero only on a "codegen"
category failure (crash), never on a "compile" category failure (known
gap) - so the wrapping ctest stays green as coverage gaps are found and
fixed incrementally, only turning red on an actual compiler crash.
Prints a validate_parser.py-style summary table plus an aggregate N/M line.

Usage:
    python3 validate_rust_codegen.py --asn1cpp-bin build/compiler/asn1cpp [--corpus asn1c-compiler] [--verbose]
"""
import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]  # asn1cpp/
RUST_RUNTIME_WIRE = REPO / "rust-runtime/wire"
TEST_DIRS = {
    "asn1": REPO / "tests/asn1",
    "asn1c-compiler": REPO / "tests/tests-asn1c-compiler",
}
KNOWN_FAILURES_FILE = REPO / "tests/parser_known_failures.txt"
KNOWN_CRASHES_FILE = REPO / "tests/rust_codegen_known_crashes.txt"


def load_name_list(path: Path) -> set[str]:
    if not path.exists():
        return set()
    lines = path.read_text().splitlines()
    return {line.strip() for line in lines if line.strip() and not line.strip().startswith("#")}

CARGO_TOML_TEMPLATE = """\
[package]
name = "validate-rust-codegen-{name}"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
path = "src/lib.rs"

[dependencies]
asn1cpp-wire = {{ path = "{rust_runtime_wire}" }}
"""


def expects_failure(asn1_file: Path, known_failures: set[str]) -> bool:
    """True when a non-zero asn1cpp exit on this file is correct behavior,
    not a codegen crash to report:
      - tests-asn1c-compiler's own -SE/-NP suffix convention (semantic
        error / not parseable — X.680 violation, meant to be rejected).
      - a name already tracked in parser_known_failures.txt (a known
        parser gap, not a new Rust-codegen finding).
      - tests/asn1/'s own fixtures have no -OK/-SE/-NP convention, so
        detect intent from a leading comment instead (e.g.
        missing_module_test.asn1: 'Should fail: error on missing module.')."""
    stem = asn1_file.stem
    if stem.endswith("-SE") or stem.endswith("-NP"):
        return True
    if asn1_file.name in known_failures:
        return True
    head = asn1_file.read_text(errors="replace")[:500].lower()
    return "should fail" in head or "expected to fail" in head or "must fail" in head


def is_hard_crash(returncode: int, combined_output: str) -> bool:
    """True for an actual abort/segfault/uncaught-exception, as opposed to
    a graceful `error: ...`-and-exit-1 rejection. subprocess.run reports a
    signal-killed child as a negative returncode (POSIX); an uncaught C++
    exception that reaches std::terminate prints "terminate called" before
    the OS-level abort. The asn1c-compiler corpus (--corpus=asn1c-compiler)
    is unlike tests/asn1/: it's ~207 real-world schemas the compiler was
    never specifically written against, so a plain "error: ..." rejection
    (a stricter check than asn1c's own, or a genuinely unsupported
    construct) is an expected, non-gating finding — only a hard crash
    means "codegen should never do this regardless of coverage"."""
    if returncode < 0:
        return True
    return any(marker in combined_output for marker in
               ("terminate called", "Segmentation fault", "Aborted", "what():"))


def run_codegen(asncpp: Path, asn1_file: Path, out_dir: Path, verbose: bool) -> tuple[bool, bool, str]:
    """Returns (ok, is_crash, detail). is_crash is only meaningful when
    ok is False."""
    r = subprocess.run(
        [str(asncpp), str(asn1_file), "--target=rust", "-o", str(out_dir)],
        capture_output=True, text=True, timeout=30,
    )
    if verbose:
        print(r.stdout, end="")
        print(r.stderr, end="", file=sys.stderr)
    if r.returncode != 0:
        combined = (r.stderr or "") + (r.stdout or "")
        first_line = (r.stderr or r.stdout).strip().splitlines()[:1]
        detail = first_line[0] if first_line else f"exit {r.returncode}"
        return False, is_hard_crash(r.returncode, combined), detail
    if not any(out_dir.glob("*.rs")):
        return False, False, "no .rs files generated"
    return True, False, ""


def run_cargo_build(cargo: str, crate_dir: Path, target_dir: Path, verbose: bool) -> tuple[bool, str]:
    env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir))
    r = subprocess.run(
        [cargo, "build", "--quiet"],
        cwd=crate_dir, capture_output=True, text=True, timeout=120, env=env,
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


def validate_one(asncpp: Path, cargo: str, asn1_file: Path, index: int, target_dir: Path,
                  known_failures: set[str], known_crashes: set[str], verbose: bool) -> tuple[str, str, str]:
    """Returns (verdict, category, detail)."""
    with tempfile.TemporaryDirectory(prefix="rustcodegen_") as tmp:
        tmp_path = Path(tmp)
        gen_dir = tmp_path / "crate" / "src"
        gen_dir.mkdir(parents=True)

        ok, is_crash, detail = run_codegen(asncpp, asn1_file, gen_dir, verbose)
        if not ok:
            if expects_failure(asn1_file, known_failures):
                return "SKIP", "expected-fail", detail
            if is_crash and asn1_file.name in known_crashes:
                return "SKIP", "known-crash", detail
            return "FAIL", ("codegen" if is_crash else "reject"), detail

        crate_dir = tmp_path / "crate"
        # Package name just needs to be unique across the whole run (crates
        # from both corpora share one CARGO_TARGET_DIR) — an index prefix
        # sidesteps any stem collision between tests/asn1/ and
        # tests-asn1c-compiler/ without having to check for one.
        (crate_dir / "Cargo.toml").write_text(
            CARGO_TOML_TEMPLATE.format(
                name=f"f{index}-{asn1_file.stem.lower().replace('_', '-')}",
                rust_runtime_wire=RUST_RUNTIME_WIRE,
            )
        )

        ok, detail = run_cargo_build(cargo, crate_dir, target_dir, verbose)
        if not ok:
            return "FAIL", "compile", detail

        return "PASS", "", ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asn1cpp-bin", required=True, help="path to the asn1cpp compiler binary")
    ap.add_argument("--cargo", default="cargo", help="cargo executable (default: cargo on PATH)")
    ap.add_argument("--corpus", default="asn1", choices=["asn1", "asn1c-compiler", "all"],
                     help="which corpus to sweep (default: asn1, this repo's own tests/asn1/*.asn1; "
                          "asn1c-compiler: the ~207-file tests-asn1c-compiler/*.asn1 mirror; "
                          "all: both)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    asncpp = Path(args.asn1cpp_bin).resolve()
    if not asncpp.exists():
        print(f"asn1cpp binary not found: {asncpp}", file=sys.stderr)
        return 1
    if not RUST_RUNTIME_WIRE.exists():
        print(f"rust-runtime/wire not found: {RUST_RUNTIME_WIRE}", file=sys.stderr)
        return 1

    corpora = ["asn1", "asn1c-compiler"] if args.corpus == "all" else [args.corpus]
    files = sorted(f for c in corpora for f in TEST_DIRS[c].glob("*.asn1"))
    if not files:
        print(f"No .asn1 files found for --corpus={args.corpus}", file=sys.stderr)
        return 1

    known_failures = load_name_list(KNOWN_FAILURES_FILE)
    known_crashes = load_name_list(KNOWN_CRASHES_FILE)

    results = []
    codegen_crashes = 0
    with tempfile.TemporaryDirectory(prefix="rustcodegen_target_") as shared_target:
        target_dir = Path(shared_target)
        for i, f in enumerate(files):
            verdict, category, detail = validate_one(
                asncpp, args.cargo, f, i, target_dir, known_failures, known_crashes, args.verbose)
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
    print(f"\n{passed}/{counted} passed" + (f" ({skipped} skipped: expected-fail fixtures + known crashes)" if skipped else ""))
    if codegen_crashes:
        print(f"{codegen_crashes} codegen crash(es) — real compiler bug(s), not a coverage gap", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
