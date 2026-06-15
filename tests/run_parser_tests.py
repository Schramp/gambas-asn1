#!/usr/bin/env python3
"""
run_parser_tests.py — run asn1cpp against the imported asn1c parser test suite.

For each .asn1 file in tests-asn1c-compiler/:
  *-OK.asn1  → asn1cpp must exit 0
  *-NP.asn1  → asn1cpp must exit non-zero  (parse rejects garbage)
  *-SE.asn1  → asn1cpp may exit 0 or non-zero (semantic errors not yet implemented)

When --asn1c is given (cross-validation mode):
  *-OK  → both compilers must succeed
  *-NP  → asn1c rejects; asn1cpp must also reject
  *-SE  → asn1c rejects; asn1cpp outcome is informational only

Exit 0 if all required checks pass, 1 otherwise.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run(cmd, asn1_file, extra_flags=None):
    args = list(cmd)
    if extra_flags:
        args += extra_flags
    args.append(str(asn1_file))
    try:
        r = subprocess.run(args, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def extra_flags_for(filename):
    """Return extra compiler flags implied by the test filename."""
    if "fallow-newer-modules" in filename:
        return ["-fallow-newer-modules"]
    return []


def classify(name):
    if "-OK." in name:
        return "OK"
    if "-SE." in name:
        return "SE"
    if "-NP." in name:
        return "NP"
    return "?"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--asn1cpp", required=True, help="Path to asn1cpp binary")
    ap.add_argument("--test-dir", required=True,
                    help="Directory containing *-OK/NP/SE.asn1 test files")
    ap.add_argument("--asn1c", default=None,
                    help="Path to asn1c binary (enables cross-validation)")
    ap.add_argument("--known-failures", metavar="FILE", nargs="+", default=[],
                    help="Filenames (basename) expected to fail; excluded from failure count")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    test_dir = Path(args.test_dir)
    cpp_cmd  = [args.asn1cpp, "-E"]
    asn1c_cmd = [args.asn1c, "-E"] if args.asn1c else None

    files = sorted(test_dir.glob("*.asn1"))
    if not files:
        print(f"ERROR: no .asn1 files in {test_dir}", file=sys.stderr)
        sys.exit(1)

    ok_pass = ok_fail = np_pass = np_fail = se_pass = se_fail = 0
    failures = []

    for f in files:
        kind = classify(f.name)
        if kind == "?":
            continue

        fflags = extra_flags_for(f.name)
        cpp_ok = run(cpp_cmd, f, fflags)

        if asn1c_cmd:
            ac_ok = run(asn1c_cmd, f)
        else:
            ac_ok = None  # unknown without asn1c

        # Determine verdict
        if kind == "OK":
            passed = cpp_ok
            if not passed:
                ok_fail += 1
                failures.append((f.name, "asn1cpp rejected -OK file"))
            else:
                ok_pass += 1
                if asn1c_cmd and not ac_ok:
                    failures.append((f.name, "asn1c rejected -OK file (asn1c bug?)"))
        elif kind == "NP":
            passed = not cpp_ok
            if not passed:
                np_fail += 1
                failures.append((f.name, "asn1cpp accepted -NP file (should reject)"))
            else:
                np_pass += 1
        else:  # SE — informational only
            if cpp_ok:
                se_pass += 1
            else:
                se_fail += 1

        if args.verbose:
            ac_str = f"  asn1c={'OK' if ac_ok else 'FAIL' if ac_ok is not None else 'n/a'}" if asn1c_cmd else ""
            verdict = "ok" if (kind == "SE" or
                               (kind == "OK" and cpp_ok) or
                               (kind == "NP" and not cpp_ok)) else "FAIL"
            print(f"  {verdict:4s}  {kind:2s}  {f.name}{ac_str}")

    xval = " (with asn1c cross-check)" if asn1c_cmd else ""
    print(f"\nParser test results{xval}:")
    print(f"  -OK : {ok_pass}/{ok_pass+ok_fail} pass")
    print(f"  -NP : {np_pass}/{np_pass+np_fail} correctly rejected")
    print(f"  -SE : {se_pass}/{se_pass+se_fail} accepted (informational)")

    known = set(args.known_failures)
    real_failures = [(n, r) for n, r in failures if n not in known]
    xfail = [(n, r) for n, r in failures if n in known]

    if xfail:
        print(f"\n{len(xfail)} known failure(s) (excluded from result):")
        for name, reason in xfail:
            print(f"  xfail {name}  — {reason}")

    if real_failures:
        print(f"\n{len(real_failures)} failure(s):")
        for name, reason in real_failures:
            print(f"  FAIL  {name}  — {reason}")
        sys.exit(1)

    print("\nAll required checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
