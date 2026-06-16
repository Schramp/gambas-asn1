#!/usr/bin/env python3
"""
run_parser_tests.py — run asn1cpp against the imported asn1c parser test suite.

For each .asn1 file in tests-asn1c-compiler/:
  *-OK.asn1  → asn1cpp must exit 0
  *-NP.asn1  → asn1cpp must exit non-zero  (parse rejects garbage)
  *-SE.asn1  → asn1cpp must exit non-zero  (semantic errors must be caught)
              Files in SE_NOT_YET_ENFORCED are still informational only.

When --asn1c is given (cross-validation mode):
  *-OK  → both compilers must succeed
  *-NP  → asn1c rejects; asn1cpp must also reject
  *-SE  → asn1c rejects; asn1cpp must also reject (modulo SE_NOT_YET_ENFORCED)

Exit 0 if all required checks pass, 1 otherwise.
"""

import argparse
import subprocess
import sys
from pathlib import Path

# SE files where the required semantic check is not yet implemented.
# These are treated as informational (not enforced) until the gap is filled.
SE_NOT_YET_ENFORCED = {
    "11-int-SE.asn1",          # named-number uniqueness not checked
    "12-int-SE.asn1",          # named-number uniqueness not checked
    "71-duplicate-types-SE.asn1",   # duplicate type names across modules not checked
    "101-class-ref-SE.asn1",   # CLASS type-misuse checks not implemented
    "102-class-ref-SE.asn1",   # CLASS type-misuse checks not implemented
    "111-param-4-SE.asn1",     # parameterized type semantic errors not checked
    "209-prefer-import-source-SE.asn1",  # ambiguous import preference not checked
}


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
    flags = []
    if "fallow-newer-modules" in filename:
        flags.append("-fallow-newer-modules")
    if "blessSize" in filename:
        # asn1c -fbless-SIZE: accept SIZE() on INTEGER/ENUMERATED (non-standard extension).
        flags.append("-fbless-SIZE")
    return flags


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

    ok_pass = ok_fail = np_pass = np_fail = 0
    se_enforced_pass = se_enforced_fail = se_skip = 0
    failures = []

    for f in files:
        kind = classify(f.name)
        if kind == "?":
            continue

        fflags = extra_flags_for(f.name)
        # SE files: run without -E so the sema pass runs (errors appear after parsing).
        cmd_for_file = [args.asn1cpp] if kind == "SE" else cpp_cmd
        cpp_ok = run(cmd_for_file, f, fflags + (["-o", "/dev/null"] if kind == "SE" else []))

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
        else:  # SE — must be rejected (unless in skip list)
            if f.name in SE_NOT_YET_ENFORCED:
                se_skip += 1
                verdict_se = "skip"
            elif not cpp_ok:
                se_enforced_pass += 1
                verdict_se = "ok"
            else:
                se_enforced_fail += 1
                failures.append((f.name, "asn1cpp accepted -SE file (should reject)"))
                verdict_se = "FAIL"

        if args.verbose:
            ac_str = f"  asn1c={'OK' if ac_ok else 'FAIL' if ac_ok is not None else 'n/a'}" if asn1c_cmd else ""
            if kind == "SE":
                verdict = verdict_se
            elif kind == "OK":
                verdict = "ok" if cpp_ok else "FAIL"
            else:
                verdict = "ok" if not cpp_ok else "FAIL"
            print(f"  {verdict:4s}  {kind:2s}  {f.name}{ac_str}")

    xval = " (with asn1c cross-check)" if asn1c_cmd else ""
    se_total = se_enforced_pass + se_enforced_fail
    print(f"\nParser test results{xval}:")
    print(f"  -OK : {ok_pass}/{ok_pass+ok_fail} pass")
    print(f"  -NP : {np_pass}/{np_pass+np_fail} correctly rejected")
    print(f"  -SE : {se_enforced_pass}/{se_total} correctly rejected"
          + (f" ({se_skip} not yet enforced)" if se_skip else ""))

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
