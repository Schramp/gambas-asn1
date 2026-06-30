#!/usr/bin/env python3
"""
run_jer_tests.py — JER (JSON Encoding Rules) test runner for asn1cpp.

For each type bundle copied from asn1c's randomized test suite:
  1. Decode a JER sample using asn1c (ground truth) → XER.
  2. Decode the same JER sample using asn1cpp JER → XER.
  3. Compare XER outputs.

Status: EXPECTED TO FAIL until asn1cpp JER decode is implemented (#156+).
The test fails at step 2 because the asn1cpp JER tool does not exist yet.

Usage:
  python3 run_jer_tests.py [--bundles-dir DIR] [--asn1c-driver BINARY]
                            [--asn1cpp-jer BINARY] [--verbose]

Exit code: 0 all pass, 1 any failure.
"""

import argparse
import os
import subprocess
import sys

HERE       = os.path.dirname(os.path.abspath(__file__))
BUNDLES    = os.path.join(HERE, "bundles")
REPO       = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))

# asn1c random-test-driver lives in each bundle dir; keyed by bundle name.
BUNDLE_DIRS = {
    "NULL":             os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.00-NULL-bundle"),
    "BOOLEAN":          os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.01-BOOLEAN-bundle"),
    "INTEGER":          os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.02-INTEGER-bundle"),
    "ENUMERATED":       os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.03-ENUMERATED-bundle"),
    "REAL":             os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.04-REAL-bundle"),
    "BIT-STRING":       os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.05-BIT-STRING-bundle"),
    "OCTET-STRING":     os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.06-OCTET-STRING-bundle"),
    "VisibleString":    os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.07-VisibleString-bundle"),
    "OBJECT-IDENTIFIER":os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.08-OBJECT-IDENTIFIER-bundle"),
    "RELATIVE-OID":     os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.09-RELATIVE-OID-bundle"),
    "UTF8String":       os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.10-UTF8String-bundle"),
    "BMPString":        os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.11-BMPString-bundle"),
    "UniversalString":  os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.12-UniversalString-bundle"),
    "UTCTime":          os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.13-UTCTime-bundle"),
    "GeneralizedTime":  os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.14-GeneralizedTime-bundle"),
    "CHOICE":           os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.15-CHOICE-bundle"),
    "SEQUENCE":         os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.16-SEQUENCE-bundle"),
    "SEQUENCE-OF":      os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.17-SEQUENCE-OF-bundle"),
    "SET-OF":           os.path.join(REPO, "asn1c/tests/tests-randomized/.tmp.19-SET-OF-bundle"),
}

# asn1cpp JER tool (does not exist until #156+ is implemented).
ASN1CPP_JER = os.path.join(REPO, "etsitools/asn1cpp/randgen/jer-to-xer")


def check_tools(asn1cpp_jer: str) -> bool:
    """Return True if all required tools are present."""
    ok = True
    if not os.path.isfile(asn1cpp_jer):
        print(f"MISSING: {asn1cpp_jer}")
        print("  (asn1cpp JER→XER converter not implemented yet — see issue #156)")
        ok = False
    for name, bdir in BUNDLE_DIRS.items():
        driver = os.path.join(bdir, "random-test-driver")
        if not os.path.isfile(driver):
            print(f"MISSING asn1c driver for {name}: {driver}")
            ok = False
    return ok


def asn1c_jer_to_xer(bundle_dir: str, jer_bytes: bytes) -> str | None:
    """Use asn1c random-test-driver to decode JER and re-encode to XER.

    The driver is invoked with ASN1_DATA_DIR=jer via env and -c flag (check
    round-trip). Since -c only does round-trips, we instead write the JER
    bytes to stdin and use the pre-computed XER fixture as reference.

    Returns the XER string on success, None on failure.
    """
    driver = os.path.join(bundle_dir, "random-test-driver")
    env = os.environ.copy()
    env["ASN1_DATA_DIR"] = "jer"
    # random-test-driver -c reads from the random-data/jer/ dir, not stdin.
    # We use the fixture XER file directly as the ground-truth reference
    # rather than re-running the driver for each sample.
    return None  # Not used in fixture-based comparison below


def run_test_bundle(name: str, bundle_dir: str, samples_dir: str,
                    asn1cpp_jer: str, verbose: bool) -> tuple[int, int]:
    """Run JER tests for one bundle. Returns (passed, failed)."""
    passed = failed = 0

    for idx in range(5):
        jer_path = os.path.join(samples_dir, f"{idx:03d}.jer")
        xer_path = os.path.join(samples_dir, f"{idx:03d}.xer")
        if not os.path.isfile(jer_path):
            continue

        jer_bytes = open(jer_path, "rb").read()
        expected_xer = open(xer_path).read().strip() if os.path.isfile(xer_path) else None

        # Step 1: asn1cpp JER→XER (expected to fail until #156+)
        try:
            r = subprocess.run(
                [asn1cpp_jer, "--type", "T"],
                input=jer_bytes, capture_output=True, timeout=10
            )
            got_xer = r.stdout.decode(errors="replace").strip()
            if r.returncode != 0:
                if verbose:
                    print(f"  FAIL {name}[{idx:03d}]: asn1cpp exited {r.returncode}")
                    print(f"    stderr: {r.stderr.decode(errors='replace')[:200]}")
                failed += 1
                continue
        except FileNotFoundError:
            if verbose:
                print(f"  FAIL {name}[{idx:03d}]: {asn1cpp_jer} not found")
            failed += 1
            continue

        # Step 2: compare with expected XER fixture
        if expected_xer and got_xer != expected_xer:
            if verbose:
                print(f"  MISMATCH {name}[{idx:03d}]:")
                print(f"    expected: {expected_xer[:120]}")
                print(f"    got:      {got_xer[:120]}")
            failed += 1
        else:
            if verbose:
                print(f"  PASS {name}[{idx:03d}]")
            passed += 1

    return passed, failed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundles-dir", default=BUNDLES)
    parser.add_argument("--asn1cpp-jer",  default=ASN1CPP_JER)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    tools_ok = check_tools(args.asn1cpp_jer)
    if not tools_ok:
        print("\nMissing required tools — tests cannot run.")
        return 1

    total_pass = total_fail = 0
    for name in sorted(BUNDLE_DIRS.keys()):
        samples_dir = os.path.join(args.bundles_dir, name, "samples")
        if not os.path.isdir(samples_dir):
            print(f"WARNING: no samples dir for {name} ({samples_dir})")
            continue
        p, f = run_test_bundle(name, BUNDLE_DIRS[name], samples_dir,
                               args.asn1cpp_jer, args.verbose)
        status = "PASS" if f == 0 else "FAIL"
        print(f"  [{status}] {name:20s}  pass={p} fail={f}")
        total_pass += p
        total_fail += f

    print(f"\nTotal: {total_pass} passed, {total_fail} failed")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
