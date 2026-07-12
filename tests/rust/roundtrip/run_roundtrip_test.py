#!/usr/bin/env python3
"""Generate Point via `asn1cpp --target=rust` and roundtrip-test it against
the real asn1cpp-ber crate (gambas-asn1#219) — proves the codegen -> runtime
pipeline works end to end for one small schema, not just that RustBackend's
output and asn1cpp-ber's API are compatible by hand.

Usage: run_roundtrip_test.py --compiler /path/to/asn1cpp --cargo /path/to/cargo --schema /path/to/simple_seq.asn1
"""
import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--compiler", required=True)
    ap.add_argument("--cargo", required=True)
    ap.add_argument("--schema", required=True)
    args = ap.parse_args()

    crate_dir = pathlib.Path(__file__).parent

    with tempfile.TemporaryDirectory() as tmp:
        gen = subprocess.run(
            [args.compiler, "--target=rust", "-o", tmp, args.schema],
            capture_output=True, text=True,
        )
        if gen.returncode != 0:
            print("compiler failed:", file=sys.stderr)
            print(gen.stdout, file=sys.stderr)
            print(gen.stderr, file=sys.stderr)
            return 1

        point_rs = pathlib.Path(tmp) / "Point.rs"
        if not point_rs.exists():
            print(f"compiler did not generate {point_rs} (schema changed?)", file=sys.stderr)
            return 1

        shutil.copy(point_rs, crate_dir / "src" / "point_generated.rs")

    test = subprocess.run(
        [args.cargo, "test", "--manifest-path", str(crate_dir / "Cargo.toml")],
        capture_output=True, text=True,
    )
    print(test.stdout)
    if test.returncode != 0:
        print(test.stderr, file=sys.stderr)
    return test.returncode


if __name__ == "__main__":
    sys.exit(main())
