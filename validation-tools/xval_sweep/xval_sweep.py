#!/usr/bin/env python3
"""
xval_sweep.py — cross-validate C++ vs Rust BER/XER codecs (and, when
asn1c is available, asn1c as ground truth) across every (schema, PDU
type) target listed in targets.txt (gambas-asn1#434, #440).

For each target: materializes a per-target C++ build (from template_cpp/)
and a per-target Rust build (from template_rust/) via keyword substitution
— see those directories' own template files for the exact keywords and
etsitools/asn1cpp/randgen + etsitools/asn1cpp/randgen-rust (in the
umbrella etsi/ repo) for the hand-maintained ETSI-only tools this
generalizes. Builds a C++ randgen + ber-to-xer + xer-to-ber trio and a
Rust ber-to-xer + xer-to-ber pair, generates N random PDUs via the C++
randgen tool, and runs a BER/XER cross-validation matrix — comparing the
C++ codec against the Rust codec, same comparison shape
asn1cpp-validation-tools/compare_random.py (umbrella etsi/ repo) uses for
asn1c vs asn1cpp, but self-contained here (no cross-repo import) since
this tool lives inside asn1cpp/ and must work from a standalone asn1cpp/
checkout.

asn1c leg (optional, #440): when an `asn1c` binary is found (ASN1C_BIN_DIR
env var, PATH, or /usr/local/bin — same search order CMakeLists.txt's own
cross-validation gate uses), also builds asn1c's own generated
converter-example tool for the target (`asn1c -D <dir> ... && make -f
converter-example.mk` — asn1c's own example CLI already speaks `-p <PDU>
-iber -oxer` / `-ixer -oder`, no custom C harness needed) and adds it as
ground truth: asn1c.B2X vs cpp.B2X, asn1c.B2X vs rust.B2X, and asn1c's own
round-trip. When asn1c isn't found, or codegen/build fails for a specific
target (e.g. a construct asn1c itself rejects), that target's asn1c leg
is skipped with a note — never a hard failure, and the C++/Rust legs
always run regardless.

Build dependency handling: each target's `make` (C++ side) and
`make gen` + `cargo build` (Rust side, via build.rs's own
rerun-if-changed) track their own source/schema/compiler staleness — this
driver doesn't re-invoke a build step it doesn't need to, but never
second-guesses `make`/`cargo`'s own up-to-date check either; a bare rerun
of this script is always safe and cheap when nothing changed.

Usage:
  python3 xval_sweep.py [--count N] [--seed S] [--target NAME] [--verbose]
                        [--asn1c-dir DIR] [--no-asn1c]

  --target NAME    only run the target whose schema path or PDU type
                   matches NAME (substring match); default: all targets.
  --asn1c-dir DIR  directory containing the asn1c binary (overrides
                   ASN1C_BIN_DIR env var / PATH / /usr/local/bin search).
  --no-asn1c       skip the asn1c leg even if asn1c is found.

Exit code: 0 if every target's every comparison passed, 1 otherwise.
"""
import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ASN1CPP_ROOT = os.path.dirname(os.path.dirname(HERE))
ASNCPP_BIN = os.path.join(ASN1CPP_ROOT, "build/compiler/asn1cpp")
ASN1CPP_BER_CRATE = os.path.join(ASN1CPP_ROOT, "rust-runtime/ber")

TEMPLATE_CPP = os.path.join(HERE, "template_cpp")
TEMPLATE_RUST = os.path.join(HERE, "template_rust")
TESTBUILD = os.path.join(HERE, "testbuild")
TARGETS_FILE = os.path.join(HERE, "targets.txt")


def find_asn1c(override_dir=None):
    """Locate the asn1c binary — same search order as CMakeLists.txt's own
    cross-validation gate: an explicit override, then ASN1C_BIN_DIR env
    var, then PATH, then /usr/local/bin. Returns the binary path, or None
    (never raises) — the asn1c leg is optional everywhere it's used.
    """
    candidates = []
    if override_dir:
        candidates.append(os.path.join(override_dir, "asn1c"))
    bin_dir = os.environ.get("ASN1C_BIN_DIR")
    if bin_dir:
        candidates.append(os.path.join(bin_dir, "asn1c"))
    on_path = shutil.which("asn1c")
    if on_path:
        candidates.append(on_path)
    candidates.append("/usr/local/bin/asn1c")
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


# ---------------------------------------------------------------------------
# BER/XER comparison helpers — ported from asn1cpp-validation-tools/
# compare_random.py (umbrella etsi/ repo) rather than imported, so this
# tool has no dependency outside asn1cpp/ itself. Keep in sync by hand if
# that script's own logic changes; the functions are small and stable.

def run(*args, **kwargs):
    return subprocess.run(args, capture_output=True, **kwargs)


def split_ber_records(data: bytes) -> list[bytes]:
    """Split raw concatenated BER stream into per-record byte strings."""
    records = []
    offset = 0
    while offset < len(data):
        start = offset
        if offset >= len(data):
            break
        tag = data[offset]; offset += 1
        if tag & 0x1F == 0x1F:
            while offset < len(data) and (data[offset] & 0x80):
                offset += 1
            offset += 1
        if offset >= len(data):
            break
        l0 = data[offset]; offset += 1
        if l0 == 0x80:
            while offset + 1 < len(data) and not (data[offset] == 0 and data[offset + 1] == 0):
                offset += 1
            offset += 2
            records.append(data[start:offset])
        elif l0 & 0x80:
            nb = l0 & 0x7F
            length = int.from_bytes(data[offset:offset + nb], 'big')
            offset += nb
            end = offset + length
            records.append(data[start:end])
            offset = end
        else:
            end = offset + l0
            records.append(data[start:end])
            offset = end
    return records


def split_xer_records(text: str) -> list[str]:
    """Split XER output into per-record strings.

    Records start with `<TypeName>` at column 0 and end with `</TypeName>`
    at column 0. Blank lines may appear inside a record (asn1c emits them
    between SEQ-OF/CHOICE siblings) so we cannot use a blank-line splitter.
    """
    records, current = [], []
    inside = False
    for line in text.splitlines():
        is_open = bool(line) and line.startswith("<") and not line.startswith("</")
        is_close = bool(line) and line.startswith("</")
        if is_open and inside and current:
            records.append("\n".join(current))
            current = []
        if is_open:
            inside = True
        if inside:
            current.append(line)
        if is_close:
            records.append("\n".join(current))
            current = []
            inside = False
    if current:
        records.append("\n".join(current))
    return [r for r in records if r.strip()]


def normalise(xer: str) -> str:
    return "\n".join(line.strip() for line in xer.splitlines() if line.strip())


def b2x_file(tool: str, type_name: str, ber_path: str) -> tuple[str, str]:
    """BER file → XER string. Returns (xer_text, stderr)."""
    r = run(tool, "--type", type_name, ber_path)
    return r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace").strip()


def x2b(tool: str, type_name: str, xer_text: str) -> tuple[bytes, str]:
    """XER string → BER bytes. Returns (ber_bytes, stderr)."""
    r = run(tool, "--type", type_name, input=xer_text.encode())
    return r.stdout, r.stderr.decode(errors="replace").strip()


def asn1c_b2x(tool: str, pdu_type: str, ber_path: str) -> tuple[str, str]:
    """BER file → XER string via asn1c's own converter-example. Returns (xer_text, stderr)."""
    r = run(tool, "-p", pdu_type, "-iber", "-oxer", ber_path)
    return r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace").strip()


def asn1c_x2b(tool: str, pdu_type: str, xer_text: str) -> tuple[bytes, str]:
    """XER string → DER bytes via asn1c's own converter-example.

    converter-example takes a datafile argument, not stdin, unlike the
    C++/Rust tools' x2b — write to a temp file.
    """
    fd, xer_path = tempfile.mkstemp(suffix=".xer")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(xer_text.encode())
        r = run(tool, "-p", pdu_type, "-ixer", "-oder", xer_path)
        return r.stdout, r.stderr.decode(errors="replace").strip()
    finally:
        os.unlink(xer_path)


def compare_records(recs_a: list[str], recs_b: list[str], verbose: bool) -> tuple[int, int]:
    n = min(len(recs_a), len(recs_b))
    matches = mismatches = 0
    for i in range(n):
        a = normalise(recs_a[i])
        b = normalise(recs_b[i])
        if a == b:
            matches += 1
        else:
            mismatches += 1
            print(f"  MISMATCH record #{i + 1}")
            if verbose:
                diff = difflib.unified_diff(
                    a.splitlines(), b.splitlines(),
                    fromfile="expected", tofile="got", lineterm="")
                for line in list(diff)[:80]:
                    print("    " + line)
    return matches, mismatches


def run_comparison(label: str, xer_a: str, xer_b: str, verbose: bool) -> tuple[int, int]:
    recs_a = split_xer_records(xer_a)
    recs_b = split_xer_records(xer_b)
    n = min(len(recs_a), len(recs_b))
    if n == 0:
        print(f"  [{label}] no records to compare")
        return 0, 0
    matches, mismatches = compare_records(recs_a, recs_b, verbose)
    status = "OK" if mismatches == 0 else "FAIL"
    print(f"  [{label}] {matches}/{n} match, {mismatches} mismatch  [{status}]")
    return matches, mismatches


def compare_ber(label: str, ber_a: bytes, ber_b: bytes, verbose: bool) -> tuple[int, int]:
    recs_a = split_ber_records(ber_a)
    recs_b = split_ber_records(ber_b)
    n = min(len(recs_a), len(recs_b))
    if n == 0:
        print(f"  [{label}] no records to compare")
        return 0, 0
    matches = mismatches = 0
    for i in range(n):
        if recs_a[i] == recs_b[i]:
            matches += 1
        else:
            mismatches += 1
            if verbose:
                print(f"  MISMATCH record #{i + 1}: "
                      f"expected {len(recs_a[i])} bytes, got {len(recs_b[i])}")
    status = "OK" if mismatches == 0 else "FAIL"
    print(f"  [{label}] {matches}/{n} match, {mismatches} mismatch  [{status}]")
    return matches, mismatches


# ---------------------------------------------------------------------------
# Target build orchestration

def parse_targets(path):
    """Returns a list of (schema, pdu_type, skip_asn1c_reason_or_None).

    A line is normally "<schema> <PduType>". A third token+ marks a known,
    already-filed divergence between asn1c and asn1cpp for this specific
    target — the C++/Rust legs still run and gate pass/fail as usual, but
    the asn1c leg is skipped (not run at all) rather than failing the
    target on a gap that's already tracked elsewhere. The remaining
    tokens are the skip reason, printed verbatim (e.g. an issue number).
    """
    targets = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                print(f"{path}:{lineno}: expected '<schema> <PduType> [skip-asn1c-reason]', got: {line!r}")
                sys.exit(1)
            reason = " ".join(parts[2:]) if len(parts) > 2 else None
            targets.append((parts[0], parts[1], reason))
    return targets


def materialize(template_path, dest_path, subs):
    with open(template_path) as f:
        text = f.read()
    for k, v in subs.items():
        text = text.replace(k, v)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(dest_path, "w") as f:
        f.write(text)


def copy_verbatim(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(src, dst)


def run_make(directory, *make_args, label=""):
    r = subprocess.run(["make", "-C", directory, *make_args],
                        capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  BUILD FAILED ({label or ' '.join(make_args) or 'all'}):")
        print(r.stdout[-4000:])
        print(r.stderr[-4000:])
        return False
    return True


def discover_ident(gen_dir, ext, pdu_type):
    """Find the real generated identifier(s) for pdu_type in gen_dir.

    asn1cpp's identifier escaping (hyphens, keyword collisions) differs
    per backend and can't be predicted from the raw ASN.1 name alone —
    confirmed divergent for a hyphenated name: C++ substitutes underscores
    (`Foo-Bar` -> `Foo_Bar`), Rust collapses the hyphen and capitalizes
    the next letter (`Foo-Bar` -> `FooBar`). Both backends emit the raw,
    unescaped name verbatim as the type's own XER-name string literal
    though (`"name": "<raw>"` in the generated TypeDescriptor/ChoiceSpec),
    so grep for that instead of guessing a transform — file stem (minus
    ext) is the real identifier.
    """
    needle = f'"{pdu_type}"'
    matches = []
    for fn in os.listdir(gen_dir):
        if not fn.endswith(ext):
            continue
        with open(os.path.join(gen_dir, fn), errors="replace") as f:
            if needle in f.read():
                matches.append(fn[:-len(ext)])
    return sorted(set(matches))


def build_cpp(target_dir, asn1_files_abs, pdu_type):
    cpp_dir = os.path.join(target_dir, "cpp")
    for name in ["randgen.cpp", "ber-to-xer.cpp", "xer-to-ber.cpp",
                 "type_registry.hpp", "type_registry.cpp"]:
        copy_verbatim(os.path.join(TEMPLATE_CPP, "src", name),
                      os.path.join(cpp_dir, "src", name))
    materialize(os.path.join(TEMPLATE_CPP, "Makefile.tmpl"),
                os.path.join(cpp_dir, "Makefile"),
                {"__ASN1CPP_ROOT__": ASN1CPP_ROOT,
                 "__ASN1_FILES__": " ".join(asn1_files_abs),
                 "__PDU_TYPE__": pdu_type})

    # Codegen first — src/types.cpp (materialized below) needs the real
    # generated identifier, which can only be discovered after codegen
    # runs (see discover_ident's own doc).
    if not run_make(cpp_dir, "gen", label="C++ codegen"):
        return None
    idents = discover_ident(os.path.join(cpp_dir, "gen"), ".cpp", pdu_type)
    if len(idents) != 1:
        print(f"  expected exactly one C++ identifier for {pdu_type!r}, found {idents}")
        return None
    ident = idents[0]

    materialize(os.path.join(TEMPLATE_CPP, "src", "types.cpp.tmpl"),
                os.path.join(cpp_dir, "src", "types.cpp"),
                {"__PDU_IDENT__": ident, "__PDU_TYPE__": pdu_type})
    if not run_make(cpp_dir, "build", "-j4", label="C++ build"):
        return None
    return {
        "randgen": os.path.join(cpp_dir, "randgen"),
        "b2x": os.path.join(cpp_dir, "ber-to-xer"),
        "x2b": os.path.join(cpp_dir, "xer-to-ber"),
    }


def build_rust(target_dir, asn1_files_abs, pdu_type):
    rust_dir = os.path.join(target_dir, "rust")
    copy_verbatim(os.path.join(TEMPLATE_RUST, "build.rs"),
                  os.path.join(rust_dir, "build.rs"))
    copy_verbatim(os.path.join(TEMPLATE_RUST, "src", "lib.rs"),
                  os.path.join(rust_dir, "src", "lib.rs"))
    materialize(os.path.join(TEMPLATE_RUST, "Makefile.tmpl"),
                os.path.join(rust_dir, "Makefile"),
                {"__ASNCPP__": ASNCPP_BIN,
                 "__ASN1_FILES__": " ".join(asn1_files_abs),
                 "__PDU_TYPE__": pdu_type})
    materialize(os.path.join(TEMPLATE_RUST, "Cargo.toml.tmpl"),
                os.path.join(rust_dir, "Cargo.toml"),
                {"__ASN1CPP_BER_CRATE__": ASN1CPP_BER_CRATE})

    if not run_make(rust_dir, "gen", label="Rust codegen"):
        return None
    idents = discover_ident(os.path.join(rust_dir, "gen"), ".rs", pdu_type)
    if len(idents) != 1:
        print(f"  expected exactly one Rust identifier for {pdu_type!r}, found {idents}")
        return None
    ident = idents[0]

    lib_rs_path = os.path.join(rust_dir, "gen", "lib.rs")
    with open(lib_rs_path) as f:
        lib_rs = f.read()
    m = re.search(rf'#\[path = "{re.escape(ident)}\.rs"\]\s*pub mod (\w+);', lib_rs)
    if not m:
        print(f"  could not find module for {ident}.rs in {lib_rs_path}")
        return None
    module = m.group(1)

    materialize(os.path.join(TEMPLATE_RUST, "src", "bin", "ber_to_xer.rs.tmpl"),
                os.path.join(rust_dir, "src", "bin", "ber_to_xer.rs"),
                {"__PDU_TYPE__": pdu_type, "__PDU_IDENT__": ident, "__PDU_MODULE__": module})
    materialize(os.path.join(TEMPLATE_RUST, "src", "bin", "xer_to_ber.rs.tmpl"),
                os.path.join(rust_dir, "src", "bin", "xer_to_ber.rs"),
                {"__PDU_TYPE__": pdu_type, "__PDU_IDENT__": ident, "__PDU_MODULE__": module})

    if not run_make(rust_dir, "build", label="Rust cargo build"):
        return None
    return {
        "b2x": os.path.join(rust_dir, "target/release/ber-to-xer"),
        "x2b": os.path.join(rust_dir, "target/release/xer-to-ber"),
    }


def build_asn1c(target_dir, asn1_files_abs, pdu_type, asn1c_bin):
    """Build asn1c's own converter-example tool for this target — ground
    truth leg (#440). Returns None (not a hard error) whenever asn1c
    itself can't handle this target's schema/construct — codegen or build
    failure just means this target's asn1c leg is skipped, same as
    "asn1c not found" globally; the C++/Rust legs never depend on this.
    """
    c_dir = os.path.join(target_dir, "asn1c")
    os.makedirs(c_dir, exist_ok=True)
    r = run(asn1c_bin, "-fcompound-names", "-fno-include-deps",
            "-fallow-newer-modules", f"-pdu={pdu_type}", "-D", c_dir,
            *asn1_files_abs)
    if r.returncode != 0:
        print(f"  asn1c leg: codegen failed, skipping — {r.stderr.decode(errors='replace')[-500:]}")
        return None
    mk = os.path.join(c_dir, "converter-example.mk")
    if not os.path.isfile(mk):
        print(f"  asn1c leg: no converter-example.mk produced, skipping")
        return None
    r = run("make", "-C", c_dir, "-f", "converter-example.mk")
    if r.returncode != 0:
        print(f"  asn1c leg: build failed, skipping — {r.stderr.decode(errors='replace')[-500:]}")
        return None
    tool = os.path.join(c_dir, "converter-example")
    if not os.path.isfile(tool):
        print(f"  asn1c leg: converter-example binary not produced, skipping")
        return None
    return {"tool": tool}


def run_target(schema_rel, pdu_type, count, seed, verbose, asn1c_bin, skip_asn1c_reason=None):
    slug = os.path.splitext(os.path.basename(schema_rel))[0] + "_" + pdu_type
    target_dir = os.path.join(TESTBUILD, slug)
    asn1_files_abs = [os.path.join(ASN1CPP_ROOT, schema_rel)]

    print(f"\n=== {schema_rel} :: {pdu_type} ===")
    if skip_asn1c_reason:
        print(f"  asn1c leg: skipped ({skip_asn1c_reason})")

    cpp_tools = build_cpp(target_dir, asn1_files_abs, pdu_type)
    if cpp_tools is None:
        return False
    rust_tools = build_rust(target_dir, asn1_files_abs, pdu_type)
    if rust_tools is None:
        return False
    asn1c_tools = (build_asn1c(target_dir, asn1_files_abs, pdu_type, asn1c_bin)
                   if asn1c_bin and not skip_asn1c_reason else None)

    ber_path = os.path.join(target_dir, "records.ber")
    gen_cmd = [cpp_tools["randgen"], "--type", pdu_type,
               "--count", str(count), "--output", ber_path]
    if seed is not None:
        gen_cmd += ["--seed", str(seed)]
    r = run(*gen_cmd)
    if r.returncode != 0:
        print(f"  randgen failed: {r.stderr.decode(errors='replace')}")
        return False
    with open(ber_path, "rb") as f:
        ber_orig = f.read()

    xer_cpp, err_cpp = b2x_file(cpp_tools["b2x"], pdu_type, ber_path)
    if err_cpp:
        print(f"  cpp b2x stderr: {err_cpp}")
    xer_rust, err_rust = b2x_file(rust_tools["b2x"], pdu_type, ber_path)
    if err_rust:
        print(f"  rust b2x stderr: {err_rust}")

    # split_xer_records requires each record's outermost tags to start at
    # column 0 — true for every SEQUENCE-rooted PDU this tooling was
    # originally built against (PS_PDU, EncryptedPayload), but a
    # top-level CHOICE PDU's XER output is indented one level (its own
    # quirk, not a codec-correctness issue — the alternative's tag isn't
    # wrapped the way a SEQUENCE member's is, see choice.rs/BerCodec.cpp's
    # own "CHOICE has no outer wrapper" doc, yet ber-to-xer/XerCodec still
    # emit it at a nonzero indent depth). Strip exactly that outer indent
    # from every line — NOT each line's own leading whitespace, which
    # would collapse nested-element indentation and corrupt multi-level
    # records (SEQUENCE OF/nested SEQUENCE) into bogus extra "records".
    def dedent_xer(text):
        lines = text.splitlines()
        indents = [len(l) - len(l.lstrip()) for l in lines if l.strip()]
        if not indents:
            return text
        base = min(indents)
        if base == 0:
            return text
        return "\n".join(l[base:] if len(l) >= base and not l[:base].strip() else l
                          for l in lines)
    xer_cpp = dedent_xer(xer_cpp)
    xer_rust = dedent_xer(xer_rust)

    total_matches = 0
    total_mismatches = 0
    total_records = 0

    def tally(pair):
        nonlocal total_matches, total_mismatches, total_records
        m, mm = pair
        total_matches += m
        total_mismatches += mm
        total_records += m + mm

    tally(run_comparison("cpp.B2X vs rust.B2X", xer_cpp, xer_rust, verbose))

    ber_cpp2, _ = x2b(cpp_tools["x2b"], pdu_type, xer_cpp)
    tally(compare_ber("orig vs cpp.X2B(cpp.XER)", ber_orig, ber_cpp2, verbose))

    ber_rust2, _ = x2b(rust_tools["x2b"], pdu_type, xer_rust)
    tally(compare_ber("orig vs rust.X2B(rust.XER)", ber_orig, ber_rust2, verbose))

    ber_cross1, _ = x2b(rust_tools["x2b"], pdu_type, xer_cpp)
    tally(compare_ber("orig vs rust.X2B(cpp.XER)", ber_orig, ber_cross1, verbose))

    ber_cross2, _ = x2b(cpp_tools["x2b"], pdu_type, xer_rust)
    tally(compare_ber("orig vs cpp.X2B(rust.XER)", ber_orig, ber_cross2, verbose))

    if asn1c_tools:
        xer_asn1c, err_asn1c = asn1c_b2x(asn1c_tools["tool"], pdu_type, ber_path)
        if err_asn1c:
            print(f"  asn1c b2x stderr: {err_asn1c}")
        xer_asn1c = dedent_xer(xer_asn1c)

        # These two are the real ground-truth signal — does asn1c agree
        # with what our own decode+XER-encode produced — so they gate
        # pass/fail like every other check.
        tally(run_comparison("asn1c.B2X vs cpp.B2X", xer_asn1c, xer_cpp, verbose))
        tally(run_comparison("asn1c.B2X vs rust.B2X", xer_asn1c, xer_rust, verbose))

        # asn1c's own round-trip stability is informational only, not
        # gating: a type with REAL fields can legitimately re-encode to a
        # different (still valid) DER byte sequence for the same value —
        # this tests asn1c's own canonicalization behavior, not our
        # codecs, so it's printed but never fails the target.
        ber_asn1c2, _ = asn1c_x2b(asn1c_tools["tool"], pdu_type, xer_asn1c)
        compare_ber("orig vs asn1c.X2B(asn1c.XER) [informational]", ber_orig, ber_asn1c2, verbose)
    elif not skip_asn1c_reason:
        print("  asn1c leg: skipped (not found or unsupported for this target)")

    if total_records == 0:
        print(f"  --- {schema_rel}::{pdu_type}: FAIL — no records compared (harness/parsing gap, not verified) ---")
        return False
    print(f"  --- {schema_rel}::{pdu_type}: {total_matches} pass, {total_mismatches} fail ---")
    return total_mismatches == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--target", default=None,
                     help="only run targets whose schema path or PDU type contains this substring")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--asn1c-dir", default=None,
                     help="directory containing the asn1c binary (overrides ASN1C_BIN_DIR/PATH search)")
    ap.add_argument("--no-asn1c", action="store_true",
                     help="skip the asn1c leg even if asn1c is found")
    opts = ap.parse_args()

    if not os.path.isfile(ASNCPP_BIN):
        print(f"asn1cpp compiler not built: {ASNCPP_BIN}\nRun: cmake --build {ASN1CPP_ROOT}/build")
        sys.exit(1)

    asn1c_bin = None if opts.no_asn1c else find_asn1c(opts.asn1c_dir)
    if asn1c_bin:
        print(f"asn1c leg: ON  ({asn1c_bin})")
    else:
        print("asn1c leg: OFF (asn1c not found — set ASN1C_BIN_DIR or --asn1c-dir to enable)")

    targets = parse_targets(TARGETS_FILE)
    if opts.target:
        targets = [t for t in targets if opts.target in t[0] or opts.target in t[1]]
        if not targets:
            print(f"no target matches {opts.target!r}")
            sys.exit(1)

    os.makedirs(TESTBUILD, exist_ok=True)

    results = []
    for schema_rel, pdu_type, skip_asn1c_reason in targets:
        ok = run_target(schema_rel, pdu_type, opts.count, opts.seed, opts.verbose,
                         asn1c_bin, skip_asn1c_reason)
        results.append((schema_rel, pdu_type, ok))

    print("\n=== Summary ===")
    failed = 0
    for schema_rel, pdu_type, ok in results:
        status = "OK" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"  [{status}] {schema_rel} :: {pdu_type}")
    print(f"\n{len(results) - failed}/{len(results)} targets passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
