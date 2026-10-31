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
  python3 xval_sweep.py [--count N] [--seed S] [--target NAME] [--limit N] [--shard K/N] [--verbose]
                        [--asn1c-dir DIR] [--no-asn1c] [-j N] [--reuse asn1c,cpp]
                        [--corpus {targets,asn1c-compiler}] [--with-asn1c] [--java]

  --target NAME    only run the target whose schema path or PDU type
                   matches NAME (substring match); default: all targets.
  --limit N        cap the target list to the first N (after --target
                   filtering) — a quick sanity slice before a full run.
  --shard K/N      keep only the build groups (targets sharing a schema,
                   built once) at index i with i mod N == K, after
                   --target/--limit, so N runners can split one sweep
                   without building any schema twice.
  --java           add the Java leg (BER round trip and the XER matrix
                   through the Java runtime, compiled with plain javac;
                   asn1c.B2X vs java.B2X when asn1c runs); targets the Java
                   backend cannot emit yet are skipped with a note.
  --asn1c-dir DIR  directory containing the asn1c binary (overrides
                   ASN1C_BIN_DIR env var / PATH / /usr/local/bin search).
  --no-asn1c       skip the asn1c leg even if asn1c is found (--corpus=targets only).
  -j, --jobs N     run N targets in parallel (default min(4, cpus/3)).
  --reuse LEGS     comma list (asn1c, cpp): skip codegen+build of those legs
                   when their key (schema + tool/runtime signature) matches
                   the previous build. Codegen output is always checksum-
                   synced, so unchanged files are never rebuilt either way.
  --corpus C       'targets' (default): the curated targets.txt list, every
                   entry hand-verified — a failure here is a real
                   regression and keeps gating the exit code.
                   'asn1c-compiler': auto-discover a PDU-type candidate
                   from every *-OK.asn1 in tests/tests-asn1c-compiler/
                   instead (see discover_pdu_type()) — a broad, one-off
                   probe of the ~207-file corpus. Always exits 0: a
                   failure here is a finding to read and act on (many are
                   already-known/-filed gaps), not a build gate. Defaults
                   --count to 3 (build cost per target dominates, not
                   record count) and skips the asn1c leg (pass
                   --with-asn1c to opt in — ~200 extra asn1c builds is the
                   single biggest cost multiplier for a broad probe).

--fuzz feeds malformed input to every decoder instead (see fuzz_target);
a target then fails only on a crash: signal, abort, Rust panic or hang.
  python3 xval_sweep.py --fuzz [--fuzz-seeds N] [--mutations M]
                        [--corrupt-percent P] [--corrupt-mode SPEC]

A target also fails when any run of the C++ or Rust codec tools (b2x,
x2b, b2j, j2b, b2p, p2b) exits nonzero or panics, even if the record
comparisons look clean; each such run is printed as "TOOL FAILURE".
asn1c's own converter-example runs only feed informational or record-
count-checked comparisons and are not treated this way.

Exit code: for --corpus=targets (default), 0 if every target's every
comparison passed, 1 otherwise. For --corpus=asn1c-compiler, always 0.
"""
import argparse
import random
import difflib
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ASN1CPP_ROOT = os.path.dirname(os.path.dirname(HERE))
ASNCPP_BIN = os.path.join(ASN1CPP_ROOT, "build/compiler/asn1cpp")
ASN1CPP_WIRE_CRATE = os.path.join(ASN1CPP_ROOT, "rust-runtime/wire")

TEMPLATE_CPP = os.path.join(HERE, "template_cpp")
TEMPLATE_RUST = os.path.join(HERE, "template_rust")
TEMPLATE_JAVA = os.path.join(HERE, "template_java")
JAVA_RUNTIME_SRC = os.path.join(ASN1CPP_ROOT, "java-runtime/src/main/java")
JAVA_PACKAGE = "xvalgen"
# The compiled Java runtime (build_java_runtime), set by --java.
java_runtime_classes = None
# Targets whose Java leg ran / was skipped, for the summary.
java_ran, java_skipped = [], []
TESTBUILD = os.path.join(HERE, "testbuild")
TARGETS_FILE = os.path.join(HERE, "targets.txt")
ASN1C_COMPILER_CORPUS_DIR = os.path.join(ASN1CPP_ROOT, "tests/tests-asn1c-compiler")

# A bare top-level "Name ::= SEQUENCE/SET/CHOICE {" — deliberately excludes
# "SEQUENCE OF"/"SET OF" (no '{' directly after the keyword: those forms
# name an element type instead) and any scalar alias (INTEGER, an
# existing type reference, etc.) — same "real top-level PDU/message type,
# not a scalar alias" qualification targets.txt's own header documents,
# just applied automatically instead of by hand.
_PDU_CANDIDATE_RE = re.compile(
    r"^\s*([A-Za-z][\w-]*)\s*::=\s*(?:SEQUENCE|SET|CHOICE)\s*\{", re.MULTILINE)

# A module header: "ModuleName", optionally followed by its definitive OID
# ("{ iso org(3) ... }"), then the DEFINITIONS keyword. Used both to find
# every module a single file defines (a file may define more than one —
# asn1c's own IMPORTS test fixtures commonly put the importing and
# imported module in the same file) and, corpus-wide, to build a
# module-name -> file index for the rarer genuinely cross-file case.
_MODULE_HEADER_RE = re.compile(
    r"^\s*([A-Za-z][\w-]*)\s*(?:\{[^}]*\})?\s*DEFINITIONS\b", re.MULTILINE)

# "FROM <ModuleName>" inside an IMPORTS clause (X.680 §34) — may repeat
# when one IMPORTS statement pulls from several modules.
_IMPORT_FROM_RE = re.compile(r"\bFROM\s+([A-Za-z][\w-]*)")


def build_module_index(corpus_dir):
    """Map every ASN.1 module name defined anywhere in `corpus_dir` to the
    (basename) file that defines it — for resolve_imports's genuinely
    cross-file case. A name defined in more than one file is dropped
    (ambiguous — resolve_imports treats it as unresolvable rather than
    guessing which file an importer meant)."""
    index = {}
    ambiguous = set()
    for name in sorted(os.listdir(corpus_dir)):
        if not name.endswith(".asn1"):
            continue
        text = open(os.path.join(corpus_dir, name), errors="replace").read()
        for m in _MODULE_HEADER_RE.finditer(text):
            mod = m.group(1)
            if mod in index and index[mod] != name:
                ambiguous.add(mod)
            else:
                index[mod] = name
    for mod in ambiguous:
        del index[mod]
    return index


def resolve_imports(asn1_path, module_index):
    """Resolve every module an IMPORTS clause in `asn1_path` names.

    Most of asn1c's own IMPORTS test fixtures define the importing and
    imported module in the *same* file (multi-module file) — the
    compiler already parses a single file's multiple modules into one
    shared ParseResult, so these need no extra files at all. A module
    not defined in this file but defined in exactly one *other* corpus
    file is a genuine cross-file dependency — that file is added to the
    returned extra-files list. A module this file imports that isn't
    defined anywhere in the corpus (and isn't ambiguous across files) is
    usually a deliberately-broken fixture testing the compiler's own
    "module not found" diagnostic (e.g. 49-real-life-OK.asn1,
    14-resolver-OK.asn1) — not a real schema this tooling can build, so
    returns None (skip) in that case, same as the old
    "any IMPORTS -> skip" behavior for these specific files.

    Returns (extra_files: list[str] of corpus-relative basenames) or None.
    """
    text = open(asn1_path, errors="replace").read()
    imported = set(_IMPORT_FROM_RE.findall(text))
    if not imported:
        return []
    defined_here = set(_MODULE_HEADER_RE.findall(text))
    extra_files = set()
    for mod in imported - defined_here:
        other = module_index.get(mod)
        if other is None:
            return None
        extra_files.add(other)
    return sorted(extra_files)


def discover_pdu_type(asn1_path):
    """Best-effort top-level PDU/message type name for an auto-discovered
    (not manually curated) schema file, or None if this file doesn't
    qualify — no bare top-level SEQUENCE/SET/CHOICE assignment anywhere in
    the file. (IMPORTS resolution is a separate concern — see
    resolve_imports.) Otherwise: a type literally named "PDU" if one
    exists (the common convention in asn1c's own test suite), else the
    last candidate found (heuristic — the outer/message type is usually
    declared after the types it's built from, not before)."""
    text = open(asn1_path, errors="replace").read()
    candidates = _PDU_CANDIDATE_RE.findall(text)
    if not candidates:
        return None
    if "PDU" in candidates:
        return "PDU"
    return candidates[-1]


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


# Failures of our own codec tools (C++/Rust b2x/x2b/b2j/j2b/b2p/p2b) seen
# while running the current target, per worker thread. A tool that exits
# nonzero or panics may still print some records, or none on both sides of
# a comparison (which compares as "no records", not a failure), so
# run_target fails the target on any entry here regardless of the record
# comparisons.
_tool_failures = threading.local()


def _codec_result(r, tool: str, leg: str) -> str:
    """stderr text of a codec tool run; records a failure in _tool_failures
    when the tool exited nonzero or a Rust binary panicked."""
    err = r.stderr.decode(errors="replace").strip()
    if r.returncode != 0 or "panicked" in err:
        failures = getattr(_tool_failures, "items", None)
        if failures is not None:
            failures.append(f"{leg} {tool}: exit {r.returncode}"
                            + (f": {err.splitlines()[-1]}" if err else ""))
    return err


def check_expected_errors(cpp_tools, rust_tools, pdu_type, ber_path) -> bool:
    """@expect-errors verdict: every BER-reading codec tool of both legs
    (b2x, b2j, b2p) must report a per-record error and exit 1 — no clean
    success, no panic, no signal."""
    ok = True
    for leg, tools in (("cpp", cpp_tools), ("rust", rust_tools)):
        for key in ("b2x", "b2j", "b2p"):
            if key not in tools:
                continue
            r = run(tools[key], "--type", pdu_type, ber_path)
            err = r.stderr.decode(errors="replace").strip()
            last = err.splitlines()[-1] if err else ""
            failed_line = next((l for l in err.splitlines() if "failed" in l), "")
            if r.returncode == 1 and "panicked" not in err and failed_line:
                print(f"  [OK]   {leg} {key}: per-record error: {failed_line}")
            else:
                print(f"  [FAIL] {leg} {key}: expected a per-record error, got exit {r.returncode}: {last}")
                ok = False
    return ok


# --fuzz verdict: a tool may reject malformed input (exit 1, "decode
# failed"), but must never crash. Seconds per tool run before it counts as
# a hang.
FUZZ_TIMEOUT = 30


def crash_of(tool: str, data: bytes, pdu_type: str):
    """Runs one codec tool on `data` (stdin). Returns None when it exited
    0 or 1 without panicking, else a one-line crash description: a signal
    (negative return code, incl. SIGABRT from an assert), a Rust panic
    (exit 101 or "panicked"), any other exit code, or a hang."""
    try:
        r = subprocess.run([tool, "--type", pdu_type], input=data,
                           capture_output=True, timeout=FUZZ_TIMEOUT)
    except subprocess.TimeoutExpired:
        return f"hang (> {FUZZ_TIMEOUT}s)"
    err = r.stderr.decode(errors="replace")
    if r.returncode < 0:
        return f"signal {-r.returncode}"
    if r.returncode not in (0, 1) or "panicked" in err:
        lines = err.strip().splitlines()
        line = next((l for l in lines if "panicked" in l), lines[-1] if lines else "")
        return f"exit {r.returncode}: {line}"
    return None


def mutate(data: bytes, rng: random.Random) -> bytes:
    """One random byte-level mutation of a valid encoding: flip a bit,
    overwrite a byte, truncate, insert or delete bytes."""
    b = bytearray(data)
    if not b:
        return bytes([rng.randrange(256)])
    kind = rng.randrange(5)
    i = rng.randrange(len(b))
    if kind == 0:
        b[i] ^= 1 << rng.randrange(8)
    elif kind == 1:
        b[i] = rng.choice((0x00, 0xFF, 0x7F, 0x80, rng.randrange(256)))
    elif kind == 2:
        del b[i:]
    elif kind == 3:
        b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9)))
    else:
        del b[i:i + rng.randrange(1, 9)]
    return bytes(b)


def java_fuzz(java_tools, pdu_type, inputs):
    """--fuzz Java leg: one JVM decodes every input file (BerRoundtrip
    --fuzz). Returns crash descriptions: an exception other than the
    runtime's DecodeException/EncodeException, or the JVM itself failing.
    The heap is capped so an allocation sized from a corrupted length
    shows up as OutOfMemoryError instead of swapping."""
    try:
        r = subprocess.run(["java", "-Xmx256m", "-cp", java_tools["classpath"], "xvalharness.BerRoundtrip",
                            "--fuzz", java_tools["classes"][pdu_type], *inputs],
                           capture_output=True, text=True, timeout=FUZZ_TIMEOUT * max(1, len(inputs)))
    except subprocess.TimeoutExpired:
        return [f"java: hang (> {FUZZ_TIMEOUT}s per input)"]
    crashes = [l[len("CRASH "):] for l in r.stdout.splitlines() if l.startswith("CRASH ")]
    if r.returncode not in (0, 3) or (r.returncode == 3 and not crashes):
        lines = r.stderr.strip().splitlines()
        crashes.append(f"java: exit {r.returncode}: {lines[-1] if lines else ''}")
    return crashes


def fuzz_target(cpp_tools, rust_tools, pdu_type, target_dir, ber_clean, opts, java_tools=None) -> bool:
    """--fuzz: feed malformed input to every decoder of both runtimes and
    fail the target only on a crash (see crash_of).
    BER: `--fuzz-seeds` randgen runs with BerCorruptor applied
    (--corrupt-percent/--corrupt-mode), a few records each — a decode error
    stops a tool at the first broken record. PER/XER/JER: `--mutations`
    seeded mutations of one valid record each (C++ encoder output), one
    tool run per mutation (PER keeps its 4-byte record frame). With a Java
    leg, its BER decoder gets the corrupted BER files plus `--mutations`
    mutated BER records, all in one JVM run (java_fuzz)."""
    crashes = []
    runs = 0
    java_inputs = []

    def probe(key, data, what):
        nonlocal runs
        for leg, tools in (("cpp", cpp_tools), ("rust", rust_tools)):
            if key not in tools:
                continue
            runs += 1
            c = crash_of(tools[key], data, pdu_type)
            if c:
                path = os.path.join(target_dir, f"crash_{leg}_{key}_{len(crashes)}.bin")
                with open(path, "wb") as f:
                    f.write(data)
                crashes.append(f"{leg} {key} ({what}): {c} — input {path}")

    for k in range(opts.fuzz_seeds):
        seed = opts.seed + k
        path = os.path.join(target_dir, "fuzz.ber")
        cmd = [cpp_tools["randgen"], "--type", pdu_type, "--count", str(opts.count),
               "--seed", str(seed), "--output", path,
               "--corrupt-percent", str(opts.corrupt_percent)]
        if opts.corrupt_mode:
            cmd += ["--corrupt-mode", opts.corrupt_mode]
        r = run(*cmd)
        if r.returncode != 0:
            print(f"  randgen --corrupt-percent failed: {r.stderr.decode(errors='replace').strip()}")
            return False
        with open(path, "rb") as f:
            data = f.read()
        for key in ("b2x", "b2j", "b2p"):
            probe(key, data, f"corrupted BER, seed {seed}")
        if java_tools:
            java_inputs.append(os.path.join(target_dir, f"fuzz_java_{k}.ber"))
            with open(java_inputs[-1], "wb") as f:
                f.write(data)

    rng = random.Random(opts.seed)
    clean_records = split_ber_records(ber_clean)[:max(1, opts.mutations // 4)]
    for fmt, enc_key, dec_key in (("XER", "b2x", "x2b"), ("JER", "b2j", "j2b"), ("PER", "b2p", "p2b")):
        if enc_key not in cpp_tools or dec_key not in cpp_tools:
            continue
        valid = []
        for rec in clean_records:
            r = run(cpp_tools[enc_key], "--type", pdu_type, input=rec)
            if r.returncode == 0 and r.stdout:
                valid.append(r.stdout[4:] if fmt == "PER" else r.stdout)
        if not valid:
            continue
        for m in range(opts.mutations):
            data = mutate(rng.choice(valid), rng)
            if fmt == "PER":
                data = len(data).to_bytes(4, "big") + data
            probe(dec_key, data, f"mutated {fmt} #{m}")

    if java_tools:
        jrng = random.Random(opts.seed)
        records = split_ber_records(ber_clean) or [ber_clean]
        for m in range(opts.mutations):
            java_inputs.append(os.path.join(target_dir, f"fuzz_java_m{m}.ber"))
            with open(java_inputs[-1], "wb") as f:
                f.write(mutate(jrng.choice(records), jrng))
        runs += len(java_inputs)
        crashes += [f"java BER: {c}" for c in java_fuzz(java_tools, pdu_type, java_inputs)]

    for c in crashes:
        print(f"  CRASH: {c}")
    print(f"  fuzz: {runs} decoder runs, {len(crashes)} crash(es)")
    return not crashes


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


def split_jer_records(text: str) -> list[str]:
    """Split JER output into per-record strings.

    Unlike XER's split_xer_records, JER needs no tag-balancing: JerCodec
    emits one compact JSON object per line, so each non-blank line is
    already a complete, self-delimiting record.
    """
    return [line for line in text.splitlines() if line.strip()]



# XER content itself is always valid text, but the ENCODING-CONTROL XER
# `::= utf8` instruction (gambas-asn1#443) writes OCTET STRING content
# octets directly as XML character data — and OCTET STRING content is
# arbitrary binary data, not guaranteed to actually be valid UTF-8 (a
# schema's `::= utf8` instruction declares intent, real-world/random test
# data doesn't have to honor it, and doesn't when randgen fills it).
# `errors="replace"` would silently substitute U+FFFD for any invalid byte
# sequence, corrupting/inflating the content before it's re-encoded on the
# x2b leg. `surrogateescape` round-trips every byte losslessly through a
# Python `str` instead — decode and encode must use the same error mode or
# the encode side raises.
_TEXT_ERRORS = "surrogateescape"


def b2x_file(tool: str, type_name: str, ber_path: str) -> tuple[str, str]:
    """BER file → XER string. Returns (xer_text, stderr)."""
    r = run(tool, "--type", type_name, ber_path)
    return r.stdout.decode(errors=_TEXT_ERRORS), _codec_result(r, tool, "b2x")


def x2b(tool: str, type_name: str, xer_text: str) -> tuple[bytes, str]:
    """XER string → BER bytes. Returns (ber_bytes, stderr)."""
    r = run(tool, "--type", type_name, input=xer_text.encode(errors=_TEXT_ERRORS))
    return r.stdout, _codec_result(r, tool, "x2b")


def b2j_file(tool: str, type_name: str, ber_path: str) -> tuple[str, str]:
    """BER file → JER string. Returns (jer_text, stderr)."""
    r = run(tool, "--type", type_name, ber_path)
    return r.stdout.decode(errors=_TEXT_ERRORS), _codec_result(r, tool, "b2j")


def j2b(tool: str, type_name: str, jer_text: str) -> tuple[bytes, str]:
    """JER string → BER bytes. Returns (ber_bytes, stderr)."""
    r = run(tool, "--type", type_name, input=jer_text.encode(errors=_TEXT_ERRORS))
    return r.stdout, _codec_result(r, tool, "j2b")


def b2p_file(tool: str, type_name: str, ber_path: str) -> tuple[bytes, str]:
    """BER file -> length-prefixed PER byte stream. Returns (per_bytes, stderr)."""
    r = run(tool, "--type", type_name, ber_path)
    return r.stdout, _codec_result(r, tool, "b2p")


def p2b(tool: str, type_name: str, per_bytes: bytes) -> tuple[bytes, str]:
    """Length-prefixed PER byte stream -> BER bytes. Returns (ber_bytes, stderr)."""
    r = run(tool, "--type", type_name, input=per_bytes)
    return r.stdout, _codec_result(r, tool, "p2b")


def split_per_records(data: bytes) -> list[bytes]:
    """Split a 4-byte-big-endian-length-prefixed PER byte stream (ber-to-per's
    own output framing, both cpp and rust legs — see template_cpp/src/
    ber-to-per.cpp's own doc for why PER itself needs this, unlike BER's
    self-delimiting TLVs) into per-record byte strings (prefix stripped,
    same shape split_ber_records/split_xer_records already return)."""
    records = []
    offset = 0
    while offset + 4 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
        if offset + length > len(data):
            break
        records.append(data[offset:offset + length])
        offset += length
    return records


# Status printed for a mismatch on an informational asn1c leg. None of
# them fails the target.
# - ASN1CINCOMPLETE: asn1c does not implement what the standard asks.
#   Implied for the PER legs whenever asn1c fails to decode its own PER
#   of the target back; stated by a target option where that round trip
#   passes but its output still differs from the standard's. BER is
#   never implied: asn1c's XER/JER-to-DER round trips gate unless a
#   target option explains them.
# - SEMANTICIDENTICAL: both sides carry the same value, asn1c re-encodes
#   it in another valid form. Only a target option can say this.
# - INFORMATIONAL: a mismatch with no known cause.
# A target option takes precedence over the implied status.
ASN1C_VERDICTS = {
    "@asn1c-opaque-contents": "ASN1CINCOMPLETE",   # X.682 §11.4 re-encoding under PER
    "@real-reencode": "SEMANTICIDENTICAL",         # REAL binary vs decimal form
}


def asn1c_verdict(options) -> str | None:
    """Status a target option states for its informational asn1c-leg
    mismatches (see ASN1C_VERDICTS), or None."""
    return next((ASN1C_VERDICTS[o] for o in sorted(options) if o in ASN1C_VERDICTS), None)


def compare_per(label: str, per_a: bytes, per_b: bytes, verbose: bool, info: str | None = None) -> tuple[int, int]:
    recs_a = split_per_records(per_a)
    recs_b = split_per_records(per_b)
    n = min(len(recs_a), len(recs_b))
    # A side that produced fewer records (a crash, a decode error, an
    # unsupported construct) fails the records it is missing; "no records"
    # is only fine when both sides are empty.
    short = abs(len(recs_a) - len(recs_b))
    if n == 0 and short == 0:
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
    if short:
        print(f"  [{label}] record count differs: {len(recs_a)} vs {len(recs_b)}")
    mismatches += short
    status = "OK" if mismatches == 0 else (info or "FAIL")
    print(f"  [{label}] {matches}/{n + short} match, {mismatches} mismatch  [{status}]")
    return matches, mismatches


def asn1c_b2x(tool: str, pdu_type: str, ber_path: str) -> tuple[str, str]:
    """BER file → XER string via asn1c's own converter-example. Returns (xer_text, stderr)."""
    r = run(tool, "-p", pdu_type, "-iber", "-oxer", ber_path)
    return r.stdout.decode(errors=_TEXT_ERRORS), r.stderr.decode(errors="replace").strip()


def asn1c_x2b(tool: str, pdu_type: str, xer_text: str) -> tuple[bytes, str]:
    """XER string → DER bytes via asn1c's own converter-example.

    converter-example takes a datafile argument, not stdin, unlike the
    C++/Rust tools' x2b — write to a temp file.
    """
    fd, xer_path = tempfile.mkstemp(suffix=".xer")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(xer_text.encode(errors=_TEXT_ERRORS))
        r = run(tool, "-p", pdu_type, "-ixer", "-oder", xer_path)
        return r.stdout, r.stderr.decode(errors="replace").strip()
    finally:
        os.unlink(xer_path)


def asn1c_b2j(tool: str, pdu_type: str, ber_path: str) -> tuple[str, str]:
    """BER file → JER string via asn1c's own converter-example.

    Unlike cpp/rust's ber-to-jer, asn1c's -ojer has no compact/one-line-
    per-record mode (an `ATS_JER_MINIFIED` enum value exists in
    converter-example.c but is never wired to a CLI flag — dead code
    upstream) — output is always pretty-printed, multi-line per record.
    Record splitting for this output therefore can't reuse
    split_jer_records (which assumes one record per line); see
    split_asn1c_jer_records below.
    """
    r = run(tool, "-p", pdu_type, "-iber", "-ojer", ber_path)
    return r.stdout.decode(errors=_TEXT_ERRORS), r.stderr.decode(errors="replace").strip()


def asn1c_j2b(tool: str, pdu_type: str, jer_text: str) -> tuple[bytes, str]:
    """JER string → DER bytes via asn1c's own converter-example.

    converter-example takes a datafile argument, not stdin, unlike the
    C++/Rust tools' j2b — write to a temp file. -ijer accepts multiple
    concatenated top-level JSON values in one file, same as -ixer does for
    XER (JER values are self-delimiting JSON). That needs an asn1c with
    mouse07410/asn1c#578 fixed: older converter-examples decode only the
    first PDU of a JER file larger than 8192 bytes.
    """
    fd, jer_path = tempfile.mkstemp(suffix=".jer")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(jer_text.encode(errors=_TEXT_ERRORS))
        r = run(tool, "-p", pdu_type, "-ijer", "-oder", jer_path)
        return r.stdout, r.stderr.decode(errors="replace").strip()
    finally:
        os.unlink(jer_path)


def split_asn1c_jer_records(text: str) -> list[str]:
    """Split asn1c's pretty-printed, multi-line JER output into per-record
    JSON strings, using a real JSON parser (json.JSONDecoder.raw_decode)
    rather than a line-based heuristic — the text has no record-boundary
    marker of its own beyond "one complete JSON value", and pretty-
    printing means a record can span many lines.
    """
    import json
    decoder = json.JSONDecoder()
    records = []
    idx = 0
    n = len(text)
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        obj, end = decoder.raw_decode(text, idx)
        records.append(text[idx:end])
        idx = end
    return records


def compare_jer(label: str, jer_a: str, jer_b: str, verbose: bool,
                 split_a=split_jer_records, split_b=split_jer_records) -> tuple[int, int]:
    """Compare two JER outputs record-by-record via parsed JSON equality,
    not raw string equality — needed whenever either side is asn1c's
    pretty-printed output (whitespace/indentation never matches our own
    compact one-line-per-record convention, even for byte-identical
    values). Still exact on the only thing that matters (JSON structure
    and values), not a lossy/lenient comparison.
    """
    import json
    recs_a = split_a(jer_a)
    recs_b = split_b(jer_b)
    n = min(len(recs_a), len(recs_b))
    # A side that produced fewer records (a crash, a decode error, an
    # unsupported construct) fails the records it is missing; "no records"
    # is only fine when both sides are empty.
    short = abs(len(recs_a) - len(recs_b))
    if n == 0 and short == 0:
        print(f"  [{label}] no records to compare")
        return 0, 0
    matches = mismatches = 0
    for i in range(n):
        try:
            a = json.loads(recs_a[i])
            b = json.loads(recs_b[i])
        except json.JSONDecodeError as e:
            mismatches += 1
            if verbose:
                print(f"  MISMATCH record #{i + 1}: JSON parse error: {e}")
            continue
        if a == b:
            matches += 1
        else:
            mismatches += 1
            if verbose:
                print(f"  MISMATCH record #{i + 1}:\n    expected {a}\n    got      {b}")
    if short:
        print(f"  [{label}] record count differs: {len(recs_a)} vs {len(recs_b)}")
    mismatches += short
    status = "OK" if mismatches == 0 else "FAIL"
    print(f"  [{label}] {matches}/{n + short} match, {mismatches} mismatch  [{status}]")
    return matches, mismatches


def asn1c_b2p(tool: str, pdu_type: str, ber_record: bytes) -> tuple[bytes, str]:
    """One BER-record's bytes -> raw UPER bytes via asn1c's own converter-example.

    One call per record, not the whole multi-record stream at once (#515):
    unlike BER's self-delimiting TLVs, UPER has no record boundary of its
    own, so a multi-PDU UPER stream can't be reliably split externally on
    the Python side once asn1c has encoded it. Matches asn1c_x2b's own
    per-record temp-file pattern — no dependency on whether asn1c's own
    -iuper reader supports multiple concatenated PDUs per file at all.
    """
    fd, ber_path = tempfile.mkstemp(suffix=".ber")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(ber_record)
        r = run(tool, "-p", pdu_type, "-iber", "-ouper", ber_path)
        return r.stdout, r.stderr.decode(errors="replace").strip()
    finally:
        os.unlink(ber_path)


def asn1c_p2b(tool: str, pdu_type: str, per_record: bytes) -> tuple[bytes, str]:
    """One record's raw UPER bytes -> DER bytes via asn1c's own converter-example."""
    fd, per_path = tempfile.mkstemp(suffix=".uper")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(per_record)
        r = run(tool, "-p", pdu_type, "-iuper", "-oder", per_path)
        return r.stdout, r.stderr.decode(errors="replace").strip()
    finally:
        os.unlink(per_path)


def pack_per_records(records: list[bytes]) -> bytes:
    """Inverse of split_per_records — reassemble individually-obtained PER
    records (e.g. one asn1c_b2p call per record) into the same 4-byte-
    length-prefixed framing compare_per expects, so the ground-truth PER
    leg can reuse it exactly like the cpp/rust comparisons do."""
    out = bytearray()
    for r in records:
        out += len(r).to_bytes(4, "big")
        out += r
    return bytes(out)


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
    # A side that produced fewer records (a crash, a decode error, an
    # unsupported construct) fails the records it is missing; "no records"
    # is only fine when both sides are empty.
    short = abs(len(recs_a) - len(recs_b))
    if n == 0 and short == 0:
        print(f"  [{label}] no records to compare")
        return 0, 0
    matches, mismatches = compare_records(recs_a, recs_b, verbose)
    if short:
        print(f"  [{label}] record count differs: {len(recs_a)} vs {len(recs_b)}")
    mismatches += short
    status = "OK" if mismatches == 0 else "FAIL"
    print(f"  [{label}] {matches}/{n + short} match, {mismatches} mismatch  [{status}]")
    return matches, mismatches


def run_comparison_jer(label: str, jer_a: str, jer_b: str, verbose: bool) -> tuple[int, int]:
    recs_a = split_jer_records(jer_a)
    recs_b = split_jer_records(jer_b)
    n = min(len(recs_a), len(recs_b))
    # A side that produced fewer records (a crash, a decode error, an
    # unsupported construct) fails the records it is missing; "no records"
    # is only fine when both sides are empty.
    short = abs(len(recs_a) - len(recs_b))
    if n == 0 and short == 0:
        print(f"  [{label}] no records to compare")
        return 0, 0
    matches, mismatches = compare_records(recs_a, recs_b, verbose)
    if short:
        print(f"  [{label}] record count differs: {len(recs_a)} vs {len(recs_b)}")
    mismatches += short
    status = "OK" if mismatches == 0 else "FAIL"
    print(f"  [{label}] {matches}/{n + short} match, {mismatches} mismatch  [{status}]")
    return matches, mismatches


def compare_ber(label: str, ber_a: bytes, ber_b: bytes, verbose: bool, info: str | None = None) -> tuple[int, int]:
    recs_a = split_ber_records(ber_a)
    recs_b = split_ber_records(ber_b)
    n = min(len(recs_a), len(recs_b))
    # A side that produced fewer records (a crash, a decode error, an
    # unsupported construct) fails the records it is missing; "no records"
    # is only fine when both sides are empty.
    short = abs(len(recs_a) - len(recs_b))
    if n == 0 and short == 0:
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
    if short:
        print(f"  [{label}] record count differs: {len(recs_a)} vs {len(recs_b)}")
    mismatches += short
    status = "OK" if mismatches == 0 else (info or "FAIL")
    print(f"  [{label}] {matches}/{n + short} match, {mismatches} mismatch  [{status}]")
    return matches, mismatches


# ---------------------------------------------------------------------------
# Target build orchestration

def parse_targets(path):
    """Returns a list of (schema, pdu_type, skip_asn1c_reason_or_None, extra_files).

    A line is normally "<schema> <PduType>"; <schema> may be a directory,
    meaning every .asn/.asn1 file under it (a multi-module schema such as
    ETSI LI). A third token+ marks a known,
    already-filed divergence between asn1c and asn1cpp for this specific
    target — the C++/Rust legs still run and gate pass/fail as usual, but
    the asn1c leg is skipped (not run at all) rather than failing the
    target on a gap that's already tracked elsewhere. The remaining
    tokens are the skip reason, printed verbatim (e.g. an issue number).
    extra_files is always [] here — the curated list is single-file only;
    only --corpus=asn1c-compiler's auto-discovery populates it (see
    resolve_imports).

    Tokens directly after the PDU type starting with '@' are target
    options: '@expect-errors' marks a schema neither runtime can encode or
    decode; the target passes when every C++ and Rust codec tool reports
    a per-record error and exits cleanly (exit 1, no panic or signal).
    '@asn1c-opaque-contents' marks a schema with contents-constrained
    OCTET STRINGs (X.682 §11) that follow the outer encoding: asn1c keeps
    their bytes as they are, while X.682 §11.4 has them re-encoded under
    PER, so the asn1c PER comparison is informational for it.
    '@real-reencode' marks a schema with REAL values that asn1c re-encodes
    in another valid form. See ASN1C_VERDICTS for how each one labels an
    informational mismatch."""
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
            # Tokens directly after the PDU type that start with '-' are
            # extra compiler flags for this target (e.g.
            # -fallow-newer-modules); everything from the first other token
            # on is the skip-asn1c reason (which may itself contain '-'
            # words).
            rest = parts[2:]
            n_opts = next((i for i, t in enumerate(rest) if not t.startswith("@")), len(rest))
            options = set(rest[:n_opts])
            unknown = options - {"@expect-errors", *ASN1C_VERDICTS}
            if unknown:
                print(f"{path}:{lineno}: unknown target option(s) {sorted(unknown)}")
                sys.exit(1)
            rest = rest[n_opts:]
            n_flags = next((i for i, t in enumerate(rest) if not t.startswith("-")), len(rest))
            # A --container-config path is relative to asn1cpp/ like the
            # schema path; make runs codegen from the target's own dir.
            flags = [f"--container-config={os.path.join(ASN1CPP_ROOT, t.split('=', 1)[1])}"
                     if t.startswith("--container-config=") else t for t in rest[:n_flags]]
            reason = " ".join(rest[n_flags:]) or None
            targets.append((parts[0], parts[1], reason, [], flags, options))
    return targets


def write_if_changed(path, data):
    """Write `data` (str or bytes) only when it differs from what is on
    disk, so an identical rewrite keeps the file's mtime and make/cargo
    see nothing to rebuild."""
    raw = data.encode() if isinstance(data, str) else data
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "rb") as f:
            if f.read() == raw:
                return
    except FileNotFoundError:
        pass
    with open(path, "wb") as f:
        f.write(raw)


def render(template_path, subs):
    with open(template_path) as f:
        text = f.read()
    for k, v in subs.items():
        text = text.replace(k, v)
    return text


def materialize(template_path, dest_path, subs):
    write_if_changed(dest_path, render(template_path, subs))


def pdu_flags(pdu_types):
    """One -pdu=<TYPE> per PDU type of a build group, for the compiler."""
    return " ".join(f"-pdu={t}" for t in pdu_types)


def render_rust_bin(template_path, entries):
    """A Rust tool template for several PDU types: its `TYPES` list names
    them all and its one `"__PDU_TYPE__" => {...}` match arm is repeated
    once per type. `entries` holds (pdu_type, ident, module) triples."""
    with open(template_path) as f:
        text = f.read()
    text = text.replace('&["__PDU_TYPE__"]', "&[" + ", ".join(f'"{t}"' for t, _, _ in entries) + "]")
    start = text.index('        "__PDU_TYPE__" => {\n')
    end = text.index("\n        }\n", start) + len("\n        }\n")
    arm = text[start:end]
    arms = "".join(arm.replace("__PDU_TYPE__", t).replace("__PDU_IDENT__", i).replace("__PDU_MODULE__", m)
                   for t, i, m in entries)
    return (text[:start] + arms + text[end:]).replace("__PDU_TYPE__", "|".join(t for t, _, _ in entries))


def copy_verbatim(src, dst):
    with open(src, "rb") as f:
        write_if_changed(dst, f.read())


def sync_dir(src, dst):
    """Content-based (checksum) sync of src into dst: files with identical
    content keep their mtime, so a regeneration that produced the same
    output triggers no rebuild. `delete` semantics are the Makefiles' own."""
    os.makedirs(dst, exist_ok=True)
    subprocess.run(["rsync", "-rc", src.rstrip("/") + "/", dst.rstrip("/") + "/"],
                   check=True, capture_output=True)


def file_sig(path):
    st = os.stat(path)
    return f"{path}:{st.st_size}:{st.st_mtime_ns}"


def reuse_key(schema_files, *extra):
    h = hashlib.sha256()
    for f in schema_files:
        with open(f, "rb") as fh:
            h.update(fh.read())
    for e in extra:
        h.update(e.encode())
    return h.hexdigest()


def key_matches(key_path, key):
    try:
        with open(key_path) as f:
            return f.read().strip() == key
    except FileNotFoundError:
        return False


def run_make(directory, *make_args, label="", env=None):
    r = subprocess.run(["make", "-C", directory, *make_args],
                        capture_output=True, text=True,
                        env={**os.environ, **env} if env else None)
    if r.returncode != 0:
        print(f"  BUILD FAILED ({label or ' '.join(make_args) or 'all'}):")
        print(r.stdout[-4000:])
        print(r.stderr[-4000:])
        return False
    return True


def discover_ident(gen_dir, ext, pdu_type):
    """Find the real generated identifier(s) for pdu_type in gen_dir.

    asn1cpp's identifier escaping (keyword collisions, rare case/module
    naming differences) can still differ per backend in edge cases and
    can't be predicted from the raw ASN.1 name alone in general. Both
    backends emit the raw, unescaped name verbatim as the type's own
    XER-name string literal though (`"name": "<raw>"` in the generated
    TypeDescriptor/ChoiceSpec), so grep for that instead of guessing a
    transform — file stem (minus ext) is the real identifier.
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


def discover_cpp_descriptor_ref(gen_dir, ident):
    """How to reach `ident`'s own `asn1::TypeDescriptor` in C++.

    A class-generating kind (SEQUENCE/CHOICE/SET/ENUMERATED, or a named
    SEQUENCE OF/SET OF with its own real wrapper class) gets it as a
    static member, `Ident::asn_DEF`. A *top-level* named SEQUENCE OF/SET
    OF type whose element isn't itself promoted compiles to a bare
    `using Ident = asn1::VectorSeqOf<...>;` alias instead (no class to
    attach a static member to) — gambas-asn1#689's own repro schema is
    exactly this shape — and the descriptor is then only reachable as
    the free global `asn_DEF_Ident`. Detected by grepping the generated
    `.hpp` for a `class`/`struct` declaration naming `ident`, rather
    than assuming one form — this is exactly the "free-standing alias
    isn't a realistic PDU root" case `types.cpp.tmpl` used to flatly
    refuse (see git history), now auto-detected instead.
    """
    hpp_path = os.path.join(gen_dir, f"{ident}.hpp")
    with open(hpp_path, errors="replace") as f:
        text = f.read()
    if re.search(rf"\b(class|struct)\s+{re.escape(ident)}\b", text):
        return f"{ident}::asn_DEF"
    return f"asn_DEF_{ident}"


def cpp_tool_paths(cpp_dir):
    return {
        "randgen": os.path.join(cpp_dir, "randgen"),
        "b2x": os.path.join(cpp_dir, "ber-to-xer"),
        "x2b": os.path.join(cpp_dir, "xer-to-ber"),
        "b2p": os.path.join(cpp_dir, "ber-to-per"),
        "p2b": os.path.join(cpp_dir, "per-to-ber"),
        "b2j": os.path.join(cpp_dir, "ber-to-jer"),
        "j2b": os.path.join(cpp_dir, "jer-to-ber"),
    }


def build_cpp(target_dir, asn1_files_abs, pdu_types, jobs=4, reuse=False, asncpp_flags=()):
    """Builds the C++ tools once for every PDU type of a build group: one
    codegen, one library, and tools whose `--type` registry holds them all."""
    cpp_dir = os.path.join(target_dir, "cpp")
    tools = cpp_tool_paths(cpp_dir)
    key_path = os.path.join(cpp_dir, ".reuse-key")
    key = reuse_key(asn1_files_abs, " ".join(pdu_types), " ".join(asncpp_flags), file_sig(ASNCPP_BIN),
                    file_sig(os.path.join(ASN1CPP_ROOT, "build/runtime/libasn1cpp_runtime.a")),
                    file_sig(os.path.join(TEMPLATE_CPP, "Makefile.tmpl")))
    if reuse and all(os.path.isfile(t) for t in tools.values()) and key_matches(key_path, key):
        print("  cpp legs: reused")
        return tools
    for name in ["randgen.cpp", "ber-to-xer.cpp", "xer-to-ber.cpp",
                 "ber-to-per.cpp", "per-to-ber.cpp",
                 "ber-to-jer.cpp", "jer-to-ber.cpp",
                 "type_registry.hpp", "type_registry.cpp"]:
        copy_verbatim(os.path.join(TEMPLATE_CPP, "src", name),
                      os.path.join(cpp_dir, "src", name))
    materialize(os.path.join(TEMPLATE_CPP, "Makefile.tmpl"),
                os.path.join(cpp_dir, "Makefile"),
                {"__ASN1CPP_ROOT__": ASN1CPP_ROOT,
                 "__ASN1_FILES__": " ".join(asn1_files_abs),
                 "__PDU_FLAGS__": pdu_flags(pdu_types),
                 "__ASNCPP_FLAGS__": " ".join(asncpp_flags)})

    # Codegen first — src/types.cpp (materialized below) needs the real
    # generated identifier, which can only be discovered after codegen
    # runs (see discover_ident's own doc).
    if not run_make(cpp_dir, "gen", label="C++ codegen"):
        return None
    includes, entries = [], []
    for pdu_type in pdu_types:
        idents = discover_ident(os.path.join(cpp_dir, "gen"), ".cpp", pdu_type)
        if len(idents) != 1:
            print(f"  expected exactly one C++ identifier for {pdu_type!r}, found {idents}")
            return None
        ident = idents[0]
        descriptor_ref = discover_cpp_descriptor_ref(os.path.join(cpp_dir, "gen"), ident)
        includes.append(f'#include "{ident}.hpp"')
        entries.append(f'            randgen::make_entry<{ident}>("{pdu_type}", {descriptor_ref}),')
    materialize(os.path.join(TEMPLATE_CPP, "src", "types.cpp.tmpl"),
                os.path.join(cpp_dir, "src", "types.cpp"),
                {"__PDU_INCLUDES__": "\n".join(includes), "__PDU_ENTRIES__": "\n".join(entries)})
    if not run_make(cpp_dir, "build", f"-j{jobs}", label="C++ build"):
        return None
    write_if_changed(key_path, key)
    return tools


def build_rust(target_dir, asn1_files_abs, pdu_types, slot=None, jobs=None, asncpp_flags=()):
    """Builds the Rust tools once for every PDU type of a build group.
    Returns the tool paths plus "per_types", the PDU types the PER tools
    were built for."""
    rust_dir = os.path.join(target_dir, "rust")
    copy_verbatim(os.path.join(TEMPLATE_RUST, "build.rs"),
                  os.path.join(rust_dir, "build.rs"))
    copy_verbatim(os.path.join(TEMPLATE_RUST, "src", "lib.rs"),
                  os.path.join(rust_dir, "src", "lib.rs"))
    materialize(os.path.join(TEMPLATE_RUST, "Makefile.tmpl"),
                os.path.join(rust_dir, "Makefile"),
                {"__ASNCPP__": ASNCPP_BIN,
                 "__ASN1_FILES__": " ".join(asn1_files_abs),
                 "__PDU_FLAGS__": pdu_flags(pdu_types),
                 "__ASNCPP_FLAGS__": " ".join(asncpp_flags)})
    if not run_make(rust_dir, "gen", label="Rust codegen"):
        return None
    lib_rs_path = os.path.join(rust_dir, "gen", "lib.rs")
    with open(lib_rs_path) as f:
        lib_rs = f.read()
    entries, per_entries = [], []
    for pdu_type in pdu_types:
        found = rust_pdu_entry(rust_dir, lib_rs, lib_rs_path, pdu_type)
        if found is None:
            return None
        entries.append(found[:3])
        if found[3]:
            per_entries.append(found[:3])
    for stem in ("ber_to_xer", "xer_to_ber", "ber_to_jer", "jer_to_ber"):
        write_if_changed(os.path.join(rust_dir, "src", "bin", f"{stem}.rs"),
                         render_rust_bin(os.path.join(TEMPLATE_RUST, "src", "bin", f"{stem}.rs.tmpl"), entries))
    per_covered = bool(per_entries)
    # Remove any stale ber_to_per.rs/per_to_ber.rs from a prior run of this
    # same target directory before deciding whether to write them again:
    # cargo auto-discovers every src/bin/*.rs file as its own binary
    # target regardless of Cargo.toml's explicit [[bin]] list, so a
    # leftover file for a type that is no longer covered would still get
    # compiled and fail.
    for stale in ("ber_to_per.rs", "per_to_ber.rs"):
        stale_path = os.path.join(rust_dir, "src", "bin", stale)
        if os.path.isfile(stale_path):
            os.remove(stale_path)
    for stem in ("ber_to_per", "per_to_ber") if per_covered else ():
        write_if_changed(os.path.join(rust_dir, "src", "bin", f"{stem}.rs"),
                         render_rust_bin(os.path.join(TEMPLATE_RUST, "src", "bin", f"{stem}.rs.tmpl"), per_entries))
    return finish_rust_build(rust_dir, per_covered, {t for t, _, _ in per_entries}, slot, jobs)


def rust_pdu_entry(rust_dir, lib_rs, lib_rs_path, pdu_type):
    """(pdu_type, ident, module, per_covered) of one PDU type in the
    generated Rust crate, or None when it cannot be found."""
    idents = discover_ident(os.path.join(rust_dir, "gen"), ".rs", pdu_type)
    if len(idents) != 1:
        print(f"  expected exactly one Rust identifier for {pdu_type!r}, found {idents}")
        return None
    ident = idents[0]
    # Module name may be a raw identifier (`r#type`) when the PDU name
    # collides with a Rust keyword (RustBackend's rust_escape()).
    m = re.search(rf'#\[path = "{re.escape(ident)}\.rs"\]\s*pub mod (r#\w+|\w+);', lib_rs)
    if not m:
        print(f"  could not find module for {ident}.rs in {lib_rs_path}")
        return None
    module = m.group(1)

    # PER coverage is decided at runtime, per value: there is no
    # codegen-time gate, and every generated top-level type implements
    # `Asn1Pdu`. This only confirms the PDU type itself was generated
    # (the same "ask the actual output" approach `discover_ident` uses).
    # A value whose kind the Rust PER runtime can't represent fails
    # encode / decode for that record.
    per_covered = False
    gen_file = os.path.join(rust_dir, "gen", f"{ident}.rs")
    if os.path.isfile(gen_file):
        with open(gen_file, errors="replace") as f:
            per_covered = f"impl asn1cpp_wire::spec::object::Asn1Pdu for {ident} " in f.read()
    return pdu_type, ident, module, per_covered


def finish_rust_build(rust_dir, per_covered, per_types, slot, jobs):
    """Writes Cargo.toml and builds the Rust tools of a build group."""
    # Written once, complete, and only if changed — an identical Cargo.toml
    # keeps its mtime so cargo's fingerprint stays valid.
    cargo_toml = render(os.path.join(TEMPLATE_RUST, "Cargo.toml.tmpl"),
                        {"__ASN1CPP_WIRE_CRATE__": ASN1CPP_WIRE_CRATE})
    if per_covered:
        cargo_toml += ('\n[[bin]]\nname = "ber-to-per"\npath = "src/bin/ber_to_per.rs"\n'
                       '\n[[bin]]\nname = "per-to-ber"\npath = "src/bin/per_to_ber.rs"\n')
    write_if_changed(os.path.join(rust_dir, "Cargo.toml"), cargo_toml)

    # One cargo target dir per worker slot (not per target): the wire
    # crate compiles once per slot instead of once per target. A slot runs
    # its targets sequentially, so the shared dir is never built
    # concurrently.
    env = {}
    bin_dir = os.path.join(rust_dir, "target/release")
    if slot is not None:
        cargo_target = os.path.join(TESTBUILD, "_cargo", f"slot{slot}")
        env["CARGO_TARGET_DIR"] = cargo_target
        bin_dir = os.path.join(cargo_target, "release")
    if jobs:
        env["CARGO_BUILD_JOBS"] = str(jobs)
    if not run_make(rust_dir, "build", label="Rust cargo build", env=env):
        return None
    result = {
        "b2x": os.path.join(bin_dir, "ber-to-xer"),
        "x2b": os.path.join(bin_dir, "xer-to-ber"),
        "b2j": os.path.join(bin_dir, "ber-to-jer"),
        "j2b": os.path.join(bin_dir, "jer-to-ber"),
    }
    if per_covered:
        result["b2p"] = os.path.join(bin_dir, "ber-to-per")
        result["p2b"] = os.path.join(bin_dir, "per-to-ber")
    result["per_types"] = per_types
    return result


def java_sources(root):
    return sorted(os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs if f.endswith(".java"))


def javac(out_dir, sources, classpath=None):
    """Compiles `sources` into `out_dir` under the same lint gate as the
    Gradle builds; returns the javac result."""
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir)
    cmd = ["javac", "--release", "21", "-Xlint:all", "-Werror", "-d", out_dir]
    if classpath:
        cmd += ["-cp", classpath]
    return subprocess.run(cmd + sources, capture_output=True, text=True)


def build_java_runtime():
    """Compiles java-runtime/ once per sweep with plain javac, so the Java
    leg needs a JDK but no Gradle. Returns the classes dir, or None."""
    out = os.path.join(TESTBUILD, "java-runtime")
    key_path = out + ".reuse-key"
    srcs = java_sources(JAVA_RUNTIME_SRC)
    key = reuse_key(srcs)
    if key_matches(key_path, key) and os.path.isdir(out):
        return out
    r = javac(out, srcs)
    if r.returncode != 0:
        print(f"java runtime build failed:\n{r.stdout[-4000:]}{r.stderr[-4000:]}")
        return None
    write_if_changed(key_path, key)
    return out


def build_java(target_dir, asn1_files_abs, pdu_types, asncpp_flags=()):
    """Generates and compiles the Java leg of a build group: the schema
    under --target=java plus the BerRoundtrip harness. Returns
    {"classpath", "classes": {pdu_type: class name}}, {"skipped": reason}
    when the Java backend does not emit a construct of the schema yet, or
    None when generation or compilation fails otherwise."""
    java_dir = os.path.join(target_dir, "java")
    gen_dir = os.path.join(java_dir, "gen")
    shutil.rmtree(gen_dir, ignore_errors=True)
    os.makedirs(gen_dir)
    r = subprocess.run([ASNCPP_BIN, "--target=java", f"--package={JAVA_PACKAGE}",
                        *[f"-pdu={t}" for t in pdu_types], *asncpp_flags, *asn1_files_abs, "-o", gen_dir],
                       capture_output=True, text=True)
    if r.returncode != 0:
        msg = (r.stderr.strip().splitlines() or ["?"])[-1]
        if "not implemented for this backend" in r.stderr:
            return {"skipped": msg}
        print(f"  BUILD FAILED (Java codegen): {r.stderr[-4000:]}")
        return None
    classes = {}
    for t in pdu_types:
        idents = discover_ident(gen_dir, ".java", t)
        if len(idents) != 1:
            print(f"  expected exactly one Java class for {t!r}, found {idents}")
            return None
        classes[t] = f"{JAVA_PACKAGE}.{idents[0]}"
    out = os.path.join(java_dir, "classes")
    r = javac(out, java_sources(gen_dir) + [os.path.join(TEMPLATE_JAVA, "BerRoundtrip.java")],
              java_runtime_classes)
    if r.returncode != 0:
        print(f"  BUILD FAILED (Java compile):\n{r.stdout[-4000:]}{r.stderr[-4000:]}")
        return None
    return {"classpath": out + os.pathsep + java_runtime_classes, "classes": classes}


def java_roundtrip(java_tools, pdu_type, ber_path, out_path):
    """Java leg: BER-decodes every record of `ber_path` and re-encodes it."""
    r = subprocess.run(["java", "-cp", java_tools["classpath"], "xvalharness.BerRoundtrip",
                        java_tools["classes"][pdu_type], ber_path, out_path],
                       capture_output=True, text=True, timeout=300)
    data = b""
    if os.path.isfile(out_path):
        with open(out_path, "rb") as f:
            data = f.read()
    return data, r.stderr.strip()


def java_b2x(java_tools, pdu_type, ber_path, out_path):
    """Java leg: BER file -> XER text, one document per record. Returns
    (xer_text, stderr)."""
    r = subprocess.run(["java", "-cp", java_tools["classpath"], "xvalharness.BerRoundtrip", "--b2x",
                        java_tools["classes"][pdu_type], ber_path, out_path],
                       capture_output=True, text=True, timeout=300)
    text = ""
    if os.path.isfile(out_path):
        with open(out_path, "rb") as f:
            text = f.read().decode(errors=_TEXT_ERRORS)
    return text, r.stderr.strip()


def java_x2b(java_tools, pdu_type, xer_text, in_path, out_path):
    """Java leg: XER text -> BER bytes, one record per document. Returns
    (ber_bytes, stderr)."""
    with open(in_path, "wb") as f:
        f.write(xer_text.encode(errors=_TEXT_ERRORS))
    r = subprocess.run(["java", "-cp", java_tools["classpath"], "xvalharness.BerRoundtrip", "--x2b",
                        java_tools["classes"][pdu_type], in_path, out_path],
                       capture_output=True, text=True, timeout=300)
    data = b""
    if os.path.isfile(out_path):
        with open(out_path, "rb") as f:
            data = f.read()
    return data, r.stderr.strip()


def build_asn1c(target_dir, asn1_files_abs, pdu_types, asn1c_bin, reuse=False, jobs=4):
    """Build asn1c's own converter-example tool for this target — ground
    truth leg (#440). Returns None (not a hard error) whenever asn1c
    itself can't handle this target's schema/construct — codegen or build
    failure just means this target's asn1c leg is skipped, same as
    "asn1c not found" globally; the C++/Rust legs never depend on this.

    Codegen goes to a scratch dir and is checksum-synced into the build
    dir, so unchanged generated files keep their mtime and `make` rebuilds
    nothing.
    """
    c_dir = os.path.join(target_dir, "asn1c")
    os.makedirs(c_dir, exist_ok=True)
    tool = os.path.join(c_dir, "converter-example")
    key_path = os.path.join(c_dir, ".reuse-key")
    key = reuse_key(asn1_files_abs, " ".join(pdu_types), file_sig(asn1c_bin))
    if reuse and os.path.isfile(tool) and key_matches(key_path, key):
        print("  asn1c leg: reused")
        return {"tool": tool}
    scratch = c_dir + ".gen"
    shutil.rmtree(scratch, ignore_errors=True)
    os.makedirs(scratch)
    r = run(asn1c_bin, "-fcompound-names", "-fno-include-deps",
            "-fallow-newer-modules", *(f"-pdu={t}" for t in pdu_types), "-D", scratch,
            *asn1_files_abs)
    if r.returncode != 0:
        print(f"  asn1c leg: codegen failed, skipping — {r.stderr.decode(errors='replace')[-500:]}")
        shutil.rmtree(scratch, ignore_errors=True)
        return None
    sync_dir(scratch, c_dir)
    shutil.rmtree(scratch, ignore_errors=True)
    mk = os.path.join(c_dir, "converter-example.mk")
    if not os.path.isfile(mk):
        print(f"  asn1c leg: no converter-example.mk produced, skipping")
        return None
    # asn1c bakes the -D directory into its makefiles as absolute paths;
    # point them at the real build dir so the scratch dir can go away.
    for name in os.listdir(c_dir):
        if name.endswith(".mk") or name.startswith("Makefile"):
            path = os.path.join(c_dir, name)
            with open(path) as f:
                text = f.read()
            write_if_changed(path, text.replace(scratch, c_dir))
    r = run("make", f"-j{jobs}", "-C", c_dir, "-f", "converter-example.mk")
    if r.returncode != 0:
        print(f"  asn1c leg: build failed, skipping — {r.stderr.decode(errors='replace')[-500:]}")
        return None
    if not os.path.isfile(tool):
        print(f"  asn1c leg: converter-example binary not produced, skipping")
        return None
    write_if_changed(key_path, key)
    return {"tool": tool}


def group_key(t):
    """Targets with the same schema, extra files and compiler flags share
    one build (`build_group`)."""
    return (t[0], tuple(t[3]), tuple(t[4]))


def schema_files(schema_rel, extra_files=()):
    """(asn1 files, testbuild slug base) of a target's schema: a directory
    means every .asn/.asn1 file under it (a multi-module schema such as
    ETSI LI), sorted, the same set the example Makefiles compile."""
    schema_abs = os.path.join(ASN1CPP_ROOT, schema_rel)
    if os.path.isdir(schema_abs):
        asn1_files_abs = sorted(
            os.path.join(root, f)
            for root, _, files in os.walk(schema_abs)
            for f in files if f.endswith((".asn", ".asn1")))
        slug_base = os.path.basename(os.path.dirname(schema_abs.rstrip("/")))
    else:
        asn1_files_abs = [schema_abs]
        slug_base = os.path.splitext(os.path.basename(schema_rel))[0]
    return asn1_files_abs + [os.path.join(ASN1CPP_ROOT, f) for f in extra_files], slug_base


def build_group(schema_rel, pdu_types, extra_files, asncpp_flags, asn1c_bin, slot=None,
                cpp_jobs=4, cargo_jobs=None, reuse=()):
    """Builds the C++, Rust and (with `asn1c_bin`) asn1c tools once for a
    build group: the targets that share a schema, extra files and compiler
    flags. Compiling the schema dominates a target's cost, so its PDU types
    share one build and each target only runs its own checks. Returns
    {"dir", "cpp", "rust", "asn1c", "java"}, or None when the C++ or Rust
    build fails; "java" is None without --java."""
    asn1_files_abs, slug_base = schema_files(schema_rel, extra_files)
    target_dir = os.path.join(TESTBUILD, slug_base + "_" + "_".join(pdu_types))
    if len(pdu_types) > 1:
        print(f"  one build for {len(pdu_types)} PDU types: {', '.join(pdu_types)}")
    cpp_tools = build_cpp(target_dir, asn1_files_abs, pdu_types, cpp_jobs, "cpp" in reuse, asncpp_flags)
    if cpp_tools is None:
        return None
    rust_tools = build_rust(target_dir, asn1_files_abs, pdu_types, slot, cargo_jobs, asncpp_flags)
    if rust_tools is None:
        return None
    asn1c_tools = (build_asn1c(target_dir, asn1_files_abs, pdu_types, asn1c_bin, "asn1c" in reuse, cpp_jobs)
                   if asn1c_bin else None)
    java_tools = (build_java(target_dir, asn1_files_abs, pdu_types, asncpp_flags)
                  if java_runtime_classes else None)
    if java_runtime_classes and java_tools is None:
        java_tools = {"failed": True}
    return {"dir": target_dir, "cpp": cpp_tools, "rust": rust_tools, "asn1c": asn1c_tools, "java": java_tools}


def run_target(schema_rel, pdu_type, count, seed, verbose, built, skip_asn1c_reason=None,
               extra_files=(), expect_errors=False, fuzz=None, asn1c_opaque_contents=False,
               info=None):
    """Runs one target's checks against its build group's tools
    (`build_group`); `built` is None when that build failed."""
    extra_note = f" (+ {', '.join(extra_files)})" if extra_files else ""
    print(f"\n=== {schema_rel} :: {pdu_type}{extra_note} ===")
    _tool_failures.items = []
    if skip_asn1c_reason:
        print(f"  asn1c leg: skipped ({skip_asn1c_reason})")
    if built is None:
        print("  build failed (see the first target of this build group)")
        return False
    cpp_tools = built["cpp"]
    rust_tools = dict(built["rust"])
    if pdu_type not in rust_tools["per_types"]:
        rust_tools.pop("b2p", None)
        rust_tools.pop("p2b", None)
    asn1c_tools = (built["asn1c"]
                   if not skip_asn1c_reason and not expect_errors and fuzz is None else None)
    target_dir = os.path.join(built["dir"], "pdu_" + pdu_type)
    os.makedirs(target_dir, exist_ok=True)

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

    if expect_errors:
        return check_expected_errors(cpp_tools, rust_tools, pdu_type, ber_path)
    if fuzz is not None:
        java_fuzz_tools = built.get("java")
        if java_fuzz_tools is not None:
            label = f"{schema_rel} :: {pdu_type}"
            if "classes" in java_fuzz_tools:
                java_ran.append(label)
            else:
                print(f"  java leg: skipped ({java_fuzz_tools.get('skipped', 'build failed')})")
                java_skipped.append(label)
                java_fuzz_tools = None
        return fuzz_target(cpp_tools, rust_tools, pdu_type, target_dir, ber_orig, fuzz, java_fuzz_tools)

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

    # Java leg (--java): the BER round trip of the C++ records, then the
    # same XER matrix as the Rust rows: Java's XER against C++'s, its own
    # round trip, and both cross combinations.
    java_tools = built.get("java")
    xer_java = None
    if java_tools is not None:
        label = f"{schema_rel} :: {pdu_type}"
        if "skipped" in java_tools:
            print(f"  java leg: skipped ({java_tools['skipped']})")
            java_skipped.append(label)
        elif "failed" in java_tools:
            print("  java leg: build failed (see the first target of this build group)")
            tally((0, 1))
        else:
            ber_java, err_java = java_roundtrip(java_tools, pdu_type, ber_path,
                                                os.path.join(target_dir, "java.ber"))
            if err_java:
                print(f"  java stderr: {err_java}")
            tally(compare_ber("orig vs java.BER(orig)", ber_orig, ber_java, verbose))

            xer_java, err_java_xer = java_b2x(java_tools, pdu_type, ber_path,
                                              os.path.join(target_dir, "java.xer"))
            if err_java_xer:
                print(f"  java b2x stderr: {err_java_xer}")
            xer_java = dedent_xer(xer_java)
            tally(run_comparison("cpp.B2X vs java.B2X", xer_cpp, xer_java, verbose))

            def java_x2b_check(label, xer_text, tool=None):
                if tool is None:
                    ber, err = java_x2b(java_tools, pdu_type, xer_text,
                                        os.path.join(target_dir, "java.x2b.in.xer"),
                                        os.path.join(target_dir, "java.x2b.ber"))
                    if err:
                        print(f"  java x2b stderr: {err}")
                else:
                    ber, _ = x2b(tool, pdu_type, xer_text)
                tally(compare_ber(label, ber_orig, ber, verbose))

            java_x2b_check("orig vs java.X2B(java.XER)", xer_java)
            java_x2b_check("orig vs java.X2B(cpp.XER)", xer_cpp)
            java_x2b_check("orig vs cpp.X2B(java.XER)", xer_java, cpp_tools["x2b"])
            java_ran.append(label)

    ber_cpp2, _ = x2b(cpp_tools["x2b"], pdu_type, xer_cpp)
    tally(compare_ber("orig vs cpp.X2B(cpp.XER)", ber_orig, ber_cpp2, verbose))

    ber_rust2, _ = x2b(rust_tools["x2b"], pdu_type, xer_rust)
    tally(compare_ber("orig vs rust.X2B(rust.XER)", ber_orig, ber_rust2, verbose))

    ber_cross1, _ = x2b(rust_tools["x2b"], pdu_type, xer_cpp)
    tally(compare_ber("orig vs rust.X2B(cpp.XER)", ber_orig, ber_cross1, verbose))

    ber_cross2, _ = x2b(cpp_tools["x2b"], pdu_type, xer_rust)
    tally(compare_ber("orig vs cpp.X2B(rust.XER)", ber_orig, ber_cross2, verbose))

    # JER leg — unconditional, same reason the XER legs above are: every
    # SEQUENCE/CHOICE top-level type gets encode_jer()/decode_jer()
    # unconditionally from codegen (no per_covered-style gate like PER's).
    # asn1c DOES have JER support (an earlier claim here that it didn't
    # was wrong — confirmed 2026-10-07 by reading converter-example's own
    # -ijer/-ojer flags); its own asn1c.B2J leg is added further down,
    # alongside the existing asn1c.B2X leg, not here.
    jer_cpp, err_cpp_jer = b2j_file(cpp_tools["b2j"], pdu_type, ber_path)
    if err_cpp_jer:
        print(f"  cpp b2j stderr: {err_cpp_jer}")
    jer_rust, err_rust_jer = b2j_file(rust_tools["b2j"], pdu_type, ber_path)
    if err_rust_jer:
        print(f"  rust b2j stderr: {err_rust_jer}")

    tally(run_comparison_jer("cpp.B2J vs rust.B2J", jer_cpp, jer_rust, verbose))

    # Our JER round-trips exactly: REAL is written as the shortest text
    # that converts back to the same double, and a fixed-size BIT STRING
    # as its bare hex string (X.697), so every orig-round-trip leg gates.
    def jer_rt_check(label, a, b):
        tally(compare_ber(label, a, b, verbose))

    ber_jer_cpp2, _ = j2b(cpp_tools["j2b"], pdu_type, jer_cpp)
    jer_rt_check("orig vs cpp.J2B(cpp.JER)", ber_orig, ber_jer_cpp2)

    ber_jer_rust2, _ = j2b(rust_tools["j2b"], pdu_type, jer_rust)
    jer_rt_check("orig vs rust.J2B(rust.JER)", ber_orig, ber_jer_rust2)

    ber_jer_cross1, _ = j2b(rust_tools["j2b"], pdu_type, jer_cpp)
    jer_rt_check("orig vs rust.J2B(cpp.JER)", ber_orig, ber_jer_cross1)

    ber_jer_cross2, _ = j2b(cpp_tools["j2b"], pdu_type, jer_rust)
    jer_rt_check("orig vs cpp.J2B(rust.JER)", ber_orig, ber_jer_cross2)

    # PER leg — only when the Rust side actually generated the type
    # (build_rust's own per_covered detection; "b2p"/"p2b" keys are absent
    # from rust_tools otherwise). C++ always supports PER
    # (its generic TypeDescriptor-driven PerCodec has no per-type
    # coverage gate the way RustBackend's codegen currently does), so this
    # entire leg is gated on Rust alone. Same matrix shape as the XER
    # legs above — cpp vs rust, both round-trips, both cross combinations
    # — using the 4-byte-length-prefixed PER record framing (PER has no
    # self-delimiting record boundary of its own, see ber-to-per.cpp's own
    # doc); an untested target isn't a failure, just narrower coverage
    # than the BER/XER legs, printed but not gated.
    if "b2p" in rust_tools:
        per_cpp, err_cpp_per = b2p_file(cpp_tools["b2p"], pdu_type, ber_path)
        if err_cpp_per:
            print(f"  cpp b2p stderr: {err_cpp_per}")
        per_rust, err_rust_per = b2p_file(rust_tools["b2p"], pdu_type, ber_path)
        if err_rust_per:
            print(f"  rust b2p stderr: {err_rust_per}")

        tally(compare_per("cpp.PER vs rust.PER", per_cpp, per_rust, verbose))

        ber_cpp_per2, _ = p2b(cpp_tools["p2b"], pdu_type, per_cpp)
        tally(compare_ber("orig vs cpp.P2B(cpp.PER)", ber_orig, ber_cpp_per2, verbose))

        ber_rust_per2, _ = p2b(rust_tools["p2b"], pdu_type, per_rust)
        tally(compare_ber("orig vs rust.P2B(rust.PER)", ber_orig, ber_rust_per2, verbose))

        ber_per_cross1, _ = p2b(rust_tools["p2b"], pdu_type, per_cpp)
        tally(compare_ber("orig vs rust.P2B(cpp.PER)", ber_orig, ber_per_cross1, verbose))

        ber_per_cross2, _ = p2b(cpp_tools["p2b"], pdu_type, per_rust)
        tally(compare_ber("orig vs cpp.P2B(rust.PER)", ber_orig, ber_per_cross2, verbose))

        if asn1c_tools:
            # Both directions below are informational only, same rationale as
            # the existing asn1c.X2B(asn1c.XER) check further down: *any*
            # comparison that ends with asn1c producing DER inherits asn1c's
            # own re-encoding-choice instability for certain values (e.g.
            # REAL's binary vs decimal form) -- confirmed empirically on
            # roundtrip_test.asn1::Container (REAL-bearing): asn1c.P2B of
            # OUR OWN PER output mismatches orig for the exact same record
            # #2 that asn1c.X2B(asn1c.XER) already independently flags as
            # unstable, regardless of which wire format fed asn1c's DER
            # encoder. Not a decode-side signal (asn1c correctly decoded our
            # PER either way) -- genuinely nothing to gate on here.
            #
            # A second, unrelated known cause: choice_test.asn1::Alt4 (and
            # canon_choice_bug_test.asn1::Alt4) mismatch asn1c.PER on every
            # record, not just one unstable value. This is not a target for
            # our own codec to match: asn1c's generated to_canonical_order/
            # from_canonical_order arrays are swapped for any untagged
            # CHOICE whose declaration order needs a non-involutory reorder
            # to reach X.680 8.6 canonical (ascending-tag) order -- our own
            # BER/PER output is spec-correct and internally consistent
            # (cpp.PER == rust.PER, both round-trip), asn1c's is not.
            cpp_recs = split_per_records(per_cpp)
            rust_recs = split_per_records(per_rust)
            der_from_cpp, der_from_rust = [], []
            p2b_err = None
            for rec in cpp_recs:
                d, e = asn1c_p2b(asn1c_tools["tool"], pdu_type, rec)
                der_from_cpp.append(d)
                p2b_err = p2b_err or e
            for rec in rust_recs:
                d, e = asn1c_p2b(asn1c_tools["tool"], pdu_type, rec)
                der_from_rust.append(d)
                p2b_err = p2b_err or e
            if p2b_err:
                print(f"  asn1c p2b stderr: {p2b_err}")

            # asn1c's own PER encoding of the original value, one record at
            # a time (asn1c_b2p's own doc on why) -- same informational
            # rationale as above.
            ber_records = split_ber_records(ber_orig)
            asn1c_per_records = []
            asn1c_per_err = None
            for rec in ber_records:
                per_rec, err = asn1c_b2p(asn1c_tools["tool"], pdu_type, rec)
                if err and not asn1c_per_err:
                    asn1c_per_err = err
                asn1c_per_records.append(per_rec)
            if asn1c_per_err:
                print(f"  asn1c b2p stderr: {asn1c_per_err}")
            per_asn1c = pack_per_records(asn1c_per_records)

            der_records = []
            for per_rec in asn1c_per_records:
                der_rec, _ = asn1c_p2b(asn1c_tools["tool"], pdu_type, per_rec)
                der_records.append(der_rec)
            ber_asn1c_per2 = b"".join(der_records)
            self_m, self_mm = compare_ber("orig vs asn1c.P2B(asn1c.PER) [informational]",
                                          ber_orig, ber_asn1c_per2, verbose,
                                          info=info or "ASN1CINCOMPLETE")
            per_info = info or ("ASN1CINCOMPLETE" if self_mm else "INFORMATIONAL")
            compare_ber("orig vs asn1c.P2B(cpp.PER) [informational]", ber_orig, b"".join(der_from_cpp), verbose, info=per_info)
            compare_ber("orig vs asn1c.P2B(rust.PER) [informational]", ber_orig, b"".join(der_from_rust), verbose, info=per_info)

            # asn1c is the PER ground truth wherever it round-trips its own
            # encoding of every record: then any difference from cpp/rust is
            # gated. Where asn1c's own round trip fails, its PER bytes aren't
            # trustworthy for this target and the comparison stays
            # informational. So it is for a target whose contained values
            # asn1c carries as opaque bytes (@asn1c-opaque-contents).
            if self_m > 0 and self_mm == 0 and not asn1c_opaque_contents:
                tally(compare_per("asn1c.PER vs cpp.PER", per_asn1c, per_cpp, verbose))
                tally(compare_per("asn1c.PER vs rust.PER", per_asn1c, per_rust, verbose))
            else:
                compare_per("asn1c.PER vs cpp.PER [informational]", per_asn1c, per_cpp, verbose, info=per_info)
                compare_per("asn1c.PER vs rust.PER [informational]", per_asn1c, per_rust, verbose, info=per_info)
        elif not skip_asn1c_reason:
            print("  asn1c PER leg: skipped (not found or unsupported for this target)")
    else:
        print("  PER leg: skipped (Rust codegen doesn't cover this type's members/alternatives yet)")

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
        if xer_java is not None:
            tally(run_comparison("asn1c.B2X vs java.B2X", xer_asn1c, xer_java, verbose))

        def asn1c_ber_check(label, ber_asn1c):
            if info:
                compare_ber(f"{label} [informational]", ber_orig, ber_asn1c, verbose, info=info)
            else:
                tally(compare_ber(label, ber_orig, ber_asn1c, verbose))

        # asn1c's own XER round trip ends in its DER encoder. It gates: a BER
        # difference is a hard failure unless a target option explains it
        # (@real-reencode: a type with REAL fields can re-encode to a
        # different, still valid DER byte sequence for the same value).
        ber_asn1c2, _ = asn1c_x2b(asn1c_tools["tool"], pdu_type, xer_asn1c)
        asn1c_ber_check("orig vs asn1c.X2B(asn1c.XER)", ber_asn1c2)

        # JER: asn1c does have JER support (ASN_DISABLE_JER_SUPPORT is off
        # by default, A1C_GEN_JER in asn1c.c's default flags) — confirmed
        # 2026-10-07 after an earlier, wrong claim in this epic that it
        # didn't. Its -ojer has no compact/one-line-per-record mode
        # (asn1c_b2j's own doc), so comparisons here use compare_jer
        # (parsed-JSON equality) instead of run_comparison_jer's raw
        # string compare, and the asn1c side is split with
        # split_asn1c_jer_records instead of split_jer_records.
        jer_asn1c, err_asn1c_jer = asn1c_b2j(asn1c_tools["tool"], pdu_type, ber_path)
        if err_asn1c_jer:
            print(f"  asn1c b2j stderr: {err_asn1c_jer}")

        # asn1c's JER is the ground truth here too: its REAL encoder always
        # writes %.17E (REAL_encode_jer passes its flags as `canonical`),
        # which is lossless, and compare_jer compares parsed JSON, so equal
        # values match whatever their notation.
        def jer_asn1c_check(label, a, b, **kw):
            tally(compare_jer(label, a, b, verbose, **kw))

        jer_asn1c_check("asn1c.B2J vs cpp.B2J", jer_asn1c, jer_cpp, split_a=split_asn1c_jer_records)
        jer_asn1c_check("asn1c.B2J vs rust.B2J", jer_asn1c, jer_rust, split_a=split_asn1c_jer_records)

        # asn1c's own JER round trip ends in its DER encoder: gated the same
        # way as orig vs asn1c.X2B above.
        ber_asn1c_jer2, _ = asn1c_j2b(asn1c_tools["tool"], pdu_type, jer_asn1c)
        asn1c_ber_check("orig vs asn1c.J2B(asn1c.JER)", ber_asn1c_jer2)
    elif not skip_asn1c_reason:
        print("  asn1c leg: skipped (not found or unsupported for this target)")

    tool_failures = _tool_failures.items
    _tool_failures.items = None
    for f in tool_failures:
        print(f"  TOOL FAILURE: {f}")
    if tool_failures:
        print(f"  --- {schema_rel}::{pdu_type}: FAIL — {len(tool_failures)} codec tool run(s) failed ---")
        return False
    if total_records == 0:
        print(f"  --- {schema_rel}::{pdu_type}: FAIL — no records compared (harness/parsing gap, not verified) ---")
        return False
    print(f"  --- {schema_rel}::{pdu_type}: {total_matches} pass, {total_mismatches} fail ---")
    return total_mismatches == 0


class _ThreadStdout:
    """Per-thread stdout capture: a worker sets `tl.buf` to a list and its
    prints accumulate there instead of interleaving with other workers."""

    def __init__(self, real):
        self.real = real
        self.tl = threading.local()

    def write(self, text):
        buf = getattr(self.tl, "buf", None)
        if buf is None:
            return self.real.write(text)
        buf.append(text)
        return len(text)

    def flush(self):
        self.real.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=None,
                     help="records per target (default: 20 for --corpus=targets, "
                          "3 for --corpus=asn1c-compiler — a much larger, one-off-probe "
                          "corpus where build cost per target dominates, not record count)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--target", default=None,
                     help="only run targets whose schema path or PDU type contains this substring")
    ap.add_argument("--limit", type=int, default=None,
                     help="cap the target list to the first N (after --target filtering) — "
                          "useful for a quick sanity pass over a small slice of a large "
                          "--corpus=asn1c-compiler run before committing to the full sweep")
    ap.add_argument("--shard", default=None, metavar="K/N",
                     help="keep only build groups at index i with i mod N == K (0 <= K < N)")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--asn1c-dir", default=None,
                     help="directory containing the asn1c binary (overrides ASN1C_BIN_DIR/PATH search)")
    ap.add_argument("--no-asn1c", action="store_true",
                     help="skip the asn1c leg even if asn1c is found")
    ap.add_argument("--corpus", default="targets", choices=["targets", "asn1c-compiler"],
                     help="'targets' (default): the curated, manually-verified list in "
                          "targets.txt. 'asn1c-compiler': auto-discover a PDU-type candidate "
                          "from every *-OK.asn1 in tests/tests-asn1c-compiler/ instead (see "
                          "discover_pdu_type()) — a broad, unverified probe of the ~207-file "
                          "corpus, not a curated/gating list; failures are reported, not a "
                          "reason to treat the whole run as red (same spirit as "
                          "validate_rust_codegen.py's own --corpus=asn1c-compiler).")
    ap.add_argument("--targets-file", default=TARGETS_FILE,
                     help="target list for --corpus=targets (default: targets.txt). "
                          "targets_per_gaps.txt lists known Rust/C++ PER gaps, "
                          "expected to fail until fixed.")
    ap.add_argument("--with-asn1c", action="store_true",
                     help="with --corpus=asn1c-compiler, also build+run the asn1c leg per "
                          "target (off by default for this corpus — ~200 extra asn1c builds "
                          "is the single biggest cost multiplier for a broad probe; the "
                          "curated --corpus=targets list keeps its own auto-detect+--no-asn1c "
                          "behavior unchanged)")
    ap.add_argument("-j", "--jobs", type=int,
                     default=min(4, max(1, (os.cpu_count() or 4) // 3)),
                     help="targets to build/run in parallel (default: min(4, cpus/3)); "
                          "each worker owns one cargo target dir")
    ap.add_argument("--reuse", default="",
                     help="comma list of legs to reuse without rebuilding when their "
                          "inputs are unchanged: asn1c, cpp (keyed on schema + tool/runtime signature)")
    ap.add_argument("--java", action="store_true",
                     help="add the Java leg: BER round trip and XER matrix of every target the Java "
                          "backend emits (needs a JDK 21 javac/java on PATH); a target "
                          "with a construct the backend does not emit yet is skipped "
                          "with a note")
    ap.add_argument("--fuzz", action="store_true",
                     help="fuzz mode: feed malformed BER (randgen's BerCorruptor) and "
                          "mutated PER/XER/JER to every C++ and Rust decoder; a target "
                          "fails only on a crash (signal, abort, Rust panic, hang), a "
                          "per-record decode error is the expected outcome. Crashing "
                          "inputs are kept as testbuild/<target>/crash_*.bin. Skips the "
                          "asn1c leg and the normal comparisons. --count is records per "
                          "corrupted BER file (default 3 here).")
    ap.add_argument("--corrupt-percent", type=float, default=5.0,
                     help="--fuzz: randgen per-TLV-header corruption chance (default 5)")
    ap.add_argument("--corrupt-mode", default="",
                     help="--fuzz: randgen --corrupt-mode SPEC (default: all modes)")
    ap.add_argument("--fuzz-seeds", type=int, default=20,
                     help="--fuzz: corrupted BER files per target, seeds S..S+N-1 (default 20)")
    ap.add_argument("--mutations", type=int, default=40,
                     help="--fuzz: mutated records per PER/XER/JER decoder (default 40)")
    opts = ap.parse_args()
    if opts.fuzz and opts.count is None:
        opts.count = 3

    if opts.count is None:
        opts.count = 3 if opts.corpus == "asn1c-compiler" else 20

    if not os.path.isfile(ASNCPP_BIN):
        print(f"asn1cpp compiler not built: {ASNCPP_BIN}\nRun: cmake --build {ASN1CPP_ROOT}/build")
        sys.exit(1)

    if opts.corpus == "asn1c-compiler":
        asn1c_bin = find_asn1c(opts.asn1c_dir) if opts.with_asn1c else None
        if asn1c_bin:
            print(f"asn1c leg: ON  ({asn1c_bin})")
        else:
            print("asn1c leg: OFF (--corpus=asn1c-compiler default; pass --with-asn1c to enable)")

        module_index = build_module_index(ASN1C_COMPILER_CORPUS_DIR)
        skipped = []
        targets = []
        for name in sorted(os.listdir(ASN1C_COMPILER_CORPUS_DIR)):
            if not name.endswith("-OK.asn1"):
                continue
            path = os.path.join(ASN1C_COMPILER_CORPUS_DIR, name)
            pdu_type = discover_pdu_type(path)
            if pdu_type is None:
                skipped.append(name)
                continue
            extra = resolve_imports(path, module_index)
            if extra is None:
                skipped.append(name)
                continue
            rel = os.path.relpath(path, ASN1CPP_ROOT)
            extra_rel = [os.path.relpath(os.path.join(ASN1C_COMPILER_CORPUS_DIR, f), ASN1CPP_ROOT)
                         for f in extra]
            targets.append((rel, pdu_type, None, extra_rel, [], set()))
        print(f"auto-discovered {len(targets)} target(s) from {ASN1C_COMPILER_CORPUS_DIR} "
              f"({len(skipped)} skipped: no qualifying top-level SEQUENCE/SET/CHOICE, or IMPORTS present)")
    else:
        asn1c_bin = None if opts.no_asn1c else find_asn1c(opts.asn1c_dir)
        if asn1c_bin:
            print(f"asn1c leg: ON  ({asn1c_bin})")
        else:
            print("asn1c leg: OFF (asn1c not found — set ASN1C_BIN_DIR or --asn1c-dir to enable)")

        targets = parse_targets(opts.targets_file)

    if opts.target:
        targets = [t for t in targets if opts.target in t[0] or opts.target in t[1]]
        if not targets:
            print(f"no target matches {opts.target!r}")
            sys.exit(1)
    if opts.limit is not None:
        targets = targets[:opts.limit]
    if opts.shard:
        try:
            k, n = (int(x) for x in opts.shard.split("/"))
            if not 0 <= k < n:
                raise ValueError
        except ValueError:
            print(f"--shard: expected K/N with 0 <= K < N, got {opts.shard!r}")
            sys.exit(1)
        # Whole build groups go to one shard, so a schema is never built twice.
        keys = list(dict.fromkeys(group_key(t) for t in targets))
        mine = set(keys[k::n])
        targets = [t for t in targets if group_key(t) in mine]
        print(f"shard {k}/{n}: {len(targets)} target(s)")
        if not targets:
            sys.exit(0)

    os.makedirs(TESTBUILD, exist_ok=True)
    if opts.java:
        global java_runtime_classes
        java_runtime_classes = build_java_runtime()
        if java_runtime_classes is None:
            sys.exit(1)

    reuse = {x for x in opts.reuse.split(",") if x}
    unknown = reuse - {"asn1c", "cpp"}
    if unknown:
        print(f"--reuse: unknown leg(s) {sorted(unknown)}; valid: asn1c, cpp")
        sys.exit(1)

    jobs = max(1, min(opts.jobs, len({group_key(t) for t in targets})))
    cpus = os.cpu_count() or 4
    cpp_jobs = max(2, cpus // jobs)
    cargo_jobs = max(2, cpus // jobs)

    # Build groups: targets sharing a schema, extra files and flags are
    # built once (build_group) and run back to back on one slot.
    groups = {}
    for i, t in enumerate(targets):
        groups.setdefault(group_key(t), []).append(i)
    group_list = list(groups.values())

    # Deterministic slot assignment (greedy by rough build weight, RRC and
    # ETSI LI being the outliers), so a group lands in the same cargo target
    # dir run after run and its incremental state survives.
    def weight(members):
        schema = targets[members[0]][0].lower()
        return 8 if "rrc" in schema or "etsi" in schema else 1
    slots = [[] for _ in range(jobs)]
    load = [0] * jobs
    for g in sorted(range(len(group_list)), key=lambda g: -weight(group_list[g])):
        k = load.index(min(load))
        slots[k].append(g)
        load[k] += weight(group_list[g])
    for lst in slots:
        lst.sort()

    real_stdout = sys.stdout
    tl_out = _ThreadStdout(real_stdout)
    sys.stdout = tl_out
    outputs = [None] * len(targets)
    done = [threading.Event() for _ in targets]
    oks = [False] * len(targets)

    def wants_asn1c(t):
        return not t[2] and "@expect-errors" not in t[5] and not opts.fuzz

    def worker(slot, group_ids):
        for g in group_ids:
            members = group_list[g]
            schema_rel, _, _, extra_files, asncpp_flags, _ = targets[members[0]]
            built = None
            tl_out.tl.buf = []
            try:
                built = build_group(schema_rel, [targets[i][1] for i in members], extra_files, asncpp_flags,
                                    asn1c_bin if any(wants_asn1c(targets[i]) for i in members) else None,
                                    slot=slot, cpp_jobs=cpp_jobs, cargo_jobs=cargo_jobs, reuse=reuse)
            except Exception as e:  # keep the sweep going; the group's targets fail
                print(f"  EXCEPTION: {e!r}")
            build_log = "".join(tl_out.tl.buf)
            for n, i in enumerate(members):
                _, pdu_type, skip_asn1c_reason, extra_files, _, options = targets[i]
                tl_out.tl.buf = []
                try:
                    oks[i] = run_target(schema_rel, pdu_type, opts.count, opts.seed, opts.verbose,
                                        built, skip_asn1c_reason,
                                        extra_files=extra_files,
                                        expect_errors="@expect-errors" in options,
                                        asn1c_opaque_contents="@asn1c-opaque-contents" in options,
                                        info=asn1c_verdict(options),
                                        fuzz=opts if opts.fuzz else None)
                except Exception as e:  # keep the sweep going; report as a failed target
                    print(f"  EXCEPTION: {e!r}")
                    oks[i] = False
                block = "".join(tl_out.tl.buf)
                if n == 0 and build_log:
                    # The group's build output goes under its first target's header.
                    head_end = block.find("\n", block.find("===")) + 1
                    block = block[:head_end] + build_log + block[head_end:]
                outputs[i] = block
                tl_out.tl.buf = None
                done[i].set()

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for slot, indices in enumerate(slots):
            pool.submit(worker, slot, indices)
        # Print each target's block in original order as soon as it and
        # every earlier target have finished.
        for i in range(len(targets)):
            done[i].wait()
            real_stdout.write(outputs[i])
            real_stdout.flush()
    sys.stdout = real_stdout

    results = [(t[0], t[1], oks[i]) for i, t in enumerate(targets)]

    print("\n=== Summary ===")
    failed = 0
    for schema_rel, pdu_type, ok in results:
        status = "OK" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"  [{status}] {schema_rel} :: {pdu_type}")
    print(f"\n{len(results) - failed}/{len(results)} targets passed")
    if opts.java:
        print(f"java leg: ran on {len(java_ran)} target(s), skipped on {len(java_skipped)}")
    # --corpus=asn1c-compiler is a broad, unverified probe (--corpus help
    # text's own words) — a failure there is a finding to report, same as
    # validate_rust_codegen.py's own --corpus=asn1c-compiler treats a
    # non-crash "reject" as informational, not a reason to fail the run.
    # The curated --corpus=targets list is unaffected: every one of its
    # entries was hand-verified to pass, so a failure there is a real
    # regression and keeps gating as before.
    if opts.corpus == "asn1c-compiler":
        sys.exit(0)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
