#!/usr/bin/env python3
"""Cross-language descriptor-table diff.

Every backend must emit the same descriptor tables (same rows, same values)
in its own language's syntax (doc/backend-guide.md). This tool proves it:
for each schema it runs the compiler once per target language, builds a
tiny harness that asks that language's runtime to dump every generated
type's tables in the canonical JSON format (backend guide, Appendix A), and
diffs each language's dump against C++ (the reference) field by field.

A field one runtime's tables do not carry is absent from its dump; it is
counted as "not carried", never as a mismatch. Tagging NONE and IMPLICIT
with the same tag frame a member identically on the wire and compare equal.

Schemas come from targets.txt next to this script: the schemas every
compared backend covers today, kept small so a run takes minutes. As a
backend's coverage grows, move schemas from ../xval_sweep/targets.txt into
it. --full runs the whole xval list (including the large real-world
schemas). The PDU column is ignored: every generated type is dumped.

A schema whose inputs (schema files, flags, compiler, runtime sources) are
unchanged since the last run reuses that run's dump; --rebuild forces a
fresh build.

Usage:
    table_diff.py [--lang cpp,rust] [--full] [--target SUBSTR] [-j N] [-v] [--not-carried] [--rebuild]

Exit code: 0 = no mismatch, 1 = mismatch or build failure.
"""
import argparse
import concurrent.futures
import fnmatch
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
COMPILER = os.path.join(ROOT, "build", "compiler", "asn1cpp")
RUNTIME_INC = os.path.join(ROOT, "runtime", "include")
RUNTIME_LIB = os.path.join(ROOT, "build", "runtime", "libasn1cpp_runtime.a")
WIRE_CRATE = os.path.join(ROOT, "rust-runtime", "wire")
TESTBUILD = os.path.join(HERE, "testbuild")
TARGETS = os.path.join(HERE, "targets.txt")
FULL_TARGETS = os.path.join(ROOT, "validation-tools", "xval_sweep", "targets.txt")
CPP_JOBS = os.cpu_count() or 4  # per schema; main() divides it by -j
KNOWN = os.path.join(HERE, "known_diffs.txt")

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(ROOT, "validation-tools", "xval_sweep"))
from xval_sweep import parse_targets  # noqa: E402


def run(cmd, cwd=None, env=None):
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} ... failed (rc={r.returncode}):\n{(r.stderr or r.stdout)[-3000:]}")
    return r.stdout


def schema_files(schema):
    path = os.path.join(ROOT, schema)
    if os.path.isdir(path):
        return sorted(os.path.join(d, n) for d, _, ns in os.walk(path) for n in ns if n.endswith((".asn", ".asn1")))
    return [path]


def generate(files, flags, lang, out):
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    run([COMPILER, f"--target={lang}", *flags, *files, "-o", out])


# ---------------------------------------------------------------------------
# C++ leg: one main() that calls asn1::dump_tables on every descriptor.

CPP_MEMBER_DEF = re.compile(r"^\s*static const asn1::TypeDescriptor asn_DEF;", re.M)
CPP_FREE_DEF = re.compile(r"^extern const asn1::TypeDescriptor (asn_DEF_\w+);", re.M)
CPP_CLASS = re.compile(r"^(?:class|struct) (\w+)\b(?![^\n]*;\s*$)", re.M)  # definitions, not forward declarations


def dump_cpp(work, files, flags):
    gen = os.path.join(work, "gen")
    generate(files, flags, "cpp", gen)
    refs, includes = [], []
    for hpp in sorted(glob.glob(os.path.join(gen, "*.hpp"))):
        text = open(hpp).read()
        found = [(m.group(1)[len("asn_DEF_"):], m.group(1)) for m in CPP_FREE_DEF.finditer(text)]
        if CPP_MEMBER_DEF.search(text):
            stem = os.path.splitext(os.path.basename(hpp))[0]
            classes = CPP_CLASS.findall(text)
            cls = stem if stem in classes else classes[0]
            found.append((cls, f"{cls}::asn_DEF"))
        if found:
            includes.append(os.path.basename(hpp))
            refs.extend(found)
    main = os.path.join(work, "dump_main.cpp")
    with open(main, "w") as f:
        f.write("#include <iostream>\n#include <asn1cpp/asn1cpp.hpp>\n")
        f.writelines(f'#include "{h}"\n' for h in includes)
        f.write("int main() {\n")
        f.writelines(f'    std::cout << "{ident}\\t"; asn1::dump_tables({ref}, std::cout);\n' for ident, ref in refs)
        f.write("    return 0;\n}\n")
    exe = os.path.join(work, "dump_cpp")
    gen_srcs = sorted(glob.glob(os.path.join(gen, "*.cpp")))
    # Unity build: each generated file is a few lines of tables behind the
    # same runtime headers, so parsing the headers dominates. One unity file
    # per core parses them once per core instead of once per type.
    units = []
    for k in range(min(CPP_JOBS, len(gen_srcs))):
        unit = os.path.join(work, f"unity_{k}.cpp")
        with open(unit, "w") as f:
            f.writelines(f'#include "{src}"\n' for src in gen_srcs[k::CPP_JOBS])
        units.append(unit)
    try:
        cpp_build(work, exe, units + [main])
    except RuntimeError:
        # A clash between file-local names of two generated files: build
        # the files one by one instead.
        cpp_build(work, exe, gen_srcs + [main])
    return run([exe])


def cpp_build(work, exe, srcs):
    objs = [os.path.splitext(x)[0] + ".o" for x in srcs]
    with open(os.path.join(work, "Makefile"), "w") as f:
        f.write(f"CXXFLAGS := -std=c++20 -O0 -w -I{os.path.join(work, 'gen')} -I{RUNTIME_INC}\n")
        f.write(f"{exe}: {' '.join(objs)}\n\tg++ $^ {RUNTIME_LIB} -o $@\n")
        f.write("%.o: %.cpp\n\tg++ $(CXXFLAGS) -c $< -o $@\n")
    run(["make", "-s", f"-j{CPP_JOBS}", "-C", work])


# ---------------------------------------------------------------------------
# Rust leg: the generated lib.rs is the crate root; a bin calls
# asn1cpp_wire::spec::dump::dump_tables::<M::M> for every module M.

RUST_MOD = re.compile(r'^#\[path = "([^"]+)\.rs"\] pub mod (\w+);', re.M)
RUST_TYPE = re.compile(r"^impl asn1cpp_wire::spec::object::AsMemberRef for (\w+)", re.M)


def dump_rust(work, files, flags, slot):
    gen = os.path.join(work, "gen")
    generate(files, flags, "rust", gen)
    mods = RUST_MOD.findall(open(os.path.join(gen, "lib.rs")).read())
    with open(os.path.join(work, "Cargo.toml"), "w") as f:
        f.write('[package]\nname = "table-dump"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
                '[lib]\nname = "gen"\npath = "gen/lib.rs"\n\n[[bin]]\nname = "dump"\npath = "dump.rs"\n\n'
                f'[dependencies]\nasn1cpp-wire = {{ path = "{WIRE_CRATE}" }}\n\n[workspace]\n')
    with open(os.path.join(work, "dump.rs"), "w") as f:
        f.write("fn main() {\n")
        # A long name is shortened with a hash in the module name, so take
        # each type's identifier from the module's own reflective impl.
        for fname, mod in mods:
            for ty in RUST_TYPE.findall(open(os.path.join(gen, fname + ".rs")).read()):
                f.write(f'    println!("{ty}\\t{{}}", asn1cpp_wire::spec::dump::dump_tables::<gen::{mod}::{ty}>("{ty}"));\n')
        f.write("}\n")
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(TESTBUILD, "_cargo", f"slot{slot}"), RUSTFLAGS="-A warnings")
    run(["cargo", "build", "--quiet", "--bin", "dump"], cwd=work, env=env)
    return run([os.path.join(env["CARGO_TARGET_DIR"], "debug", "dump")])


DUMPERS = {"cpp": dump_cpp, "rust": dump_rust}

# What a language's dump depends on besides the schema and the compiler.
RUNTIME_INPUTS = {
    "cpp": [os.path.join(ROOT, "runtime"), RUNTIME_LIB],
    "rust": [os.path.join(WIRE_CRATE, "src"), os.path.join(WIRE_CRATE, "Cargo.toml")],
}


def input_key(lang, files, flags):
    """Fingerprint of everything a dump depends on: schema content, flags,
    and the size and mtime of the compiler and the runtime's sources."""
    h = hashlib.sha256(" ".join(flags).encode())
    for f in files:
        h.update(open(f, "rb").read())
    for path in [COMPILER, os.path.abspath(__file__), *RUNTIME_INPUTS[lang]]:
        paths = [path] if os.path.isfile(path) else sorted(
            os.path.join(d, n) for d, _, ns in os.walk(path) for n in ns)
        for p in paths:
            st = os.stat(p)
            h.update(f"{p}:{st.st_size}:{st.st_mtime_ns}".encode())
    return h.hexdigest()


def dump_with_reuse(lang, work, files, flags, slot, rebuild):
    key = input_key(lang, files, flags)
    key_path, dump_path = os.path.join(work, "input.key"), os.path.join(work, "dump.jsonl")
    if not rebuild and os.path.exists(dump_path) and os.path.exists(key_path) and open(key_path).read() == key:
        return open(dump_path).read(), True
    if os.path.exists(key_path):
        os.remove(key_path)
    text = DUMPERS[lang](work, files, flags) if lang == "cpp" else DUMPERS[lang](work, files, flags, slot)
    open(dump_path, "w").write(text)
    open(key_path, "w").write(key)
    return text, False


# ---------------------------------------------------------------------------
# Comparison

def key_of(name):
    return name.replace("-", "_")


def tagging_equal(a, b):
    """NONE and IMPLICIT with the same tag frame a row identically (the tag
    replaces itself); everything else must match exactly."""
    if not isinstance(a, dict) or not isinstance(b, dict) or "tagging" not in a or "tagging" not in b:
        return False
    pair = {a["tagging"], b["tagging"]}
    return pair == {"NONE", "IMPLICIT"} and a.get("tag") == b.get("tag")


def compare(ref, other, path, diffs, not_carried, counts):
    if isinstance(ref, dict) and isinstance(other, dict):
        for k in ref:
            if k not in other:
                not_carried.add(re.sub(r"\[\d+\]", "[]", f"{path}.{k}"))
                continue
            if k == "name" and "." not in path and key_of(ref[k]) == key_of(other[k]):
                counts[0] += 1
                continue
            if k == "tagging" and ref[k] != other[k] and tagging_equal(ref, other):
                counts[0] += 1
                continue
            compare(ref[k], other[k], f"{path}.{k}", diffs, not_carried, counts)
        return
    if isinstance(ref, list) and isinstance(other, list):
        if len(ref) != len(other):
            diffs.append(f"{path}: length {len(ref)} vs {len(other)}")
            return
        for i, (a, b) in enumerate(zip(ref, other)):
            compare(a, b, f"{path}[{i}]", diffs, not_carried, counts)
        return
    counts[0] += 1
    if ref != other:
        diffs.append(f"{path}: {json.dumps(ref)} vs {json.dumps(other)}")


def load_known(path):
    """Already-filed divergences: "<lang> <field-path glob> <reason...>" per line.
    '[' and ']' in a glob are literal (list indices), '*' matches anything."""
    known = []
    if os.path.exists(path):
        for line in open(path):
            # The glob may contain ": a vs b" (spaces); a tab or two spaces
            # end it.
            parts = [x for x in re.split(r"\t|\s{2,}", line.strip(), maxsplit=2) if x]
            if parts and not parts[0].startswith("#") and len(parts) >= 2:
                glob_ = "".join({"[": "[[]", "]": "[]]"}.get(c, c) for c in parts[1])
                known.append((parts[0], parts[1], glob_, parts[2].strip() if len(parts) > 2 else ""))
    return known


def known_reason(known, lang, diff):
    """A glob without ': ' matches the field path; one with ': ' matches the
    whole "path: ref vs other" line, so an entry can name the values too."""
    field = diff.split(":", 1)[0]
    for k_lang, raw, glob_, reason in known:
        if k_lang == lang and fnmatch.fnmatchcase(diff if ": " in raw else field, glob_):
            return f"{raw} ({reason})" if reason else raw
    return None


def parse_dump(text):
    """Harness output is "<generated identifier>\t<json>" per type, keyed by
    the identifier: descriptor names are XER names, which anonymous inner
    types share (X.693 §12)."""
    out = {}
    for line in text.splitlines():
        if line.strip():
            ident, _, js = line.partition("\t")
            out[key_of(ident)] = json.loads(js)
    return out


def check_schema(job):
    idx, schema, flags, langs, rebuild = job
    work_root = os.path.join(TESTBUILD, re.sub(r"[^\w.-]", "_", schema))
    files = schema_files(schema)
    dumps, errors, reused = {}, [], []
    for lang in langs:
        work = os.path.join(work_root, lang)
        os.makedirs(work, exist_ok=True)
        try:
            text, was_reused = dump_with_reuse(lang, work, files, flags, idx, rebuild)
            dumps[lang] = parse_dump(text)
            if was_reused:
                reused.append(lang)
        except Exception as e:  # build or run failure is a result, not a crash
            errors.append(f"{lang}: {e}")
    results = []
    if errors:
        return schema, errors, results, reused
    ref = dumps[langs[0]]
    for lang in langs[1:]:
        other = dumps[lang]
        diffs, not_carried, counts = [], set(), [0]
        missing = sorted(set(ref) - set(other))
        extra = sorted(set(other) - set(ref))
        for name in sorted(set(ref) & set(other)):
            compare(ref[name], other[name], name, diffs, not_carried, counts)
        results.append((lang, len(ref), counts[0], diffs, missing, extra, not_carried))
    return schema, errors, results, reused


def say(*a):
    print(*a, flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lang", default="cpp,rust", help="comma list; the first is the reference (default cpp,rust)")
    ap.add_argument("--target", help="only schemas whose path contains this substring")
    ap.add_argument("-j", type=int, default=4)
    ap.add_argument("-v", "--verbose", action="store_true", help="print every differing field")
    ap.add_argument("--not-carried", action="store_true", help="list fields a runtime does not carry")
    ap.add_argument("--full", action="store_true", help="run every schema in xval_sweep/targets.txt")
    ap.add_argument("--targets-file", help="target list (default: targets.txt here; --full: xval_sweep/targets.txt)")
    ap.add_argument("--rebuild", action="store_true", help="rebuild every dump, even when its inputs are unchanged")
    ap.add_argument("--known", default=KNOWN, help="known-divergence list (default: known_diffs.txt)")
    args = ap.parse_args()
    known = load_known(args.known)
    # Schemas build in parallel; split the cores between them so a run never
    # starts more compilers than there are cores (a unity unit of a large
    # schema needs a few GB).
    global CPP_JOBS
    CPP_JOBS = max(1, (os.cpu_count() or 4) // args.j)
    langs = args.lang.split(",")
    unknown = [l for l in langs if l not in DUMPERS]
    if unknown or len(langs) < 2:
        ap.error(f"--lang needs two or more of {sorted(DUMPERS)}")

    seen, jobs = set(), []
    targets_file = args.targets_file or (FULL_TARGETS if args.full else TARGETS)
    for schema, _pdu, _reason, _extra, flags, options in parse_targets(targets_file):
        if "@expect-errors" in options or schema in seen:
            continue
        if args.target and args.target not in schema:
            continue
        seen.add(schema)
        jobs.append((len(jobs) % args.j, schema, flags, langs, args.rebuild))

    failed = 0
    all_not_carried = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.j) as ex:
        # Report each schema as it finishes: a large schema must not hold back
        # the results of the small ones submitted after it.
        for fut in concurrent.futures.as_completed([ex.submit(check_schema, j) for j in jobs]):
            schema, errors, results, reused = fut.result()
            if errors:
                failed += 1
                say(f"  [FAIL] {schema}: build/run error")
                for e in errors:
                    say("         " + e.replace("\n", "\n         ")[:2000])
                continue
            for lang, ntypes, nfields, diffs, missing, extra, not_carried in results:
                all_not_carried.setdefault(lang, set()).update(not_carried)
                known_hits = sorted({r for d in diffs if (r := known_reason(known, lang, d))})
                diffs = [d for d in diffs if not known_reason(known, lang, d)]
                bad = diffs or missing or extra
                failed += bool(bad)
                say(f"  [{'DIFF' if bad else 'OK'}] {schema} :: {langs[0]} vs {lang}: {ntypes} types, "
                    f"{nfields} fields compared, {len(diffs)} differ, {len(not_carried)} not carried"
                    + (f" (reused {'+'.join(reused)})" if reused else ""))
                for r in known_hits:
                    say(f"         known: {r}")
                if missing:
                    say(f"         types missing in {lang}: {', '.join(missing)}")
                if extra:
                    say(f"         types only in {lang}: {', '.join(extra)}")
                for d in diffs[: None if args.verbose else 10]:
                    say(f"         {d}")
                if len(diffs) > 10 and not args.verbose:
                    say(f"         ... {len(diffs) - 10} more (-v)")
    if args.not_carried:
        for lang, fields in all_not_carried.items():
            say(f"\nNot carried by {lang} ({len(fields)} field paths):")
            for f in sorted({re.sub(r"^[^.]*", "<type>", p) for p in fields}):
                say(f"  {f}")
    say(f"\n{len(jobs) - failed}/{len(jobs)} schemas match")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
