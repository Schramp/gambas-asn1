#!/usr/bin/env python3
r"""Build the BER framing vectors: concatenated records in *.ber files plus
framing.vectors, the expected frames and result of reading each file.

    make_framing_vectors.py            # *.ber + framing.vectors
    make_framing_vectors.py --records  # first re-encode records/*.der (needs asn1c)

Valid records come from asn1c: records/*.der (framing.asn1 values encoded
by asn1c through ../vectors/make_ber_vectors.py) and the indefinite-length
records of asn1c's own test suite (../tests-c-compiler/data-62, the files
asn1c decodes, never a -B one). Malformed input is built here from those
records, since asn1c cannot produce a framing fault.

The expected results follow from how each file is put together (record
lengths and the position of the fault), not from parsing the files.

framing.vectors has one tab-separated line per file:

    file  max_frame  frames  result

max_frame is `-` for the default limit (64 MiB) or a number of octets;
frames is `-` or a comma list of offset+length; result is `end`, or
`error REASON OFFSET` with OFFSET an absolute octet offset.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DATA62 = os.path.join(HERE, "..", "tests-c-compiler", "data-62")


def hexdata(n):
    return "".join(f"{i % 256:02X}" for i in range(n))


RECORDS_XER = [
    ("short", "Rec", "<Rec><id>1</id><data>68656C6C6F</data></Rec>"),
    ("long81", "Rec", f"<Rec><id>2</id><data>{hexdata(200)}</data></Rec>"),
    ("long82", "Rec", f"<Rec><id>3</id><data>{hexdata(300)}</data></Rec>"),
    ("long83", "Rec", f"<Rec><id>4</id><data>{hexdata(65536)}</data></Rec>"),
    ("high", "High", "<High><id>5</id></High>"),
]

# data-62 records asn1c decodes: definite, indefinite, nested indefinite,
# high tag number.
DATA62_RECORDS = ["01", "24-L", "29-L", "30-L", "31-D", "32"]


def make_records():
    os.makedirs(os.path.join(HERE, "records"), exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        xer = os.path.join(work, "records.xer")
        out = os.path.join(work, "records.vectors")
        with open(xer, "w") as f:
            for _, ty, value in RECORDS_XER:
                f.write(f"{ty}\t{value}\n")
        subprocess.run([sys.executable, os.path.join(HERE, "..", "vectors", "make_ber_vectors.py"),
                        os.path.join(HERE, "framing.asn1"), xer, out], check=True)
        rows = [l.split("\t") for l in open(out) if l.strip() and not l.startswith("#")]
    for (name, _, _), row in zip(RECORDS_XER, rows):
        with open(os.path.join(HERE, "records", f"{name}.der"), "wb") as f:
            f.write(bytes.fromhex(row[2]))


def load_records():
    rec = {}
    for name, _, _ in RECORDS_XER:
        path = os.path.join(HERE, "records", f"{name}.der")
        if not os.path.exists(path):
            sys.exit(f"{path} missing: run with --records")
        with open(path, "rb") as f:
            rec[name] = f.read()
    for name in DATA62_RECORDS:
        with open(os.path.join(DATA62, f"data-62-{name}.ber"), "rb") as f:
            rec[f"d62-{name}"] = f.read()
    return rec


def check_single_record(name, data):
    """A data-62 file must be exactly one record; checked with a minimal
    walk so the construction below can use the file size as its length."""
    def header(pos):
        tag_start = pos
        first = data[pos]
        pos += 1
        if first & 0x1F == 0x1F:
            while data[pos] & 0x80:
                pos += 1
            pos += 1
        n = data[pos]
        pos += 1
        if n == 0x80:
            return tag_start, pos, None, bool(first & 0x20)
        if n & 0x80:
            length = int.from_bytes(data[pos:pos + (n & 0x7F)], "big")
            pos += n & 0x7F
        else:
            length = n
        return tag_start, pos, length, bool(first & 0x20)

    def skip(pos):
        _, pos, length, _ = header(pos)
        if length is not None:
            return pos + length
        while data[pos:pos + 2] != b"\0\0":
            pos = skip(pos)
        return pos + 2

    if skip(0) != len(data):
        sys.exit(f"{name} is not exactly one BER record")


def build(rec):
    vectors = []

    def add(fname, parts, result, max_frame=None):
        """parts: ("rec", bytes) for a complete record, ("raw", bytes) for
        trailing input that is not one; result: "end", or (reason, offset)
        with offset None meaning the end of the file."""
        data = b""
        frames = []
        for kind, b in parts:
            if kind == "rec":
                frames.append(f"{len(data)}+{len(b)}")
            data += b
        with open(os.path.join(HERE, fname), "wb") as f:
            f.write(data)
        if result == "end":
            res = "end"
        else:
            reason, offset = result
            res = f"error {reason} {len(data) if offset is None else offset}"
        vectors.append((fname, "-" if max_frame is None else str(max_frame),
                        ",".join(frames) or "-", res))

    R = lambda name: ("rec", rec[name])
    raw = lambda hexstr: ("raw", bytes.fromhex(hexstr))
    short = rec["short"]

    add("empty.ber", [], "end")
    add("single.ber", [R("short")], "end")
    add("long_forms.ber", [R("short"), R("long81"), R("long82"), R("long83")], "end")
    add("high_tag.ber", [R("high"), R("d62-32"), R("high")], "end")
    add("indefinite.ber", [R("d62-24-L"), R("d62-29-L"), R("d62-30-L"), R("d62-31-D")], "end")
    add("mixed.ber", [R("d62-01"), R("long81"), R("d62-24-L"), R("high"), R("d62-30-L"), R("short")], "end")
    # Non-minimal long form (allowed in BER, X.690 §8.1.3.5 note 2), an
    # empty indefinite-length record, and end-of-contents octets at the top
    # level, which the framer takes as a record like any other TLV.
    add("forms.ber", [("rec", bytes.fromhex("3081050201050400")), ("rec", bytes.fromhex("30800000")),
                      R("short"), ("rec", b"\0\0"), ("rec", b"\0\0")], "end")
    # Nesting: 256 indefinite levels are allowed, a 257th is not.
    add("depth_256.ber", [("rec", bytes.fromhex("3080" * 256 + "0000" * 256))], "end")
    add("too_deep.ber", [raw("3080" * 257 + "0000" * 257)], ("too-deep", 2 * 256))

    add("trunc_tag.ber", [R("short"), raw("30")], ("truncated", None))
    add("trunc_high_tag.ber", [R("short"), raw("BF82")], ("truncated", None))
    add("trunc_length.ber", [R("short"), raw("308201")], ("truncated", None))
    add("trunc_content.ber", [R("short"), ("raw", rec["long81"][:-1])], ("truncated", None))
    add("trunc_indefinite.ber", [R("short"), ("raw", rec["d62-29-L"][:-2])], ("truncated", None))
    add("trunc_nested_header.ber", [("raw", rec["d62-24-L"][:5])], ("truncated", None))

    add("indef_primitive.ber", [R("short"), raw("04800000")], ("indefinite-primitive", len(short) + 1))
    add("indef_primitive_nested.ber", [raw("308004800000" + "0000")], ("indefinite-primitive", 3))
    add("length_field.ber", [R("short"), raw("3089" + "01" * 9)], ("length-field-too-long", len(short) + 1))
    add("length_ff.ber", [raw("30FF")], ("length-field-too-long", 1))
    add("tag_too_long.ber", [R("short"), raw("BF818181818101" + "00")], ("tag-too-long", len(short)))
    add("tag_too_large.ber", [raw("BF8FFFFFFF7F00")], ("tag-too-long", 0))

    add("too_large.ber", [R("short"), raw("04847FFFFFFF")], ("frame-too-large", len(short)))
    add("limit.ber", [R("short"), ("raw", rec["long82"])], ("frame-too-large", len(short)), max_frame=300)
    add("limit_exact.ber", [R("long82")], "end", max_frame=len(rec["long82"]))
    add("limit_indefinite.ber", [R("short"), ("raw", rec["d62-29-L"])], ("frame-too-large", len(short)), max_frame=16)

    with open(os.path.join(HERE, "framing.vectors"), "w") as f:
        f.write("# Generated by make_framing_vectors.py; do not edit.\n")
        f.write("# file\tmax_frame\tframes\tresult\n")
        for v in vectors:
            f.write("\t".join(v) + "\n")


def main():
    if "--records" in sys.argv[1:]:
        make_records()
    rec = load_records()
    for name in DATA62_RECORDS:
        check_single_record(name, rec[f"d62-{name}"])
    build(rec)


if __name__ == "__main__":
    main()
