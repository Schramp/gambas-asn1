package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.DecodeOptions;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.ByteSource;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.Nesting;
import io.github.schramp.gambasasn1.wire.spec.Positions;

/**
 * BER input: reads one TLV at a time from a {@link ByteSource}. Every
 * malformed input ends in a {@link DecodeException}. The reader also
 * carries the constructed nesting depth of the decode using it
 * ({@link Nesting}), its {@link DecodeOptions} and, when the decode
 * records them, where its bytes sit in the decode's input ({@link Positions}).
 */
public final class BerReader {
    private final ByteSource src;
    private int depth;
    private DecodeOptions options = DecodeOptions.DEFAULT;
    private Positions positions;
    // Absolute bit of local offset 0, for a reader over a copy of input bytes.
    private long baseBits;
    // A reader over SET components copied into table order: piece i starts
    // at local offset pieceLocal[i] and came from absolute bit pieceAbs[i].
    private int[] pieceLocal;
    private long[] pieceAbs;

    public BerReader(ByteSource src) {
        this.src = src;
    }

    /** A reader over a nested value's bytes, at this reader's depth and with its settings. */
    public BerReader nested(ByteSource contents) {
        BerReader r = new BerReader(contents);
        r.depth = depth;
        r.options = options;
        r.positions = positions;
        r.baseBits = baseBits;
        r.pieceLocal = pieceLocal;
        r.pieceAbs = pieceAbs;
        return r;
    }

    /** Contained-value settings of this decode; null means the defaults. */
    public ContainedOptions contained() {
        return options.contained();
    }

    /** Sets the contained-value settings; returns this reader. */
    public BerReader withContained(ContainedOptions c) {
        options = options.withContained(c);
        return this;
    }

    /** The decoder settings of this decode. */
    public DecodeOptions options() {
        return options;
    }

    /** Sets the decoder settings, contained-value settings included; null for the defaults. Returns this reader. */
    public BerReader withOptions(DecodeOptions o) {
        options = DecodeOptions.orDefault(o);
        return this;
    }

    /**
     * {@link #nested(ByteSource)} over a copy of the given bytes. Their place
     * in the input is unknown, so the reader records no positions.
     */
    public BerReader nested(byte[] contents) {
        BerReader r = nested(new ByteSource(contents));
        r.positions = null;
        r.pieceLocal = null;
        r.pieceAbs = null;
        return r;
    }

    /** {@link #nested(byte[])} over bytes that start at absolute bit {@code absBit} of the input. */
    public BerReader nestedAt(byte[] contents, long absBit) {
        BerReader r = nested(contents);
        r.positions = positions;
        r.baseBits = absBit;
        return r;
    }

    /**
     * {@link #nested(byte[])} over pieces of the input copied back to back:
     * piece i starts at local offset {@code local[i]} and came from absolute
     * bit {@code abs[i]}.
     */
    public BerReader nestedPieces(byte[] contents, int[] local, long[] abs) {
        BerReader r = nested(contents);
        r.positions = positions;
        r.pieceLocal = local;
        r.pieceAbs = abs;
        return r;
    }

    /** The positions this decode records into, or null when it records none. */
    public Positions positions() {
        return positions;
    }

    /** Records positions of the nodes decoded through this reader into {@code p}; returns this reader. */
    public BerReader withPositions(Positions p) {
        positions = p;
        return this;
    }

    /** Absolute bit, in the decode's input, of local offset {@code local} of this reader's bytes. */
    public long absoluteBit(int local) {
        if (pieceLocal == null) {
            return baseBits + 8L * local;
        }
        int i = pieceLocal.length - 1;
        while (i > 0 && pieceLocal[i] > local) {
            i--;
        }
        return pieceAbs[i] + 8L * (local - pieceLocal[i]);
    }

    /**
     * Absolute bit just after the octet before local offset {@code local}:
     * the end of a value that finishes there. Differs from
     * {@link #absoluteBit} where a SET's components were reordered, since the
     * next octet can then come from a different place in the input.
     */
    public long absoluteEndBit(int local) {
        return local == 0 ? absoluteBit(0) : absoluteBit(local - 1) + 8;
    }

    /** Records that {@code node} starts at the reader's current position, when positions are recorded. */
    public void markStart(Object node) {
        if (positions != null) {
            positions.record(node, absoluteBit(src.position()));
        }
    }

    /**
     * Absolute bits of local octets {@code from} up to {@code to}
     * (exclusive), as {start, end}.
     */
    private long[] span(int from, int to) {
        long a = absoluteBit(from);
        return new long[] {a, to == from ? a : absoluteEndBit(to)};
    }

    /** Records local octets {@code from} up to {@code to} as the contents of {@code node} (its value too, unless recorded apart). */
    public void markContents(Object node, int from, int to) {
        if (positions != null) {
            long[] s = span(from, to);
            positions.recordContents(node, s[0], s[1]);
        }
    }

    /** Records local octets {@code from} up to {@code to} as the value of {@code node}. */
    public void markValue(Object node, int from, int to) {
        if (positions != null) {
            long[] s = span(from, to);
            positions.recordValue(node, s[0], s[1]);
        }
    }

    /** Records that {@code node} ends at the reader's current position, when positions are recorded. */
    public void markEnd(Object node) {
        if (positions != null) {
            positions.recordEnd(node, absoluteEndBit(src.position()));
        }
    }

    /**
     * Enters one constructed nesting level.
     *
     * @throws DecodeException when the decode is already
     *         {@link Nesting#MAX_DECODE_DEPTH} levels deep
     */
    public void enterLevel() throws DecodeException {
        if (depth >= Nesting.MAX_DECODE_DEPTH) {
            throw new DecodeException(Nesting.tooDeep(), position());
        }
        depth++;
    }

    /** The constructed levels this decode is inside. */
    public int depth() {
        return depth;
    }

    /** Leaves the level the matching {@link #enterLevel()} entered. */
    public void leaveLevel() {
        depth--;
    }

    public BerReader(byte[] data) {
        this(new ByteSource(data));
    }

    public ByteSource source() {
        return src;
    }

    public boolean atEnd() {
        return src.atEnd();
    }

    public int position() {
        return src.position();
    }

    /** The next tag without consuming it, or null when none can be read. */
    public Tag peekTag() {
        if (src.atEnd()) {
            return null;
        }
        int first = src.peek();
        TagClass cls = TagClass.fromBits(first >> 6);
        boolean constructed = (first & 0x20) != 0;
        int n = first & 0x1F;
        if (n != 0x1F) {
            return new Tag(cls, n, constructed);
        }
        long number = 0;
        for (int i = 1; i <= 5; i++) {
            int b = src.peek(i);
            if (b < 0) {
                return null;
            }
            number = (number << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                return number <= Integer.MAX_VALUE ? new Tag(cls, (int) number, constructed) : null;
            }
        }
        return null;
    }

    /** Identifier octets (X.690 §8.1.2). Tag numbers above 2^31-1 are rejected. */
    public Tag readTag() throws DecodeException {
        int start = src.position();
        Tag t = peekTag();
        if (t == null) {
            throw new DecodeException("truncated or oversized tag", start);
        }
        src.skip(t.number() < 31 ? 1 : 1 + (32 - Integer.numberOfLeadingZeros(t.number()) + 6) / 7, "tag");
        return t;
    }

    /**
     * One TLV (X.690 §8.1). An indefinite length (X.690 §8.1.3.6) is allowed
     * only on a constructed encoding; its contents end at the matching
     * end-of-contents octets.
     */
    public Tlv readTlv() throws DecodeException {
        Tag tag = readTag();
        int lenPos = src.position();
        int len = readLength();
        if (len >= 0) {
            return new Tlv(tag, src.sub(len, "contents"));
        }
        if (!tag.constructed()) {
            throw new DecodeException("indefinite-length encoding on primitive type", lenPos);
        }
        int start = src.position();
        int depth = 1;
        while (depth > 0) {
            if (src.remaining() < 2) {
                throw new DecodeException("unterminated indefinite-length encoding", src.position());
            }
            if (src.peek() == 0 && src.peek(1) == 0) {
                src.skip(2, "end-of-contents");
                depth--;
                continue;
            }
            Tag inner = readTag();
            int innerLenPos = src.position();
            int innerLen = readLength();
            if (innerLen >= 0) {
                src.skip(innerLen, "nested value");
            } else if (inner.constructed()) {
                depth++;
            } else {
                throw new DecodeException("indefinite-length encoding on primitive type", innerLenPos);
            }
        }
        int end = src.position() - 2;
        return new Tlv(tag, src.window(start, end));
    }

    /**
     * Checks that {@code bytes}, the octets of an ANY value, are zero or
     * more complete BER encodings (X.690 §8.1); their types are not known,
     * so their values are not decoded. Mirrors C++ {@code check_any_tlvs}
     * ({@code BerCodec.cpp}) and Rust {@code check_any_contents}.
     *
     * @throws DecodeException {@code malformed ANY contents: <reason>}, at
     *         the offset in {@code bytes} of the first malformed TLV
     */
    public static void checkAnyContents(byte[] bytes) throws DecodeException {
        BerReader r = new BerReader(bytes);
        try {
            while (!r.atEnd()) {
                r.checkAnyTlv(0, true);
            }
        } catch (DecodeException e) {
            throw new DecodeException("malformed ANY contents: " + e.getMessage(), e.position());
        }
    }

    /**
     * One TLV of an ANY value: a constructed one's contents are themselves
     * complete encodings (X.690 §3.2), and an indefinite length is closed by
     * its end-of-contents octets (§8.1.3.6, §8.1.5). Tag 0 is otherwise
     * refused, except an exact {@code 00 00} in a definite-length frame,
     * which asn1c keeps as legacy ANY bytes ({@code octet_string_ber_read_child}).
     *
     * @param depth    nesting level inside the ANY, limited to {@link Nesting#MAX_DECODE_DEPTH}
     * @param definite true when the enclosing frame has a definite length
     */
    private void checkAnyTlv(int depth, boolean definite) throws DecodeException {
        if (depth > Nesting.MAX_DECODE_DEPTH) {
            throw new DecodeException("ANY contents nest deeper than " + Nesting.MAX_DECODE_DEPTH + " levels",
                    src.position());
        }
        if (definite && src.peek() == 0 && src.peek(1) == 0) {
            src.skip(2, "zero octets");
            return;
        }
        Tag tag = readTag();
        if (tag.tagClass() == TagClass.UNIVERSAL && tag.number() == 0) {
            throw new DecodeException("end-of-contents octets outside an indefinite-length encoding", src.position());
        }
        int lenPos = src.position();
        int len = readLength();
        if (len >= 0) {
            ByteSource contents = src.sub(len, "contents");
            if (tag.constructed()) {
                BerReader inner = new BerReader(contents);
                while (!inner.atEnd()) {
                    inner.checkAnyTlv(depth + 1, true);
                }
            }
            return;
        }
        if (!tag.constructed()) {
            throw new DecodeException("indefinite-length encoding on primitive type", lenPos);
        }
        for (;;) {
            if (src.remaining() < 2) {
                throw new DecodeException("unterminated indefinite-length encoding", src.position());
            }
            if (src.peek() == 0 && src.peek(1) == 0) {
                src.skip(2, "end-of-contents");
                return;
            }
            checkAnyTlv(depth + 1, false);
        }
    }

    /**
     * Joins the segments of a constructed BIT STRING, OCTET STRING or
     * character string: {@code contents} (the constructed contents, for an
     * indefinite length without the end-of-contents octets) holds primitive
     * or nested constructed encodings with the universal tag
     * {@code universal}, concatenated in order (X.690 §8.6.4, §8.7.3,
     * §8.23.3). Mirrors C++ {@code join_segments} ({@code BerCodec.cpp}) and
     * Rust {@code join_segments}, with the same errors.
     *
     * @param universal 3 for BIT STRING segments, 4 for OCTET STRING segments
     *                  (which character strings use too)
     * @return the joined contents; for BIT STRING with the last segment's
     *         unused-bits octet in front, so it decodes as a primitive one
     * @throws DecodeException for a wrong segment tag, unused bits before the
     *         last BIT STRING segment, or nesting deeper than
     *         {@link #MAX_SEGMENT_DEPTH} levels
     */
    public static byte[] joinSegments(ByteSource contents, int universal) throws DecodeException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(contents.remaining() + 1);
        boolean bits = universal == UniversalTag.BIT_STRING;
        if (bits) {
            out.write(0);
        }
        int[] unused = {0};
        joinInto(new BerReader(contents), universal, 1, false, out, unused);
        byte[] joined = out.toByteArray();
        if (bits) {
            joined[0] = (byte) unused[0];
        }
        return joined;
    }

    /**
     * Deepest nesting of constructed string segments a decoder accepts,
     * counting the constructed string itself as level 1. X.690 sets no
     * limit; this is the limit of the reference decoder (asn1c,
     * {@code BER_EXPLICIT_TAG_DEPTH_LIMIT}), and CER never nests segments.
     * Same value as C++ {@code kMaxSegmentDepth} and Rust {@code MAX_SEGMENT_DEPTH}.
     */
    static final int MAX_SEGMENT_DEPTH = 30;

    /**
     * Appends the segments read by {@code r} to {@code out}; part of
     * {@link #joinSegments}. Reads each segment's identifier and length
     * only, and walks a nested indefinite-length segment on the same reader
     * up to its end-of-contents, so every octet is visited once whatever the
     * nesting. Mirrors C++ {@code join_segments}.
     *
     * @param depth    nesting level, limited to {@link #MAX_SEGMENT_DEPTH}
     * @param untilEoc true for the segments of an indefinite-length segment:
     *                 stop after its end-of-contents (X.690 §8.1.5); false:
     *                 stop at the end of {@code r}
     * @param unused   BIT STRING only: unused bits of the last segment so far
     */
    private static void joinInto(BerReader r, int universal, int depth, boolean untilEoc,
            java.io.ByteArrayOutputStream out, int[] unused) throws DecodeException {
        if (depth > MAX_SEGMENT_DEPTH) {
            throw new DecodeException("constructed string segments nest deeper than " + MAX_SEGMENT_DEPTH
                    + " levels", r.position());
        }
        boolean bits = universal == UniversalTag.BIT_STRING;
        ByteSource src = r.src;
        for (;;) {
            if (untilEoc) {
                if (src.remaining() >= 2 && src.peek() == 0 && src.peek(1) == 0) {
                    src.skip(2, "end-of-contents");
                    return;
                }
                if (src.atEnd()) {
                    throw new DecodeException("unterminated indefinite-length encoding", src.position());
                }
            } else if (src.atEnd()) {
                return;
            }
            int at = src.position();
            Tag tag = r.readTag();
            if (tag.tagClass() != TagClass.UNIVERSAL || tag.number() != universal) {
                throw new DecodeException(bits
                        ? "segment of a constructed BIT STRING is not a BIT STRING"
                        : "segment of a constructed string is not an OCTET STRING", at);
            }
            int lenPos = src.position();
            int len = r.readLength();
            if (len < 0) {
                if (!tag.constructed()) {
                    throw new DecodeException("indefinite-length encoding on primitive type", lenPos);
                }
                joinInto(r, universal, depth + 1, true, out, unused);
                continue;
            }
            ByteSource v = src.sub(len, "contents");
            if (tag.constructed()) {
                joinInto(new BerReader(v), universal, depth + 1, false, out, unused);
                continue;
            }
            if (bits) {
                if (unused[0] != 0) {
                    throw new DecodeException("BIT STRING segment other than the last has unused bits", at);
                }
                if (v.atEnd()) {
                    throw new DecodeException("BIT STRING segment is empty (need at least unused-bits byte)", at);
                }
                int u = v.read("BIT STRING");
                if (u > 7 || (u != 0 && v.atEnd())) {
                    throw new DecodeException("BIT STRING segment has " + u + " unused bits in " + v.remaining()
                            + " octets", at);
                }
                unused[0] = u;
            }
            out.writeBytes(v.remainingBytes());
        }
    }

    /** Definite length, or -1 for the indefinite form. */
    private int readLength() throws DecodeException {
        int first = src.read("length");
        if (first == 0x80) {
            return -1;
        }
        if ((first & 0x80) == 0) {
            return first;
        }
        int n = first & 0x7F;
        if (n > 4) {
            throw new DecodeException("unsupported length encoding (" + n + " bytes)", src.position() - 1);
        }
        long len = 0;
        for (int i = 0; i < n; i++) {
            len = (len << 8) | src.read("length");
        }
        if (len > Integer.MAX_VALUE) {
            throw new DecodeException("length " + len + " exceeds 2 GiB", src.position());
        }
        return (int) len;
    }
}
