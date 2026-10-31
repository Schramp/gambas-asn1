package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.ByteSource;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.Nesting;

/**
 * BER input: reads one TLV at a time from a {@link ByteSource}. Every
 * malformed input ends in a {@link DecodeException}. The reader also
 * carries the constructed nesting depth of the decode using it
 * ({@link Nesting}) and its contained-value settings.
 */
public final class BerReader {
    private final ByteSource src;
    private int depth;
    private ContainedOptions contained;

    public BerReader(ByteSource src) {
        this.src = src;
    }

    /** A reader over a nested value's bytes, at this reader's depth and with its contained-value settings. */
    public BerReader nested(ByteSource contents) {
        BerReader r = new BerReader(contents);
        r.depth = depth;
        r.contained = contained;
        return r;
    }

    /** Contained-value settings of this decode; null means the defaults. */
    public ContainedOptions contained() {
        return contained;
    }

    /** Sets the contained-value settings; returns this reader. */
    public BerReader withContained(ContainedOptions options) {
        contained = options;
        return this;
    }

    /** {@link #nested(ByteSource)} over a copy of the given bytes. */
    public BerReader nested(byte[] contents) {
        return nested(new ByteSource(contents));
    }

    /**
     * Enters one constructed nesting level.
     *
     * @throws DecodeException when the decode is already
     *         {@link Nesting#MAX_DECODE_DEPTH} levels deep
     */
    public void enterLevel() {
        if (depth >= Nesting.MAX_DECODE_DEPTH) {
            throw new DecodeException(Nesting.tooDeep(), position());
        }
        depth++;
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
    public Tag readTag() {
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
    public Tlv readTlv() {
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

    /** Definite length, or -1 for the indefinite form. */
    private int readLength() {
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
