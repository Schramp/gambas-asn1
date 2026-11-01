package io.github.schramp.gambasasn1.wire.per;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.Nesting;

/**
 * Cursor over an unaligned PER encoding, reading bit-fields most
 * significant bit first (X.691 §11.1.3). Its {@link DecodeException}s
 * carry the octet as position and the exact bit in the message: PER fields
 * rarely start on an octet.
 */
public final class PerReader {
    private final byte[] buf;
    private long pos;
    private int depth;
    private ContainedOptions contained;

    public PerReader(byte[] buf) {
        this.buf = buf;
    }

    /** Contained-value settings of this decode; null for the defaults. */
    public ContainedOptions contained() {
        return contained;
    }

    /** Sets the contained-value settings of this decode. */
    public PerReader withContained(ContainedOptions options) {
        contained = options;
        return this;
    }

    /** Bits read so far. */
    public long bitPos() {
        return pos;
    }

    /** Bits left before the end of the input. */
    public long remaining() {
        return buf.length * 8L - pos;
    }

    /** The octet the cursor is in, as a {@link DecodeException} position. */
    public int position() {
        return (int) (pos >>> 3);
    }

    /** A decode error at the cursor, its bit offset in the message. */
    public DecodeException error(String message) {
        return new DecodeException(message + " (bit " + pos + ")", position());
    }

    /**
     * Reads {@code n} bits, most significant first.
     *
     * @param n 0 to 64; 0 reads nothing and gives 0
     * @throws DecodeException when fewer than {@code n} bits are left
     */
    public long getBits(int n) {
        if (n > remaining()) {
            throw error("PER: unexpected end of data");
        }
        long v = 0;
        for (int i = 0; i < n; i++) {
            int bit = (buf[(int) (pos >>> 3)] >>> (7 - (int) (pos & 7))) & 1;
            v = (v << 1) | bit;
            pos++;
        }
        return v;
    }

    /**
     * A reader over {@code bytes}, an open-type field's contents (X.691
     * §11.2), at this reader's nesting depth and with its settings.
     */
    public PerReader sub(byte[] bytes) {
        PerReader r = new PerReader(bytes);
        r.depth = depth;
        r.contained = contained;
        return r;
    }

    /** Counts one more nesting level; fails past {@link Nesting#MAX_DECODE_DEPTH}. */
    public void enterLevel() {
        if (++depth > Nesting.MAX_DECODE_DEPTH) {
            throw error(Nesting.tooDeep());
        }
    }

    public void leaveLevel() {
        depth--;
    }

    /** The constructed levels this decode is inside. */
    public int depth() {
        return depth;
    }
}
