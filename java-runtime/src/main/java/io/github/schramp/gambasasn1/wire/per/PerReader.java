package io.github.schramp.gambasasn1.wire.per;

import io.github.schramp.gambasasn1.wire.DecodeOptions;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.Nesting;
import io.github.schramp.gambasasn1.wire.spec.Positions;

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
    private DecodeOptions options = DecodeOptions.DEFAULT;
    private Positions positions;
    // Absolute bit, in the decode's input, of this reader's bit 0.
    private long baseBits;

    public PerReader(byte[] buf) {
        this.buf = buf;
    }

    /** Contained-value settings of this decode; null for the defaults. */
    public ContainedOptions contained() {
        return options.contained();
    }

    /** Sets the contained-value settings of this decode. */
    public PerReader withContained(ContainedOptions c) {
        options = options.withContained(c);
        return this;
    }

    /** The decoder settings of this decode. */
    public DecodeOptions options() {
        return options;
    }

    /** Sets the decoder settings, contained-value settings included; null for the defaults. */
    public PerReader withOptions(DecodeOptions o) {
        options = DecodeOptions.orDefault(o);
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

    /**
     * A decode error at the cursor, its bit offset in the message. Both
     * are offsets in the decode's input, also inside an open type.
     */
    public DecodeException error(String message) {
        long at = absoluteBit(pos);
        return new DecodeException(message + " (bit " + at + ")", (int) (at >>> 3));
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
        r.options = options;
        return r;
    }

    /**
     * {@link #sub} over the octets this reader has just read, so the nested
     * reader's positions are the octets' place in the input. For an open
     * type below 16K octets (one length determinant, X.691 §11.9.3.8) that
     * place is exact.
     */
    public PerReader subJustRead(byte[] bytes) {
        PerReader r = sub(bytes);
        r.withPositions(positions, absoluteBit(pos) - 8L * bytes.length);
        return r;
    }

    /** The positions this decode records into, or null when it records none. */
    public Positions positions() {
        return positions;
    }

    /**
     * Records positions of the nodes decoded through this reader into
     * {@code p}, this reader's bit 0 being absolute bit {@code baseBit};
     * returns this reader.
     */
    public PerReader withPositions(Positions p, long baseBit) {
        positions = p;
        baseBits = baseBit;
        return this;
    }

    /** Absolute bit, in the decode's input, of this reader's bit {@code local}. */
    public long absoluteBit(long local) {
        return baseBits + local;
    }

    /** Records that {@code node} starts at the reader's current bit, when positions are recorded. */
    public void markStart(Object node) {
        if (positions != null) {
            positions.record(node, absoluteBit(pos));
        }
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
