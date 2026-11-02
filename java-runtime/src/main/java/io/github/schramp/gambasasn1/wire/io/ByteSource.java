package io.github.schramp.gambasasn1.wire.io;

import java.util.Arrays;
import java.util.Objects;

/**
 * Read cursor over a window of a byte array. {@link #sub} hands out a
 * narrower window over the same array, so nested values are decoded
 * without copying.
 */
public final class ByteSource {
    private final byte[] data;
    private final int end;
    private int pos;

    public ByteSource(byte[] data) {
        this(data, 0, data.length);
    }

    public ByteSource(byte[] data, int start, int end) {
        Objects.checkFromToIndex(start, end, data.length);
        this.data = data;
        this.pos = start;
        this.end = end;
    }

    /** Absolute offset of the next byte in the underlying array. */
    public int position() {
        return pos;
    }

    public int remaining() {
        return end - pos;
    }

    public boolean atEnd() {
        return pos >= end;
    }

    /** The next byte (0..255) without consuming it, or -1 at the end. */
    public int peek() {
        return pos < end ? data[pos] & 0xFF : -1;
    }

    /** The byte (0..255) {@code offset} bytes ahead, or -1 past the end. */
    public int peek(int offset) {
        return offset >= 0 && offset < end - pos ? data[pos + offset] & 0xFF : -1;
    }

    public int read(String what) {
        if (pos >= end) {
            throw new DecodeException("unexpected end of data reading " + what, pos);
        }
        return data[pos++] & 0xFF;
    }

    /** The next {@code len} bytes as a window over the same array; consumes them. */
    public ByteSource sub(int len, String what) {
        require(len, what);
        ByteSource s = new ByteSource(data, pos, pos + len);
        pos += len;
        return s;
    }

    /**
     * A window over {@code start..end} (absolute offsets inside this
     * source's own window), sharing the same array. The cursor is unchanged.
     */
    public ByteSource window(int start, int end) {
        if (start < 0 || start > end || end > this.end) {
            throw new IndexOutOfBoundsException("window " + start + ".." + end);
        }
        return new ByteSource(data, start, end);
    }

    /** The next {@code len} bytes as a copy; consumes them. */
    public byte[] readBytes(int len, String what) {
        require(len, what);
        byte[] out = Arrays.copyOfRange(data, pos, pos + len);
        pos += len;
        return out;
    }

    /** The bytes from {@code start} (an earlier {@link #position()}) up to here. */
    public byte[] bytesSince(int start) {
        return Arrays.copyOfRange(data, start, pos);
    }

    public void skip(int len, String what) {
        require(len, what);
        pos += len;
    }

    /** A copy of the unread bytes, leaving the cursor where it is. */
    public byte[] remainingBytes() {
        return Arrays.copyOfRange(data, pos, end);
    }

    private void require(int len, String what) {
        if (len < 0 || len > end - pos) {
            throw new DecodeException("need " + len + " bytes for " + what + " but only " + (end - pos) + " remain", pos);
        }
    }
}
