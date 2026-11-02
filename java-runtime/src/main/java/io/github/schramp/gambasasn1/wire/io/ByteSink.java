package io.github.schramp.gambasasn1.wire.io;

import java.util.Arrays;
import java.util.Objects;

/**
 * Growable output buffer shared by a whole encode. Codecs append to it and
 * may rewrite or shift bytes they already wrote, which a length back-fill
 * needs (see {@code BerWriter.writeTagged}).
 */
public final class ByteSink {
    private byte[] buf;
    private int size;

    public ByteSink() {
        this(64);
    }

    public ByteSink(int initialCapacity) {
        buf = new byte[Math.max(initialCapacity, 16)];
    }

    public int size() {
        return size;
    }

    public void write(int b) {
        ensure(size + 1);
        buf[size++] = (byte) b;
    }

    public void write(byte[] bytes) {
        write(bytes, 0, bytes.length);
    }

    public void write(byte[] bytes, int off, int len) {
        ensure(size + len);
        System.arraycopy(bytes, off, buf, size, len);
        size += len;
    }

    /** Overwrites the byte at {@code pos}, which must already be written. */
    public void set(int pos, int b) {
        Objects.checkIndex(pos, size);
        buf[pos] = (byte) b;
    }

    /** Appends {@code n} zero bytes. */
    public void pad(int n) {
        ensure(size + n);
        Arrays.fill(buf, size, size + n, (byte) 0);
        size += n;
    }

    /**
     * Moves the bytes {@code from..size} to start at {@code to}, so the buffer
     * shrinks or grows by {@code to - from}. Opened bytes are zero.
     */
    public void shift(int from, int to) {
        Objects.checkIndex(from, size + 1);
        int len = size - from;
        if (to > from) {
            ensure(to + len);
            System.arraycopy(buf, from, buf, to, len);
            Arrays.fill(buf, from, to, (byte) 0);
        } else {
            System.arraycopy(buf, from, buf, to, len);
        }
        size = to + len;
    }

    public byte[] toByteArray() {
        return Arrays.copyOf(buf, size);
    }

    private void ensure(int capacity) {
        if (capacity < 0) {
            throw new EncodeException("output exceeds 2 GiB");
        }
        if (capacity > buf.length) {
            buf = Arrays.copyOf(buf, Math.max(capacity, buf.length * 2));
        }
    }
}
