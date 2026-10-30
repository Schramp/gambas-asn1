package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import java.util.function.Consumer;

/**
 * BER output: appends identifier, length and contents octets to a shared
 * {@link ByteSink}. Lengths are definite (X.690 §8.1.3.3).
 */
public final class BerWriter {
    private BerWriter() {
    }

    /** Identifier octets (X.690 §8.1.2); high-tag-number form from 31 on. */
    public static void writeTag(ByteSink out, Tag t) {
        int first = (t.tagClass().bits() << 6) | (t.constructed() ? 0x20 : 0x00);
        int n = t.number();
        if (n < 31) {
            out.write(first | n);
            return;
        }
        out.write(first | 0x1F);
        int groups = (32 - Integer.numberOfLeadingZeros(n) + 6) / 7;
        for (int i = groups - 1; i >= 0; i--) {
            out.write(((n >>> (7 * i)) & 0x7F) | (i != 0 ? 0x80 : 0x00));
        }
    }

    /** Definite length octets, short form below 128 (X.690 §8.1.3.4/§8.1.3.5). */
    public static void writeLength(ByteSink out, int len) {
        if (len < 128) {
            out.write(len);
            return;
        }
        int n = (32 - Integer.numberOfLeadingZeros(len) + 7) / 8;
        out.write(0x80 | n);
        for (int i = n - 1; i >= 0; i--) {
            out.write(len >>> (8 * i));
        }
    }

    /** One complete TLV with the given contents octets. */
    public static void writePrimitive(ByteSink out, Tag t, byte[] value) {
        writeTag(out, t);
        writeLength(out, value.length);
        out.write(value);
    }

    /**
     * Writes tag {@code t}, lets {@code fill} append the contents directly
     * to {@code out}, then back-fills the length. A 3-byte placeholder is
     * reserved and the contents shift down to close the gap, so a whole tree
     * of TLVs is written into one buffer with no buffer per node. This is
     * also the EXPLICIT wrapper (X.690 §8.14.2): {@code fill} writes the
     * inner TLV.
     */
    public static void writeTagged(ByteSink out, Tag t, Consumer<ByteSink> fill) {
        writeTag(out, t);
        int lenPos = out.size();
        out.pad(3);
        int contentStart = out.size();
        fill.accept(out);
        int contentSize = out.size() - contentStart;
        if (contentSize < 128) {
            out.shift(contentStart, lenPos + 1);
            out.set(lenPos, contentSize);
        } else if (contentSize < 256) {
            out.shift(contentStart, lenPos + 2);
            out.set(lenPos, 0x81);
            out.set(lenPos + 1, contentSize);
        } else if (contentSize < 65536) {
            out.set(lenPos, 0x82);
            out.set(lenPos + 1, contentSize >>> 8);
            out.set(lenPos + 2, contentSize);
        } else {
            int n = (32 - Integer.numberOfLeadingZeros(contentSize) + 7) / 8;
            out.shift(contentStart, contentStart + n - 2);
            out.set(lenPos, 0x80 | n);
            for (int i = 0; i < n; i++) {
                out.set(lenPos + 1 + i, contentSize >>> (8 * (n - 1 - i)));
            }
        }
    }
}
