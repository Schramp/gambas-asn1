package io.github.schramp.gambasasn1.wire.per;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;

/**
 * The whole-number encodings of X.691 §11.3–§11.5 that need no length
 * determinant: non-negative-binary-integer, 2's-complement-binary-integer
 * and the constrained whole number of the UNALIGNED variant. Bounds and
 * offsets are full 64-bit: a range up to {@code Long.MIN_VALUE..Long.MAX_VALUE}
 * is a 64-bit field (X.691 §11.5.6).
 */
public final class PerWhole {
    private PerWhole() {
    }

    /**
     * Bits of the bit-field that holds {@code n - lb} for {@code lb <= n <= ub}:
     * the fewest that represent the range, 0 when the range is one value
     * (X.691 §11.5.6, §11.5.4).
     */
    public static int rangeBits(long lb, long ub) {
        long span = ub - lb;
        return span == 0 ? 0 : 64 - Long.numberOfLeadingZeros(span);
    }

    /** Appends {@code n} as a constrained whole number in {@code lb..ub} (X.691 §11.5.6). */
    public static void putConstrained(PerWriter w, long n, long lb, long ub) {
        if (n < lb || n > ub) {
            throw new EncodeException("PER: " + n + " outside " + lb + ".." + ub);
        }
        w.putBits(n - lb, rangeBits(lb, ub));
    }

    /**
     * Reads a constrained whole number in {@code lb..ub} (X.691 §11.5.6).
     *
     * @throws DecodeException for a field value beyond the range
     */
    public static long getConstrained(PerReader r, long lb, long ub) {
        long offset = r.getBits(rangeBits(lb, ub));
        if (Long.compareUnsigned(offset, ub - lb) > 0) {
            throw r.error("PER: constrained whole number beyond " + lb + ".." + ub);
        }
        return lb + offset;
    }

    /**
     * The minimum octet 2's-complement-binary-integer encoding of {@code n}
     * (X.691 §11.4.6): the leading nine bits are neither all zero nor all one.
     */
    public static byte[] twosComplementOctets(long n) {
        int len = 8;
        while (len > 1 && (n >> (len * 8 - 9)) == (n >> 63)) {
            len--;
        }
        return toOctets(n, len);
    }

    /** The value of a 2's-complement-binary-integer field of 1 to 8 octets (X.691 §11.4.4). */
    public static long fromTwosComplement(byte[] octets) {
        long v = octets[0];
        for (int i = 1; i < octets.length; i++) {
            v = (v << 8) | (octets[i] & 0xFF);
        }
        return v;
    }

    /**
     * The minimum octet non-negative-binary-integer encoding of {@code n}
     * read as unsigned (X.691 §11.3.6): no leading zero octet, one octet for 0.
     */
    public static byte[] nonNegativeOctets(long n) {
        int len = Math.max(1, (64 - Long.numberOfLeadingZeros(n) + 7) / 8);
        return toOctets(n, len);
    }

    /** The unsigned value of a non-negative-binary-integer field of 1 to 8 octets (X.691 §11.3.4). */
    public static long fromNonNegative(byte[] octets) {
        long v = 0;
        for (byte b : octets) {
            v = (v << 8) | (b & 0xFF);
        }
        return v;
    }

    private static byte[] toOctets(long n, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (n >>> ((len - 1 - i) * 8));
        }
        return out;
    }
}
