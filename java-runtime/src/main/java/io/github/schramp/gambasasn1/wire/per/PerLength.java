package io.github.schramp.gambasasn1.wire.per;

import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import java.io.ByteArrayOutputStream;

/**
 * Length determinants of the UNALIGNED variant (X.691 §11.9.4) and the
 * whole-number encodings that carry one: semi-constrained (§11.7),
 * unconstrained (§11.8) and normally small (§11.6). A count of 16K items or
 * more is written together with its items, since the fragmentation procedure
 * (§11.9.3.8) interleaves length octets with them; the C++
 * {@code per_detail} and Rust {@code per::length} helpers have the same shape.
 */
public final class PerLength {
    /** The fragment unit of X.691 §11.9.3.8: 16K items. */
    public static final int FRAGMENT_UNIT = 16384;

    private PerLength() {
    }

    /** Writes the items {@code from} to {@code to} (exclusive). */
    @FunctionalInterface
    public interface ItemWriter {
        void write(PerWriter w, int from, int to);
    }

    /** Reads {@code count} more items. */
    @FunctionalInterface
    public interface ItemReader {
        void read(PerReader r, int count);
    }

    /**
     * Appends a length determinant for {@code n} below 16K: one octet up to
     * 127 (X.691 §11.9.3.6), otherwise two with the top bits {@code 10}
     * (§11.9.3.7). Larger counts go through {@link #putLengthAndItems}.
     */
    public static void putLength(PerWriter w, int n) {
        if (n < 0 || n >= FRAGMENT_UNIT) {
            throw new EncodeException("PER: length " + n + " needs the fragmentation procedure");
        }
        if (n <= 127) {
            w.putBits(n, 8);
        } else {
            w.putBits(0x8000 | n, 16);
        }
    }

    /** Decode counterpart of {@link #putLength}; a fragment header is an error here. */
    public static int getLength(PerReader r) {
        int first = (int) r.getBits(8);
        if ((first & 0x80) == 0) {
            return first;
        }
        if ((first & 0xC0) == 0x80) {
            return ((first & 0x3F) << 8) | (int) r.getBits(8);
        }
        throw r.error("PER: fragmented length where a single length is required");
    }

    /**
     * Appends the general length determinant for {@code n} items followed by
     * the items (X.691 §11.9.3.5–§11.9.3.8): while 16K or more remain, an
     * octet {@code 11000kkk} and k (1 to 4, the largest that fits) blocks of
     * 16K items, then the rest the same way; a rest of 0 is the closing
     * {@code 00} octet.
     */
    public static void putLengthAndItems(PerWriter w, int n, ItemWriter items) {
        int start = 0;
        while (n - start >= FRAGMENT_UNIT) {
            int k = Math.min((n - start) / FRAGMENT_UNIT, 4);
            w.putBits(0xC0 | k, 8);
            items.write(w, start, start + k * FRAGMENT_UNIT);
            start += k * FRAGMENT_UNIT;
        }
        putLength(w, n - start);
        items.write(w, start, n);
    }

    /**
     * Decode counterpart of {@link #putLengthAndItems}: hands each fragment's
     * item count to {@code items}.
     *
     * @return the total item count
     */
    public static int getLengthAndItems(PerReader r, ItemReader items) {
        long total = 0;
        while (true) {
            int first = (int) r.getBits(8);
            if ((first & 0xC0) == 0xC0) {
                int k = first & 0x3F;
                if (k < 1 || k > 4) {
                    throw r.error("PER: fragment multiplier " + k + " outside 1..4");
                }
                total += (long) k * FRAGMENT_UNIT;
                if (total > Integer.MAX_VALUE) {
                    throw r.error("PER: fragmented length beyond the largest array");
                }
                items.read(r, k * FRAGMENT_UNIT);
                continue;
            }
            int n = (first & 0x80) == 0 ? first : ((first & 0x3F) << 8) | (int) r.getBits(8);
            if (total + n > Integer.MAX_VALUE) {
                throw r.error("PER: fragmented length beyond the largest array");
            }
            items.read(r, n);
            return (int) (total + n);
        }
    }

    /** Appends a general length and the octets (open types, OID, REAL, ANY contents). */
    public static void putOctets(PerWriter w, byte[] bytes) {
        putLengthAndItems(w, bytes.length, (out, from, to) -> {
            for (int i = from; i < to; i++) {
                out.putBits(bytes[i] & 0xFF, 8);
            }
        });
    }

    /** Decode counterpart of {@link #putOctets}. */
    public static byte[] getOctets(PerReader r) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        getLengthAndItems(r, (in, count) -> {
            if (count * 8L > in.remaining()) {
                throw in.error("PER: unexpected end of data");
            }
            for (int i = 0; i < count; i++) {
                out.write((int) in.getBits(8));
            }
        });
        return out.toByteArray();
    }

    /**
     * Appends a normally small length, the count of a SEQUENCE's extension
     * additions (X.691 §11.9.3.4): bit 0 and {@code n - 1} in 6 bits for
     * {@code n} in 1..64, otherwise bit 1 and a general length.
     */
    public static void putNormallySmallLength(PerWriter w, int n) {
        if (n >= 1 && n <= 64) {
            w.putBits(n - 1, 7);
        } else {
            w.putBits(1, 1);
            putLength(w, n);
        }
    }

    /** Decode counterpart of {@link #putNormallySmallLength}. */
    public static int getNormallySmallLength(PerReader r) {
        if (r.getBits(1) == 0) {
            return (int) r.getBits(6) + 1;
        }
        return getLength(r);
    }

    /**
     * Appends a normally small non-negative whole number, the index of a
     * CHOICE extension alternative (X.691 §23.8) or an ENUMERATED extension
     * item (§14.3): bit 0 and {@code n} in 6 bits up to 63 (§11.6.1), otherwise
     * bit 1 and {@code n} as a semi-constrained whole number with lb 0
     * (§11.6.2).
     */
    public static void putNormallySmall(PerWriter w, long n) {
        if (n < 0) {
            throw new EncodeException("PER: normally small number " + n + " is negative");
        }
        if (n <= 63) {
            w.putBits(n, 7);
        } else {
            w.putBits(1, 1);
            putSemiConstrained(w, n);
        }
    }

    /** Decode counterpart of {@link #putNormallySmall}. */
    public static long getNormallySmall(PerReader r) {
        if (r.getBits(1) == 0) {
            return r.getBits(6);
        }
        long n = getSemiConstrained(r);
        if (n < 0) {
            throw r.error("PER: normally small number beyond 63 bits");
        }
        return n;
    }

    /**
     * Appends a semi-constrained whole number (X.691 §11.7.4): the offset
     * {@code n - lb}, read as unsigned, in the minimum octets (§11.3.6),
     * preceded by their count as a length determinant.
     */
    public static void putSemiConstrained(PerWriter w, long offset) {
        putOctets(w, PerWhole.nonNegativeOctets(offset));
    }

    /**
     * Decode counterpart of {@link #putSemiConstrained}.
     *
     * @return the offset, to be read as unsigned
     */
    public static long getSemiConstrained(PerReader r) {
        return PerWhole.fromNonNegative(wholeNumberOctets(r));
    }

    /**
     * Appends an unconstrained whole number (X.691 §11.8.3): {@code n} as a
     * 2's-complement-binary-integer in the minimum octets (§11.4.6),
     * preceded by their count as a length determinant.
     */
    public static void putUnconstrained(PerWriter w, long n) {
        putOctets(w, PerWhole.twosComplementOctets(n));
    }

    /** Decode counterpart of {@link #putUnconstrained}. */
    public static long getUnconstrained(PerReader r) {
        return PerWhole.fromTwosComplement(wholeNumberOctets(r));
    }

    /** The octets of a length-prefixed whole number: 1 to 8, beyond 64 bits rejected. */
    private static byte[] wholeNumberOctets(PerReader r) {
        int len = getLength(r);
        if (len == 0) {
            throw r.error("PER: whole number with no octets");
        }
        if (len > 8) {
            throw r.error("PER: whole number of " + len + " octets exceeds 64 bits");
        }
        byte[] octets = new byte[len];
        for (int i = 0; i < len; i++) {
            octets[i] = (byte) r.getBits(8);
        }
        return octets;
    }

    /**
     * True when a SIZE takes the constrained-count length (X.691 §11.9.4.1):
     * a finite SIZE with ub below 64K. Otherwise the general length is used.
     */
    private static boolean countIsConstrained(Constraints c) {
        return (c.flags() & Constraints.SIZE_CONSTRAINED) != 0 && c.sizeUpper() < 65536;
    }

    /**
     * Appends the length determinant of {@code n} items under the SIZE of
     * {@code c}, then the items (X.691 §11.9.4): nothing for a fixed size,
     * {@code n - lb} in {@code sizeRangeBits} bits for a SIZE with ub below
     * 64K, otherwise the general length. A count outside such a SIZE has no
     * encoding and fails before anything is written.
     */
    public static void putSize(PerWriter w, Constraints c, int n, ItemWriter items) {
        if (!countIsConstrained(c)) {
            putLengthAndItems(w, n, items);
            return;
        }
        if (n < c.sizeLower() || n > c.sizeUpper()) {
            throw new EncodeException("PER: length " + n + " outside the non-extensible SIZE ("
                    + c.sizeLower() + ".." + c.sizeUpper() + ")");
        }
        w.putBits(n - c.sizeLower(), c.sizeRangeBits());
        items.write(w, 0, n);
    }

    /**
     * Decode counterpart of {@link #putSize}; a count outside a
     * non-extensible SIZE fails.
     *
     * @return the item count
     */
    public static int getSize(PerReader r, Constraints c, ItemReader items) {
        if (!countIsConstrained(c)) {
            int n = getLengthAndItems(r, items);
            if ((c.flags() & Constraints.SIZE_CONSTRAINED) != 0 && (n < c.sizeLower() || n > c.sizeUpper())) {
                throw r.error("PER: length " + n + " outside SIZE (" + c.sizeLower() + ".." + c.sizeUpper() + ")");
            }
            return n;
        }
        long n = c.sizeLower() + r.getBits(c.sizeRangeBits());
        if (n > c.sizeUpper()) {
            throw r.error("PER: length " + n + " outside SIZE (" + c.sizeLower() + ".." + c.sizeUpper() + ")");
        }
        items.read(r, (int) n);
        return (int) n;
    }

    /**
     * {@link #putSize} for a type whose SIZE may be extensible: OCTET STRING
     * (X.691 §17.3), BIT STRING (§16.6), SEQUENCE OF and SET OF (§20.4). An
     * extensible SIZE adds one bit first: 0 and the root form for a count in
     * the root, otherwise 1 and the general length.
     */
    public static void putExtSize(PerWriter w, Constraints c, int n, ItemWriter items) {
        if ((c.flags() & Constraints.EXTENSIBLE) != 0 && (c.flags() & Constraints.SIZE_CONSTRAINED) != 0) {
            boolean inRoot = n >= c.sizeLower() && n <= c.sizeUpper();
            w.putBits(inRoot ? 0 : 1, 1);
            if (!inRoot) {
                putLengthAndItems(w, n, items);
                return;
            }
        }
        putSize(w, c, n, items);
    }

    /** Decode counterpart of {@link #putExtSize}. */
    public static int getExtSize(PerReader r, Constraints c, ItemReader items) {
        if ((c.flags() & Constraints.EXTENSIBLE) != 0 && (c.flags() & Constraints.SIZE_CONSTRAINED) != 0
                && r.getBits(1) == 1) {
            return getLengthAndItems(r, items);
        }
        return getSize(r, c, items);
    }
}
