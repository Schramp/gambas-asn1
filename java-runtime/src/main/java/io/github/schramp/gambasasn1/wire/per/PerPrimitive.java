package io.github.schramp.gambasasn1.wire.per;

import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.EnumSpec;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.ber.BerPrimitive;
import io.github.schramp.gambasasn1.wire.ber.BerReal;
import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import io.github.schramp.gambasasn1.wire.types.Asn1Any;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1CharString;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1ObjectIdentifier;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1RelativeOid;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;

/**
 * Unaligned PER fields of the builtin leaf types: one switch over the
 * builtin wrappers, as in the C++ {@code PerCodec} and the Rust
 * {@code spec::primitive} dispatch. A value's own constraints pick its
 * field; a type with no PER field yet fails the encode or decode.
 */
public final class PerPrimitive {
    private PerPrimitive() {
    }

    /**
     * Appends {@code p}'s field.
     *
     * @param c its own PER-visible constraints
     */
    public static void encode(Asn1Primitive p, Constraints c, PerWriter w) {
        switch (p) {
            // X.691 §12: a single bit, 1 for TRUE.
            case Asn1Boolean b -> w.putBits(b.get() ? 1 : 0, 1);
            // X.691 §18: no field.
            case Asn1Null n -> {
            }
            case Asn1Integer i -> encodeInteger(i.get(), c, w);
            case Asn1UInteger u -> encodeUInteger(u.get(), c, w);
            case Asn1OctetString o -> encodeOctets(o.get(), c, w);
            case Asn1BitString b -> encodeBits(b, c, w);
            case Asn1CharString s -> encodeChars(s.octets(), s.universalTagNumber(), c, w);
            // X.691 §24, §25: the BER contents octets after a general length.
            case Asn1ObjectIdentifier o -> PerLength.putOctets(w, BerPrimitive.encodeObjectIdentifier(o.get()));
            case Asn1RelativeOid o -> PerLength.putOctets(w, BerPrimitive.encodeRelativeOid(o.get()));
            // X.691 §15: the CER/DER contents octets (X.690 §11.3) after a general length.
            case Asn1Real r -> PerLength.putOctets(w, BerReal.encode(r));
            // X.691 §11.2: an open type field, the value's encoding after a general length.
            case Asn1Any a -> PerLength.putOctets(w, a.get());
            default -> throw new EncodeException("PER: " + p.getClass().getSimpleName() + " is not supported yet");
        }
    }

    /**
     * Reads {@code p}'s field.
     *
     * @param c its own PER-visible constraints
     */
    public static void decode(Asn1Primitive p, Constraints c, PerReader r) {
        switch (p) {
            case Asn1Boolean b -> b.set(r.getBits(1) == 1);
            case Asn1Null n -> {
            }
            case Asn1Integer i -> i.set(decodeInteger(c, r));
            case Asn1UInteger u -> u.set(decodeUInteger(c, r));
            case Asn1OctetString o -> o.set(decodeOctets(c, r));
            case Asn1BitString b -> decodeBits(b, c, r);
            case Asn1CharString s -> s.setOctets(decodeChars(s.universalTagNumber(), c, r));
            case Asn1ObjectIdentifier o -> o.set(BerPrimitive.decodeObjectIdentifier(PerLength.getOctets(r), r.position()));
            case Asn1RelativeOid o -> o.set(BerPrimitive.decodeRelativeOid(PerLength.getOctets(r), r.position()));
            case Asn1Real real -> real.set(BerReal.decode(PerLength.getOctets(r), r.position()));
            case Asn1Any a -> a.set(PerLength.getOctets(r));
            default -> throw r.error("PER: " + p.getClass().getSimpleName() + " is not supported yet");
        }
    }

    private static boolean has(Constraints c, int flag) {
        return (c.flags() & flag) != 0;
    }

    /**
     * An INTEGER with signed storage (X.691 §13): the extension bit of an
     * extensible constraint, 1 and the unconstrained form for a value
     * outside the root (§13.1); then a constrained whole number in the
     * table's {@code rangeBits} (§11.5.6), a semi-constrained whole number
     * (§13.2.3, §11.7) or an unconstrained one (§11.8).
     */
    static void encodeInteger(long v, Constraints c, PerWriter w) {
        if (has(c, Constraints.CONSTRAINED)) {
            if (has(c, Constraints.EXTENSIBLE)) {
                boolean inRoot = v >= c.lowerBound() && v <= c.upperBound();
                w.putBits(inRoot ? 0 : 1, 1);
                if (!inRoot) {
                    PerLength.putUnconstrained(w, v);
                    return;
                }
            } else if (v < c.lowerBound() || v > c.upperBound()) {
                throw new EncodeException("PER: INTEGER " + v + " outside " + c.lowerBound() + ".." + c.upperBound());
            }
            w.putBits(v - c.lowerBound(), c.rangeBits());
        } else if (has(c, Constraints.SEMI_CONSTRAINED)) {
            if (has(c, Constraints.EXTENSIBLE)) {
                boolean inRoot = v >= c.lowerBound();
                w.putBits(inRoot ? 0 : 1, 1);
                if (!inRoot) {
                    PerLength.putUnconstrained(w, v);
                    return;
                }
            } else if (v < c.lowerBound()) {
                throw new EncodeException("PER: INTEGER " + v + " below " + c.lowerBound());
            }
            PerLength.putSemiConstrained(w, v - c.lowerBound());
        } else {
            PerLength.putUnconstrained(w, v);
        }
    }

    /** Decode counterpart of {@link #encodeInteger}. */
    static long decodeInteger(Constraints c, PerReader r) {
        boolean bounded = has(c, Constraints.CONSTRAINED) || has(c, Constraints.SEMI_CONSTRAINED);
        if (bounded && has(c, Constraints.EXTENSIBLE) && r.getBits(1) == 1) {
            return PerLength.getUnconstrained(r);
        }
        if (has(c, Constraints.CONSTRAINED)) {
            long offset = r.getBits(c.rangeBits());
            if (Long.compareUnsigned(offset, c.upperBound() - c.lowerBound()) > 0) {
                throw r.error("PER: INTEGER beyond " + c.lowerBound() + ".." + c.upperBound());
            }
            return c.lowerBound() + offset;
        }
        if (has(c, Constraints.SEMI_CONSTRAINED)) {
            long offset = PerLength.getSemiConstrained(r);
            // n - lb fits when it is at most Long.MAX_VALUE - lb, read as unsigned.
            if (Long.compareUnsigned(offset, Long.MAX_VALUE - c.lowerBound()) > 0) {
                throw r.error("PER: semi-constrained INTEGER exceeds its storage");
            }
            return c.lowerBound() + offset;
        }
        return PerLength.getUnconstrained(r);
    }

    /**
     * An INTEGER with unsigned 64-bit storage, bounds {@code lowerU64} and
     * {@code upperU64}: {@link #encodeInteger}'s cases with unsigned
     * compares. A value outside the root is the unconstrained form of the
     * value itself, which takes a ninth octet from 2^63 up (X.691 §11.8.3,
     * §11.4.6).
     */
    static void encodeUInteger(long v, Constraints c, PerWriter w) {
        if (has(c, Constraints.CONSTRAINED)) {
            boolean inRoot = Long.compareUnsigned(v, c.lowerU64()) >= 0 && Long.compareUnsigned(v, c.upperU64()) <= 0;
            if (has(c, Constraints.EXTENSIBLE)) {
                w.putBits(inRoot ? 0 : 1, 1);
                if (!inRoot) {
                    putUnsignedUnconstrained(w, v);
                    return;
                }
            } else if (!inRoot) {
                throw new EncodeException("PER: INTEGER " + Long.toUnsignedString(v) + " outside "
                        + Long.toUnsignedString(c.lowerU64()) + ".." + Long.toUnsignedString(c.upperU64()));
            }
            w.putBits(v - c.lowerU64(), c.rangeBits());
        } else if (has(c, Constraints.SEMI_CONSTRAINED)) {
            boolean inRoot = Long.compareUnsigned(v, c.lowerU64()) >= 0;
            if (has(c, Constraints.EXTENSIBLE)) {
                w.putBits(inRoot ? 0 : 1, 1);
                if (!inRoot) {
                    putUnsignedUnconstrained(w, v);
                    return;
                }
            } else if (!inRoot) {
                throw new EncodeException("PER: INTEGER " + Long.toUnsignedString(v) + " below "
                        + Long.toUnsignedString(c.lowerU64()));
            }
            PerLength.putSemiConstrained(w, v - c.lowerU64());
        } else {
            putUnsignedUnconstrained(w, v);
        }
    }

    /** Decode counterpart of {@link #encodeUInteger}. */
    static long decodeUInteger(Constraints c, PerReader r) {
        boolean bounded = has(c, Constraints.CONSTRAINED) || has(c, Constraints.SEMI_CONSTRAINED);
        if (bounded && has(c, Constraints.EXTENSIBLE) && r.getBits(1) == 1) {
            return getUnsignedUnconstrained(r);
        }
        if (has(c, Constraints.CONSTRAINED)) {
            long offset = r.getBits(c.rangeBits());
            if (Long.compareUnsigned(offset, c.upperU64() - c.lowerU64()) > 0) {
                throw r.error("PER: INTEGER beyond " + Long.toUnsignedString(c.lowerU64()) + ".."
                        + Long.toUnsignedString(c.upperU64()));
            }
            return c.lowerU64() + offset;
        }
        if (has(c, Constraints.SEMI_CONSTRAINED)) {
            long offset = PerLength.getSemiConstrained(r);
            if (Long.compareUnsigned(offset, -1L - c.lowerU64()) > 0) {
                throw r.error("PER: semi-constrained INTEGER exceeds its storage");
            }
            return c.lowerU64() + offset;
        }
        return getUnsignedUnconstrained(r);
    }

    /** {@code v}, read as unsigned, as an unconstrained whole number (X.691 §11.8.3). */
    private static void putUnsignedUnconstrained(PerWriter w, long v) {
        if (v >= 0) {
            PerLength.putUnconstrained(w, v);
            return;
        }
        byte[] octets = new byte[9];
        System.arraycopy(PerWhole.nonNegativeOctets(v), 0, octets, 1, 8);
        PerLength.putOctets(w, octets);
    }

    /** Decode counterpart of {@link #putUnsignedUnconstrained}: a negative value has no unsigned storage. */
    private static long getUnsignedUnconstrained(PerReader r) {
        byte[] octets = PerLength.getOctets(r);
        if (octets.length == 9 && octets[0] == 0 && octets[1] < 0) {
            return PerWhole.fromNonNegative(java.util.Arrays.copyOfRange(octets, 1, 9));
        }
        if (octets.length == 0 || octets.length > 8 || octets[0] < 0) {
            throw r.error("PER: INTEGER outside its unsigned 64-bit storage");
        }
        return PerWhole.fromNonNegative(octets);
    }

    /**
     * An ENUMERATED value (X.691 §14): its index in the table's items, which
     * are sorted by value (§14.1). A root item is a constrained whole number
     * in {@code rootBits} (§14.2); with an extension marker a bit comes first,
     * 1 for an extension item, whose index among the extension items is then
     * a normally small non-negative whole number (§14.3).
     */
    static void encodeEnumerated(EnumSlot slot, EnumSpec spec, PerWriter w) {
        long value = slot.enumGet();
        int index = -1;
        for (int i = 0; i < spec.entries().size(); i++) {
            if (spec.entries().get(i).value() == value) {
                index = i;
                break;
            }
        }
        if (index < 0) {
            throw new EncodeException("PER: " + value + " is not an item of " + spec.name());
        }
        boolean inRoot = index < spec.rootCount();
        if (spec.extensible()) {
            w.putBits(inRoot ? 0 : 1, 1);
        }
        if (inRoot) {
            w.putBits(index, spec.rootBits());
        } else {
            PerLength.putNormallySmall(w, index - spec.rootCount());
        }
    }

    /** Decode counterpart of {@link #encodeEnumerated}; an index past the known items fails. */
    static void decodeEnumerated(EnumSlot slot, EnumSpec spec, PerReader r) {
        long index;
        if (spec.extensible() && r.getBits(1) == 1) {
            index = spec.rootCount() + PerLength.getNormallySmall(r);
            if (index >= spec.entries().size()) {
                throw r.error("PER: unknown extension item of " + spec.name());
            }
        } else {
            index = r.getBits(spec.rootBits());
            if (index >= spec.rootCount()) {
                throw r.error("PER: root index " + index + " beyond the items of " + spec.name());
            }
        }
        slot.enumSet(spec.entries().get((int) index).value());
    }

    /**
     * An OCTET STRING (X.691 §17): the length determinant under its SIZE,
     * with the extension bit of an extensible SIZE (§17.3), then the octets.
     */
    static void encodeOctets(byte[] octets, Constraints c, PerWriter w) {
        PerLength.putExtSize(w, c, octets.length, (out, from, to) -> {
            for (int i = from; i < to; i++) {
                out.putBits(octets[i] & 0xFF, 8);
            }
        });
    }

    /** Decode counterpart of {@link #encodeOctets}. */
    static byte[] decodeOctets(Constraints c, PerReader r) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        PerLength.getExtSize(r, c, (in, count) -> {
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
     * A BIT STRING (X.691 §16): the length determinant under its SIZE, with
     * the extension bit of an extensible SIZE (§16.6), then the bits. With a
     * NamedBitList, trailing 0 bits are left out down to the SIZE's lower
     * bound, and 0 bits are added up to it (§16.2, §16.3).
     */
    static void encodeBits(Asn1BitString b, Constraints c, PerWriter w) {
        byte[] bytes = b.bytes();
        int count = b.bitCount();
        int n = count;
        if (has(c, Constraints.NAMED_BITS)) {
            while (n > 0 && ((bytes[(n - 1) / 8] >>> (7 - (n - 1) % 8)) & 1) == 0) {
                n--;
            }
            if (has(c, Constraints.SIZE_CONSTRAINED)) {
                n = (int) Math.max(n, c.sizeLower());
            }
        }
        PerLength.putExtSize(w, c, n, (out, from, to) -> {
            for (int i = from; i < to; i++) {
                out.putBits(i < count ? (bytes[i / 8] >>> (7 - i % 8)) & 1 : 0, 1);
            }
        });
    }

    /** Decode counterpart of {@link #encodeBits}. */
    static void decodeBits(Asn1BitString b, Constraints c, PerReader r) {
        PerWriter bits = new PerWriter();
        int n = PerLength.getExtSize(r, c, (in, count) -> {
            if (count > in.remaining()) {
                throw in.error("PER: unexpected end of data");
            }
            for (int i = 0; i < count; i++) {
                bits.putBits(in.getBits(1), 1);
            }
        });
        b.set(n == 0 ? new byte[0] : bits.toByteArray(), (8 - n % 8) % 8);
    }

    /**
     * Bits per character and octets per character of a string kind without a
     * PER-visible FROM (X.691 §30.5.2): NumericString 4, the 128-character
     * kinds 7 (UTCTime and GeneralizedTime as VisibleString, §10.6.5),
     * BMPString 16 and UniversalString 32 as their 2 or 4 octets; every other
     * kind its octets, 8 bits each. The C++ and Rust runtimes use the same table.
     */
    private static int[] charLayout(int tag) {
        return switch (tag) {
            case UniversalTag.NUMERIC_STRING -> new int[] {4, 1};
            case UniversalTag.PRINTABLE_STRING, UniversalTag.IA5_STRING, UniversalTag.VISIBLE_STRING,
                    UniversalTag.UTC_TIME, UniversalTag.GENERALIZED_TIME -> new int[] {7, 1};
            case UniversalTag.BMP_STRING -> new int[] {8, 2};
            case UniversalTag.UNIVERSAL_STRING -> new int[] {8, 4};
            default -> new int[] {8, 1};
        };
    }

    /** The FROM table applies: the generated table carries a PER-visible permitted alphabet. */
    private static boolean hasAlphabet(Constraints c) {
        return c.alphabetBits() > 0 && c.encodeTable() != null;
    }

    /** Index of the character in octets {@code at..at+width} in the FROM table, or -1. */
    private static int alphabetIndex(Constraints c, byte[] octets, int at, int width) {
        for (int k = 0; k < width - 1; k++) {
            if (octets[at + k] != 0) {
                return -1;
            }
        }
        char index = c.encodeTable()[octets[at + width - 1] & 0xFF];
        return index == 0xFFFF ? -1 : index;
    }

    /**
     * A restricted character string (X.691 §30). An extensible SIZE or FROM
     * adds a bit, 1 and the string under no constraint when it lies outside
     * the root (§30.4). Then the length in characters under the SIZE and each
     * character: its FROM index in {@code alphabetBits} bits, or the
     * {@link #charLayout} field of the kind (NumericString remapped, §30.5.4).
     */
    static void encodeChars(byte[] octets, int tag, Constraints c, PerWriter w) {
        int bits = charLayout(tag)[0];
        int width = charLayout(tag)[1];
        int count = octets.length / width;
        boolean alpha = hasAlphabet(c);
        boolean sized = has(c, Constraints.SIZE_CONSTRAINED);
        if (has(c, Constraints.EXTENSIBLE) && (sized || alpha)) {
            boolean inRoot = !sized || (count >= c.sizeLower() && count <= c.sizeUpper());
            for (int i = 0; inRoot && alpha && i < count; i++) {
                inRoot = alphabetIndex(c, octets, i * width, width) >= 0;
            }
            w.putBits(inRoot ? 0 : 1, 1);
            if (!inRoot) {
                encodeChars(octets, tag, Constraints.UNCONSTRAINED, w);
                return;
            }
        }
        for (int i = 0; i < count; i++) {
            int at = i * width;
            if (alpha) {
                if (alphabetIndex(c, octets, at, width) < 0) {
                    throw new EncodeException("PER: character " + (octets[at + width - 1] & 0xFF)
                            + " is not in the permitted alphabet");
                }
            } else if (bits == 4) {
                int ch = octets[at] & 0xFF;
                if (ch != ' ' && (ch < '0' || ch > '9')) {
                    throw new EncodeException("PER: character " + ch + " is not in the NumericString alphabet");
                }
            } else if (bits == 7 && (octets[at] & 0x80) != 0) {
                throw new EncodeException("PER: character " + (octets[at] & 0xFF) + " is outside a 7-bit alphabet");
            }
        }
        PerLength.putSize(w, c, count, (out, from, to) -> {
            for (int i = from; i < to; i++) {
                int at = i * width;
                if (alpha) {
                    out.putBits(alphabetIndex(c, octets, at, width), c.alphabetBits());
                } else if (bits == 4) {
                    int ch = octets[at] & 0xFF;
                    out.putBits(ch == ' ' ? 0 : ch - '0' + 1, 4);
                } else {
                    for (int k = 0; k < width; k++) {
                        out.putBits(octets[at + k] & 0xFF, bits);
                    }
                }
            }
        });
    }

    /** Decode counterpart of {@link #encodeChars}: the string's contents octets. */
    static byte[] decodeChars(int tag, Constraints c, PerReader r) {
        int bits = charLayout(tag)[0];
        int width = charLayout(tag)[1];
        boolean alpha = hasAlphabet(c);
        if (has(c, Constraints.EXTENSIBLE) && (has(c, Constraints.SIZE_CONSTRAINED) || alpha) && r.getBits(1) == 1) {
            return decodeChars(tag, Constraints.UNCONSTRAINED, r);
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int perChar = alpha ? c.alphabetBits() : bits * width;
        PerLength.getSize(r, c, (in, count) -> {
            if ((long) count * perChar > in.remaining()) {
                throw in.error("PER: unexpected end of data");
            }
            for (int i = 0; i < count; i++) {
                if (alpha) {
                    long index = in.getBits(c.alphabetBits());
                    if (index >= c.alphabetSize()) {
                        throw in.error("PER: alphabet index " + index + " beyond the permitted alphabet");
                    }
                    for (int k = 0; k < width - 1; k++) {
                        out.write(0);
                    }
                    out.write(c.alphabet()[(int) index]);
                } else if (bits == 4) {
                    long v = in.getBits(4);
                    if (v > 10) {
                        throw in.error("PER: NumericString character index " + v + " beyond 10");
                    }
                    out.write(v == 0 ? ' ' : (int) ('0' + v - 1));
                } else {
                    for (int k = 0; k < width; k++) {
                        out.write((int) in.getBits(bits));
                    }
                }
            }
        });
        return out.toByteArray();
    }
}
