package io.github.schramp.gambasasn1.wire.spec;

import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1CharString;
import io.github.schramp.gambasasn1.wire.types.Asn1GeneralizedTime;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import io.github.schramp.gambasasn1.wire.types.Asn1UtcTime;

/**
 * Checks a decoded value against its {@link Constraints} row: the value
 * range of an INTEGER or REAL, the SIZE of a string or SEQUENCE OF and a
 * string's permitted alphabet (X.680 §51). The rules are the C++ runtime's
 * {@code validate()}: a constraint with an extension marker admits every
 * value, and a string's SIZE counts its contents octets.
 */
public final class ConstraintCheck {
    private ConstraintCheck() {
    }

    /**
     * Why {@code m}'s value breaks {@code c}, or null when it satisfies it.
     * A SEQUENCE OF is checked for its SIZE and each element against
     * {@code c.element()}; a SEQUENCE or CHOICE checks nothing here, its
     * members being checked against their own rows.
     */
    public static String violation(MemberRef m, Constraints c) {
        if (c == null || c == Constraints.UNCONSTRAINED) {
            return null;
        }
        return switch (m) {
            case MemberRef.Primitive(var p) -> switch (p) {
                case Asn1Integer i -> range(i.get(), c);
                case Asn1UInteger u -> rangeUnsigned(u.get(), c);
                case Asn1Real r -> realRange(r.value(), c);
                case Asn1OctetString o -> size("OCTET STRING", o.get().length, c, false);
                case Asn1BitString b -> bits(b, c);
                case Asn1UtcTime t -> null;
                case Asn1GeneralizedTime t -> null;
                case Asn1CharString s -> chars(s, c);
                default -> null;
            };
            case MemberRef.SeqOf(var q) -> {
                String v = size("SEQUENCE OF", q.size(), c, false);
                for (int i = 0; v == null && c.element() != null && i < q.size(); i++) {
                    v = violation(q.get(i), c.element());
                }
                yield v;
            }
            default -> null;
        };
    }

    /** A value that breaks its constraints, {@code path} naming it ({@code Type.member[index]}). */
    public record Violation(String path, String reason) {
    }

    /**
     * The first value, depth first, in the tree under {@code m} that breaks
     * its constraints ({@code c} for {@code m} itself, then each member's,
     * alternative's or element's own row), or null when there is none. The
     * inner value of a contained field is not looked into: its decode
     * checks it.
     */
    public static Violation firstViolation(MemberRef m, Constraints c, String path) {
        String why = violation(m, c);
        if (why != null) {
            return new Violation(path, why);
        }
        switch (m) {
            case MemberRef.Composite(var s) -> {
                for (int i = 0; i < s.spec().members().size(); i++) {
                    MemberMeta row = s.spec().members().get(i);
                    Violation v = firstViolation(s.getMember(i), row.constraints(), path + "." + row.name());
                    if (v != null) {
                        return v;
                    }
                }
            }
            case MemberRef.Choice(var ch) -> {
                int i = ch.activeIndex();
                if (i >= 0) {
                    AltMeta row = ch.spec().alternatives().get(i);
                    return firstViolation(ch.getActive(), row.constraints(), path + "." + row.name());
                }
            }
            case MemberRef.SeqOf(var q) -> {
                Constraints e = c != null && c.element() != null ? c.element() : Constraints.UNCONSTRAINED;
                for (int i = 0; i < q.size(); i++) {
                    Violation v = firstViolation(q.get(i), e, path + "[" + i + "]");
                    if (v != null) {
                        return v;
                    }
                }
            }
            default -> {
            }
        }
        return null;
    }

    private static String range(long v, Constraints c) {
        int f = c.flags();
        if ((f & Constraints.EXTENSIBLE) != 0) {
            return null;
        }
        if ((f & Constraints.CONSTRAINED) != 0 && (v < c.lowerBound() || v > c.upperBound())) {
            return "INTEGER " + v + " outside " + c.lowerBound() + ".." + c.upperBound();
        }
        if ((f & Constraints.SEMI_CONSTRAINED) != 0 && v < c.lowerBound()) {
            return "INTEGER " + v + " below " + c.lowerBound();
        }
        return null;
    }

    private static String rangeUnsigned(long v, Constraints c) {
        int f = c.flags();
        if ((f & Constraints.EXTENSIBLE) != 0) {
            return null;
        }
        boolean below = Long.compareUnsigned(v, c.lowerU64()) < 0;
        if ((f & Constraints.CONSTRAINED) != 0 && (below || Long.compareUnsigned(v, c.upperU64()) > 0)) {
            return "INTEGER " + Long.toUnsignedString(v) + " outside " + Long.toUnsignedString(c.lowerU64())
                    + ".." + Long.toUnsignedString(c.upperU64());
        }
        if ((f & Constraints.SEMI_CONSTRAINED) != 0 && below) {
            return "INTEGER " + Long.toUnsignedString(v) + " below " + Long.toUnsignedString(c.lowerU64());
        }
        return null;
    }

    private static String realRange(double v, Constraints c) {
        int f = c.flags();
        if ((f & Constraints.REAL_RANGE) == 0 || (f & Constraints.EXTENSIBLE) != 0) {
            return null;
        }
        boolean lowOpen = (f & Constraints.REAL_LOWER_OPEN) != 0;
        boolean highOpen = (f & Constraints.REAL_UPPER_OPEN) != 0;
        if (Double.isNaN(v) || v < c.realLower() || (lowOpen && v == c.realLower())
                || v > c.realUpper() || (highOpen && v == c.realUpper())) {
            return "REAL " + v + " outside " + c.realLower() + (lowOpen ? "<" : "") + ".."
                    + (highOpen ? "<" : "") + c.realUpper();
        }
        return null;
    }

    /** A SIZE constraint on a count {@code n}; {@code namedBits} keeps only the upper bound. */
    private static String size(String what, long n, Constraints c, boolean namedBits) {
        int f = c.flags();
        if ((f & Constraints.EXTENSIBLE) != 0) {
            return null;
        }
        if ((f & Constraints.SIZE_LOWER_BOUND) != 0 && !namedBits && n < c.sizeLower()) {
            return what + " size " + n + " below SIZE(" + c.sizeLower() + "..MAX)";
        }
        if ((f & Constraints.SIZE_CONSTRAINED) != 0
                && ((!namedBits && n < c.sizeLower()) || n > c.sizeUpper())) {
            return what + " size " + n + " outside SIZE(" + c.sizeLower() + ".." + c.sizeUpper() + ")";
        }
        return null;
    }

    /**
     * A NamedBitList value is padded up to the lower bound when sent
     * (X.691 §15.3), so only its significant bits count, against the upper
     * bound alone.
     */
    private static String bits(Asn1BitString b, Constraints c) {
        if ((c.flags() & Constraints.NAMED_BITS) == 0) {
            return size("BIT STRING", b.bitCount(), c, false);
        }
        if ((c.flags() & Constraints.SIZE_LOWER_BOUND) != 0) {
            return null;
        }
        byte[] bytes = b.bytes();
        int sig = b.bitCount();
        while (sig > 0 && (bytes[(sig - 1) / 8] & (0x80 >>> ((sig - 1) % 8))) == 0) {
            sig--;
        }
        return size("BIT STRING", sig, c, true);
    }

    private static String chars(Asn1CharString s, Constraints c) {
        byte[] octets = s.octets();
        String v = size(s.xerElementName(), octets.length, c, false);
        if (v != null || c.encodeTable() == null) {
            return v;
        }
        char[] table = c.encodeTable();
        for (byte o : octets) {
            if (table[o & 0xFF] == 0xFFFF) {
                return s.xerElementName() + " character " + (o & 0xFF) + " outside its permitted alphabet";
            }
        }
        return null;
    }
}
