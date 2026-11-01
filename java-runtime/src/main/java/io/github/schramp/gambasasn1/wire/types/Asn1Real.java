package io.github.schramp.gambasasn1.wire.types;

import java.util.Arrays;
import java.util.Objects;

/**
 * REAL (X.680 §21): an abstract value mantissa × base^exponent with base 2
 * or 10, in one of three {@link Storage} classes. {@link #value()} is exact
 * for {@code DOUBLE} and the nearest double (±∞ or ±0 beyond the double
 * range) otherwise. Same model as the C++ {@code asn1::Real} and the Rust
 * {@code Real}.
 */
public final class Asn1Real implements Asn1Primitive {

    /** Storage class of a value. */
    public enum Storage {
        /** An IEEE 754 double, base 2. */
        DOUBLE,
        /** Base 2 with an arbitrary mantissa: a value a double cannot hold exactly. */
        BINARY,
        /** Base 10 with an arbitrary digit string: the BER decimal form. */
        DECIMAL
    }

    /**
     * Exact components of a {@code BINARY} or {@code DECIMAL} value:
     * (negative ? −1 : 1) × mantissa × base^exponent. {@code BINARY}: the
     * mantissa is big-endian octets, odd (X.690 §11.3.1). {@code DECIMAL}:
     * ASCII digits, neither first nor last digit 0 (X.690 §11.3.2.4).
     * Unique per abstract value. The mantissa array is not copied and must
     * not be changed.
     */
    public record Exact(Storage storage, boolean negative, byte[] mantissa, long exponent) {
        @Override
        public boolean equals(Object o) {
            return o instanceof Exact x && x.storage == storage && x.negative == negative
                    && x.exponent == exponent && Arrays.equals(x.mantissa, mantissa);
        }

        @Override
        public int hashCode() {
            return Objects.hash(storage, negative, exponent, Arrays.hashCode(mantissa));
        }
    }

    private double value;
    private Exact exact;

    public Asn1Real() {
    }

    /** A base-2 {@code DOUBLE} value. */
    public Asn1Real(double value) {
        this.value = value;
    }

    private Asn1Real(double value, Exact exact) {
        this.value = value;
        this.exact = exact;
    }

    /**
     * A base-2 value S × N × 2^{@code exponent} ({@code mantissa} = N,
     * big-endian, leading zero octets allowed; {@code exponent} of N's least
     * significant bit). A value a double holds exactly becomes
     * {@code DOUBLE}, any other {@code BINARY}; a zero mantissa gives ±0.
     *
     * @see "X.690 §8.5.7"
     */
    public static Asn1Real binary(boolean negative, byte[] mantissa, long exponent) {
        int lo = 0;
        while (lo < mantissa.length && mantissa[lo] == 0) {
            lo++;
        }
        if (lo == mantissa.length) {
            return new Asn1Real(negative ? -0.0 : 0.0);
        }
        // Odd mantissa (X.690 §11.3.1): trailing zero bits move into the exponent.
        int hi = mantissa.length;
        while (mantissa[hi - 1] == 0) {
            hi--;
        }
        int zeroOctets = mantissa.length - hi;
        int r = Integer.numberOfTrailingZeros(mantissa[hi - 1] & 0xFF);
        byte[] out = new byte[hi - lo];
        int carry = 0;
        for (int i = lo; i < hi; i++) {
            int b = mantissa[i] & 0xFF;
            out[i - lo] = (byte) (r != 0 ? (b >>> r) | carry : b);
            carry = r != 0 ? (b << (8 - r)) & 0xFF : 0;
        }
        if (out.length > 1 && out[0] == 0) {
            out = Arrays.copyOfRange(out, 1, out.length);
        }
        long e = exponent + zeroOctets * 8L + r;
        Rounded rounded = fromBinary(negative, out, e);
        if (rounded.exact()) {
            return new Asn1Real(rounded.value());
        }
        return new Asn1Real(rounded.value(), new Exact(Storage.BINARY, negative, out, e));
    }

    /**
     * A base-10 {@code DECIMAL} value S × {@code digits} × 10^{@code exponent}
     * ({@code exponent} of the last digit; leading and trailing zeros
     * allowed). All-zero digits give ±0 ({@code DOUBLE}).
     *
     * @see "X.680 §21.5"
     */
    public static Asn1Real decimal(boolean negative, String digits, long exponent) {
        int lo = 0;
        while (lo < digits.length() && digits.charAt(lo) == '0') {
            lo++;
        }
        if (lo == digits.length()) {
            return new Asn1Real(negative ? -0.0 : 0.0);
        }
        int hi = digits.length();
        while (digits.charAt(hi - 1) == '0') {
            hi--;
        }
        String trimmed = digits.substring(lo, hi);
        long e = saturatingAdd(exponent, digits.length() - hi);
        double v = Double.parseDouble((negative ? "-" : "") + trimmed + "e" + e);
        return new Asn1Real(v, new Exact(Storage.DECIMAL, negative,
                trimmed.getBytes(java.nio.charset.StandardCharsets.US_ASCII), e));
    }

    /** The value as a double: exact for {@code DOUBLE}, the nearest double otherwise. */
    public double value() {
        return value;
    }

    /** Sets a base-2 {@code DOUBLE} value. */
    public void set(double value) {
        this.value = value;
        this.exact = null;
    }

    /** Takes {@code other}'s value, in its storage class. */
    public void set(Asn1Real other) {
        this.value = other.value;
        this.exact = other.exact;
    }

    public Storage storage() {
        return exact == null ? Storage.DOUBLE : exact.storage();
    }

    /** 10 for {@code DECIMAL}, 2 otherwise. */
    public int base() {
        return storage() == Storage.DECIMAL ? 10 : 2;
    }

    /** Exact components; {@code null} for {@code DOUBLE}. */
    public Exact exact() {
        return exact;
    }

    /**
     * Numeric equality at double precision, ignoring the base: compares
     * {@link #value()}, with −0 equal to +0 and NaN unequal to itself.
     */
    public boolean numericallyEqual(Asn1Real other) {
        return value == other.value;
    }

    @Override
    public String xerElementName() {
        return "REAL";
    }

    /**
     * Equality of REAL abstract values: storage class (base) and exact
     * components must match. For {@code DOUBLE}, minus zero and plus zero
     * differ and NOT-A-NUMBER equals itself, since X.690 §8.5.9 gives each
     * its own encoding. X.680 §21.5 NOTE 1: base-2 and base-10 values are
     * distinct.
     */
    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Asn1Real r)) {
            return false;
        }
        if (exact != null || r.exact != null) {
            return Objects.equals(exact, r.exact);
        }
        return Double.doubleToLongBits(value) == Double.doubleToLongBits(r.value);
    }

    @Override
    public int hashCode() {
        return exact != null ? exact.hashCode() : Long.hashCode(Double.doubleToLongBits(value));
    }

    @Override
    public String toString() {
        if (exact == null) {
            return Double.toString(value);
        }
        if (exact.storage() == Storage.DECIMAL) {
            String digits = new String(exact.mantissa(), java.nio.charset.StandardCharsets.US_ASCII);
            return (exact.negative() ? "-" : "") + digits + "E" + exact.exponent();
        }
        return (exact.negative() ? "-" : "") + "0x" + java.util.HexFormat.of().formatHex(exact.mantissa())
                + "*2^" + exact.exponent();
    }

    private static long saturatingAdd(long a, long b) {
        long s = a + b;
        return ((a ^ s) & (b ^ s)) < 0 ? (a < 0 ? Long.MIN_VALUE : Long.MAX_VALUE) : s;
    }

    private record Rounded(double value, boolean exact) {
    }

    /** Bit {@code i} (0 = least significant) of the unsigned big-endian integer {@code n}. */
    private static boolean bitAt(byte[] n, long i) {
        return ((n[n.length - 1 - (int) (i / 8)] >> (i % 8)) & 1) != 0;
    }

    /**
     * S × N × 2^{@code e2} to the nearest double, rounding half to even,
     * and whether that is exact. {@code n} is N, big-endian, first octet
     * non-zero; {@code e2} is the exponent of N's least significant bit. A
     * magnitude beyond the double range gives ±∞ or ±0, inexact.
     *
     * @see "X.690 §8.5.7; IEEE 754 round-to-nearest-even"
     */
    private static Rounded fromBinary(boolean negative, byte[] n, long e2) {
        double inf = negative ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
        double zero = negative ? -0.0 : 0.0;
        long bitsN = (n.length - 1L) * 8 + (32 - Integer.numberOfLeadingZeros(n[0] & 0xFF));
        long eMsb = e2 + bitsN - 1;
        if (eMsb > 1023) {
            return new Rounded(inf, false);
        }
        if (eMsb < -1075) {
            // Below half of 2^-1074: rounds to zero.
            return new Rounded(zero, false);
        }
        // Unit of the result's last significand bit: 53 significant bits for a
        // normal double, fewer below 2^-1022 (subnormal, unit 2^-1074).
        long unit = Math.max(eMsb - 52, -1074);
        long shift = unit - e2;
        long kept = 0;
        boolean exact = true;
        if (shift <= 0) {
            for (long i = bitsN - 1; i >= 0; i--) {
                kept = (kept << 1) | (bitAt(n, i) ? 1 : 0);
            }
            kept <<= -shift;
        } else {
            for (long i = bitsN - 1; i >= shift; i--) {
                kept = (kept << 1) | (bitAt(n, i) ? 1 : 0);
            }
            boolean round = bitAt(n, shift - 1);
            boolean sticky = false;
            for (long i = 0; i < shift - 1 && !sticky; i++) {
                sticky = bitAt(n, i);
            }
            exact = !round && !sticky;
            if (round && (sticky || (kept & 1) != 0)) {
                kept++;
            }
        }
        if (kept == 1L << 53) {
            kept >>>= 1;
            unit++;
        }
        if (kept == 0) {
            return new Rounded(zero, false);
        }
        long bits;
        if (kept < 1L << 52) {
            bits = kept; // subnormal: unit is 2^-1074
        } else {
            long biased = unit + 52 + 1023;
            if (biased >= 2047) {
                return new Rounded(inf, false);
            }
            bits = (biased << 52) | (kept & ((1L << 52) - 1));
        }
        if (negative) {
            bits |= 1L << 63;
        }
        return new Rounded(Double.longBitsToDouble(bits), exact);
    }
}
