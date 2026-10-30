package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * REAL contents octets (X.690 §8.5): a {@code DOUBLE} in the binary form
 * with the fewest octets, a {@code BINARY} or {@code DECIMAL} value in its
 * CER/DER form (X.690 §11.3). Decode accepts every form: binary in bases
 * 2, 8 and 16, decimal NR1–NR3, and the special values.
 */
public final class BerReal {
    private BerReal() {
    }

    /** Contents octets of {@code v}. */
    public static byte[] encode(Asn1Real v) {
        ByteSink out = new ByteSink();
        Asn1Real.Exact x = v.exact();
        if (x == null) {
            encodeDouble(out, v.value());
        } else if (x.storage() == Asn1Real.Storage.DECIMAL) {
            // NR3 (X.690 §11.3.2): [-]digits.E<exp>, exponent "+0" when zero.
            out.write(0x03);
            if (x.negative()) {
                out.write('-');
            }
            out.write(x.mantissa());
            out.write(".E".getBytes(StandardCharsets.US_ASCII));
            out.write((x.exponent() == 0 ? "+0" : Long.toString(x.exponent())).getBytes(StandardCharsets.US_ASCII));
        } else {
            // Binary, base 2, F = 0, odd mantissa, fewest octets (X.690 §11.3.1).
            byte[] exp = BerPrimitive.encodeInteger(x.exponent());
            int info = 0x80 | (x.negative() ? 0x40 : 0);
            if (exp.length <= 3) {
                out.write(info | (exp.length - 1));
            } else {
                out.write(info | 0x03);
                out.write(exp.length);
            }
            out.write(exp);
            out.write(x.mantissa());
        }
        return out.toByteArray();
    }

    /**
     * A double (X.690 §8.5): empty for plus zero, one octet for the special
     * values and minus zero (§8.5.9), otherwise base 2 with the trailing zero
     * bits of the mantissa moved into the exponent.
     */
    private static void encodeDouble(ByteSink out, double value) {
        if (value == 0.0) {
            if (Double.doubleToRawLongBits(value) < 0) {
                out.write(0x43);
            }
            return;
        }
        if (Double.isInfinite(value)) {
            out.write(value > 0 ? 0x40 : 0x41);
            return;
        }
        if (Double.isNaN(value)) {
            out.write(0x42);
            return;
        }
        long bits = Double.doubleToRawLongBits(value);
        int info = 0x80 | (bits < 0 ? 0x40 : 0);
        int biased = (int) ((bits >>> 52) & 0x7FF);
        long m = bits & 0x000F_FFFF_FFFF_FFFFL;
        int e;
        if (biased == 0) {
            e = -1074; // subnormal: no implicit leading 1
        } else {
            m |= 1L << 52;
            e = biased - 1023 - 52;
        }
        int tz = Long.numberOfTrailingZeros(m);
        m >>>= tz;
        e += tz;
        byte[] exp = BerPrimitive.encodeInteger(e);
        out.write(info | (exp.length - 1));
        out.write(exp);
        int mlen = (64 - Long.numberOfLeadingZeros(m) + 7) / 8;
        for (int i = mlen - 1; i >= 0; i--) {
            out.write((int) (m >>> (8 * i)));
        }
    }

    /**
     * Decodes REAL contents octets: {@code DOUBLE} when a double holds the
     * value exactly, {@code BINARY} for any other binary-form value,
     * {@code DECIMAL} for the decimal form. A reserved or malformed encoding,
     * or an exponent beyond 56 bits (binary) or 64 bits (decimal), is an error.
     *
     * @param pos the TLV's position, for the error
     * @see "X.690 §8.5.2 plus zero, §8.5.7 binary form (exponent formats a–d of
     *      §8.5.7.4, bases 2/8/16 of §8.5.7.2, unnormalized mantissa of §8.5.7.5
     *      NOTE 1), §8.5.8 decimal form, §8.5.9 special values"
     */
    public static Asn1Real decode(byte[] v, int pos) {
        if (v.length == 0) {
            return new Asn1Real(0.0);
        }
        int info = v[0] & 0xFF;
        if ((info & 0xC0) == 0x40) {
            if (v.length != 1) {
                throw error("special value with extra contents octets", pos);
            }
            return switch (info) {
                case 0x40 -> new Asn1Real(Double.POSITIVE_INFINITY);
                case 0x41 -> new Asn1Real(Double.NEGATIVE_INFINITY);
                case 0x42 -> new Asn1Real(Double.NaN);
                case 0x43 -> new Asn1Real(-0.0);
                default -> throw error("reserved special value", pos);
            };
        }
        if ((info & 0x80) == 0) {
            int form = info & 0x3F;
            if (form < 1 || form > 3) {
                throw error("reserved decimal number representation", pos);
            }
            return fromDecimal(form, v, 1, pos);
        }
        boolean negative = (info & 0x40) != 0;
        // B' = 2, 8 or 16: one, three or four binary digits per exponent step.
        int log2Base = switch ((info >> 4) & 0x03) {
            case 0 -> 1;
            case 1 -> 3;
            case 2 -> 4;
            default -> throw error("reserved base", pos);
        };
        int scaling = (info >> 2) & 0x03;
        int i = 1;
        int expLen;
        if ((info & 0x03) == 0x03) {
            if (i >= v.length) {
                throw error("truncated exponent length", pos);
            }
            expLen = v[i++] & 0xFF;
            if (expLen == 0) {
                throw error("exponent length 0", pos);
            }
        } else {
            expLen = (info & 0x03) + 1;
        }
        if (v.length - i < expLen) {
            throw error("truncated exponent", pos);
        }
        int expStart = i;
        int mStart = i + expLen;
        while (mStart < v.length && v[mStart] == 0) {
            mStart++;
        }
        if (mStart == v.length) {
            return new Asn1Real(negative ? -0.0 : 0.0);
        }
        // Two's-complement exponent; redundant sign octets carry no value.
        int sign = (v[expStart] & 0x80) != 0 ? 0xFF : 0x00;
        int k = expStart;
        while (k + 1 < expStart + expLen && (v[k] & 0xFF) == sign && (v[k + 1] & 0x80) == (sign & 0x80)) {
            k++;
        }
        if (expStart + expLen - k > 7) {
            throw error("binary exponent beyond 56 bits", pos);
        }
        long e = sign != 0 ? -1 : 0;
        for (int j = k; j < expStart + expLen; j++) {
            e = (e << 8) | (v[j] & 0xFF);
        }
        long e2 = e * log2Base + scaling;
        int nLen = v.length - mStart;
        if (nLen <= 8) {
            // Common case, a value a double holds exactly: at most 53 significant
            // bits and a scale inside the double range (normal or subnormal).
            long m = 0;
            for (int j = mStart; j < v.length; j++) {
                m = (m << 8) | (v[j] & 0xFF);
            }
            int tz = Long.numberOfTrailingZeros(m);
            m >>>= tz;
            long width = 64 - Long.numberOfLeadingZeros(m);
            long lsb = e2 + tz;
            long msb = lsb + width - 1;
            if (width <= 53 && lsb >= -1074 && msb <= 1023) {
                long bits = msb >= -1022
                        ? ((msb + 1023) << 52) | ((m << (53 - width)) & ((1L << 52) - 1))
                        : m << (lsb + 1074); // subnormal: unit 2^-1074
                if (negative) {
                    bits |= 1L << 63;
                }
                return new Asn1Real(Double.longBitsToDouble(bits));
            }
        }
        return Asn1Real.binary(negative, Arrays.copyOfRange(v, mStart, v.length), e2);
    }

    /**
     * Parses an ISO 6093 number (X.690 §8.5.8) in NR {@code form} 1, 2 or 3
     * from {@code v[from..]}: leading spaces, an optional sign, digits; NR2
     * and NR3 add a decimal mark ({@code .} or {@code ,}); NR3 adds
     * {@code E}/{@code e}, an optional sign and exponent digits (the decimal
     * mark is optional in NR3). Anything else is an error.
     */
    private static Asn1Real fromDecimal(int form, byte[] v, int from, int pos) {
        int i = from;
        while (i < v.length && v[i] == ' ') {
            i++;
        }
        boolean negative = false;
        if (i < v.length && (v[i] == '+' || v[i] == '-')) {
            negative = v[i] == '-';
            i++;
        }
        StringBuilder digits = new StringBuilder();
        int fracLen = 0;
        boolean mark = false;
        for (; i < v.length; i++) {
            int c = v[i];
            if (c >= '0' && c <= '9') {
                digits.append((char) c);
                if (mark) {
                    fracLen++;
                }
            } else if ((c == '.' || c == ',') && !mark && form >= 2) {
                mark = true;
            } else {
                break;
            }
        }
        if (digits.isEmpty() || (form == 2 && !mark)) {
            throw error("malformed ISO 6093 number", pos);
        }
        long exponent = 0;
        if (form == 3) {
            if (i >= v.length || (v[i] != 'E' && v[i] != 'e')) {
                throw error("malformed ISO 6093 number", pos);
            }
            i++;
            int expStart = i;
            if (i < v.length && (v[i] == '+' || v[i] == '-')) {
                i++;
            }
            int digitStart = i;
            while (i < v.length && v[i] >= '0' && v[i] <= '9') {
                i++;
            }
            if (i == digitStart) {
                throw error("malformed ISO 6093 number", pos);
            }
            try {
                exponent = Long.parseLong(new String(v, expStart, i - expStart, StandardCharsets.US_ASCII));
            } catch (NumberFormatException ex) {
                throw error("decimal exponent beyond 64 bits", pos);
            }
        }
        if (i != v.length) {
            throw error("malformed ISO 6093 number", pos);
        }
        try {
            return Asn1Real.decimal(negative, digits.toString(), Math.subtractExact(exponent, fracLen));
        } catch (ArithmeticException ex) {
            throw error("decimal exponent beyond 64 bits", pos);
        }
    }

    private static DecodeException error(String what, int pos) {
        return new DecodeException("REAL: " + what, pos);
    }
}
