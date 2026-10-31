package io.github.schramp.gambasasn1.wire.jer;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.spec.EnumEntry;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.EnumSpec;
import io.github.schramp.gambasasn1.wire.types.Asn1Any;
import io.github.schramp.gambasasn1.wire.types.Asn1Arcs;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1BmpString;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1CharString;
import io.github.schramp.gambasasn1.wire.types.Asn1GeneralString;
import io.github.schramp.gambasasn1.wire.types.Asn1GraphicString;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1T61String;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import io.github.schramp.gambasasn1.wire.types.Asn1UniversalString;
import io.github.schramp.gambasasn1.wire.types.Asn1VideotexString;
import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * JER values of the builtin leaf types (X.697 §8-§23), in the text the C++
 * and Rust runtimes write: one switch over the builtin wrappers. A value's
 * own constraints pick the BIT STRING and REAL forms.
 */
public final class JerPrimitive {
    /** The text forms {@code strtod} accepts for a REAL number, without hex floats or words. */
    private static final Pattern DECIMAL = Pattern.compile("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?");

    private JerPrimitive() {
    }

    /**
     * Writes {@code p} as one JSON value.
     *
     * @param c its own constraints
     */
    public static void encode(Asn1Primitive p, Constraints c, JerWriter w) {
        switch (p) {
            case Asn1Boolean b -> w.ascii(b.get() ? "true" : "false");
            case Asn1Null n -> w.ascii("null");
            case Asn1Integer i -> w.ascii(Long.toString(i.get()));
            case Asn1UInteger u -> w.ascii(Long.toUnsignedString(u.get()));
            case Asn1Real r -> encodeReal(r, c, w);
            case Asn1OctetString o -> w.hexString(o.get());
            case Asn1BitString b -> encodeBits(b, c, w);
            case Asn1Arcs a -> w.string(a.toString());
            case Asn1Any a -> w.hexString(a.get());
            // Not plain text: written as hex, as for an OCTET STRING.
            case Asn1T61String s -> w.hexString(s.octets());
            case Asn1VideotexString s -> w.hexString(s.octets());
            case Asn1GraphicString s -> w.hexString(s.octets());
            case Asn1GeneralString s -> w.hexString(s.octets());
            case Asn1BmpString s -> w.string(Asn1CharString.wideToUtf8(s.octets(), 2));
            case Asn1UniversalString s -> w.string(Asn1CharString.wideToUtf8(s.octets(), 4));
            case Asn1CharString s -> w.string(s.octets());
            default -> throw new IllegalStateException("no JER form for " + p.getClass().getName());
        }
    }

    /**
     * Decodes one JSON value into {@code p}.
     *
     * @param c its own constraints
     */
    public static void decode(Asn1Primitive p, Constraints c, JerReader r) {
        int at = r.position();
        switch (p) {
            case Asn1Boolean b -> b.set(decodeBoolean(r));
            case Asn1Null n -> {
                String t = r.readToken();
                if (!t.equals("null")) {
                    throw new DecodeException("JER: expected null, got: " + t, at);
                }
            }
            case Asn1Integer i -> i.set(parseLong(r, false));
            case Asn1UInteger u -> u.set(parseLong(r, true));
            case Asn1Real real -> real.set(decodeReal(r, c));
            case Asn1OctetString o -> o.set(hexPairs(r.readString()));
            case Asn1BitString b -> decodeBits(b, c, r);
            case Asn1Arcs a -> a.set(Asn1Arcs.parseDotted(r.readStringText()));
            case Asn1Any a -> a.set(hexPairs(r.readString()));
            case Asn1T61String s -> s.setOctets(hexPairs(r.readString()));
            case Asn1VideotexString s -> s.setOctets(hexPairs(r.readString()));
            case Asn1GraphicString s -> s.setOctets(hexPairs(r.readString()));
            case Asn1GeneralString s -> s.setOctets(hexPairs(r.readString()));
            case Asn1BmpString s -> s.setOctets(Asn1CharString.utf8ToWide(r.readString(), 2));
            case Asn1UniversalString s -> s.setOctets(Asn1CharString.utf8ToWide(r.readString(), 4));
            case Asn1CharString s -> s.setOctets(r.readString());
            default -> throw new DecodeException("JER: no JER form for " + p.getClass().getName(), at);
        }
    }

    /** An ENUMERATED value as its identifier; a value without one as its number (X.697 §20). */
    public static void encodeEnumerated(EnumSlot slot, EnumSpec spec, JerWriter w) {
        long v = slot.enumGet();
        for (EnumEntry e : spec.entries()) {
            if (e.value() == v) {
                w.string(e.name());
                return;
            }
        }
        w.ascii(Long.toString(v));
    }

    /** Decode counterpart of {@link #encodeEnumerated}: an identifier, or a bare number. */
    public static void decodeEnumerated(EnumSlot slot, EnumSpec spec, JerReader r) {
        int at = r.position();
        long v;
        if (r.peek() == '"') {
            String name = r.readStringText();
            EnumEntry found = spec.entries().stream().filter(e -> e.name().equals(name)).findFirst()
                    .orElseThrow(() -> new DecodeException("JER: unknown enum value: " + name, at));
            v = found.value();
        } else {
            String t = r.readToken();
            try {
                v = Long.parseLong(t);
            } catch (NumberFormatException e) {
                throw new DecodeException("JER: invalid ENUMERATED: " + t, at);
            }
        }
        if (!slot.enumSet(v)) {
            throw new DecodeException("JER: value " + v + " is not an item of " + spec.name(), at);
        }
    }

    private static boolean decodeBoolean(JerReader r) {
        int at = r.position();
        String t = r.readToken();
        return switch (t) {
            case "true" -> true;
            case "false" -> false;
            default -> throw new DecodeException("JER: BOOLEAN expected true/false, got: " + t, at);
        };
    }

    private static long parseLong(JerReader r, boolean unsigned) {
        int at = r.position();
        String t = r.readToken();
        try {
            return unsigned ? Long.parseUnsignedLong(t) : Long.parseLong(t);
        } catch (NumberFormatException e) {
            throw new DecodeException("JER: invalid INTEGER: " + t, at);
        }
    }

    /**
     * A {@code DECIMAL} value as its exact digits, bare when the JER-visible
     * base constraint admits only 10 and as {@code {"base10Value":n}}
     * otherwise; the special values as the strings {@code "NaN"},
     * {@code "INF"}, {@code "-INF"}, {@code "-0"}; any other value as the
     * shortest number that converts back to the same double.
     *
     * @see "X.697 §23"
     */
    private static void encodeReal(Asn1Real r, Constraints c, JerWriter w) {
        Asn1Real.Exact x = r.exact();
        if (x != null && x.storage() == Asn1Real.Storage.DECIMAL) {
            String text = (x.negative() ? "-" : "") + new String(x.mantissa(), StandardCharsets.US_ASCII)
                    + (x.exponent() != 0 ? "E" + x.exponent() : "");
            w.ascii((c.flags() & Constraints.REAL_BASE_10) != 0 ? text : "{\"base10Value\":" + text + "}");
            return;
        }
        double d = r.value();
        if (Double.isNaN(d)) {
            w.string("NaN");
        } else if (Double.isInfinite(d)) {
            w.string(d > 0 ? "INF" : "-INF");
        } else if (d == 0.0) {
            if (1 / d < 0) {
                w.string("-0");
            } else {
                w.ascii("0");
            }
        } else {
            w.ascii(formatReal(d));
        }
    }

    /**
     * The shortest digits that convert back to {@code d}, in plain decimal
     * notation when the decimal exponent is in [-4, 15) and as
     * {@code d.dddE<exp>} otherwise: the C++ and Rust runtimes' rule.
     */
    static String formatReal(double d) {
        BigDecimal b = new BigDecimal(Double.toString(Math.abs(d))).stripTrailingZeros();
        if (b.precision() == 2) {
            // Double.toString writes at least two digits; a one-digit number may also convert back.
            BigDecimal exact = new BigDecimal(Math.abs(d));
            BigDecimal best = null;
            for (RoundingMode mode : new RoundingMode[] {RoundingMode.FLOOR, RoundingMode.CEILING}) {
                BigDecimal one = b.round(new MathContext(1, mode));
                if (Double.parseDouble(one.toString()) == Math.abs(d)
                        && (best == null || one.subtract(exact).abs().compareTo(best.subtract(exact).abs()) < 0)) {
                    best = one;
                }
            }
            if (best != null) {
                b = best.stripTrailingZeros();
            }
        }
        String digits = b.unscaledValue().toString();
        int exp = digits.length() - 1 - b.scale();
        StringBuilder out = new StringBuilder(d < 0 ? "-" : "");
        if (exp >= -4 && exp < 15) {
            if (exp < 0) {
                out.append("0.").append("0".repeat(-exp - 1)).append(digits);
            } else if (digits.length() <= exp + 1) {
                out.append(digits).append("0".repeat(exp + 1 - digits.length()));
            } else {
                out.append(digits, 0, exp + 1).append('.').append(digits, exp + 1, digits.length());
            }
        } else {
            out.append(digits.charAt(0));
            if (digits.length() > 1) {
                out.append('.').append(digits, 1, digits.length());
            }
            out.append('E').append(exp);
        }
        return out.toString();
    }

    /**
     * A JSON number, a special-value string (X.697 §23.2) or
     * {@code {"base10Value":n}} (§23.4), which gives an exact
     * {@code DECIMAL} value; a number also does when the base constraint
     * admits only 10 (§23.1.4).
     */
    private static Asn1Real decodeReal(JerReader r, Constraints c) {
        int at = r.position();
        if (r.peek() == '{') {
            r.expect('{');
            String key = r.readStringText();
            if (!key.equals("base10Value")) {
                throw new DecodeException("JER: unexpected REAL object member: " + key, at);
            }
            r.expect(':');
            Asn1Real v = parseDecimal(r.readToken(), at);
            r.expect('}');
            return v;
        }
        if (r.peek() == '"') {
            String s = r.readStringText();
            return new Asn1Real(switch (s) {
                case "NaN" -> Double.NaN;
                case "INF" -> Double.POSITIVE_INFINITY;
                case "-INF" -> Double.NEGATIVE_INFINITY;
                case "-0" -> -0.0;
                default -> {
                    if (!DECIMAL.matcher(s).matches()) {
                        throw new DecodeException("JER: invalid REAL string: " + s, at);
                    }
                    yield Double.parseDouble(s);
                }
            });
        }
        String t = r.readToken();
        if ((c.flags() & Constraints.REAL_BASE_10) != 0) {
            return parseDecimal(t, at);
        }
        if (!DECIMAL.matcher(t).matches()) {
            throw new DecodeException("JER: invalid REAL: " + t, at);
        }
        return new Asn1Real(Double.parseDouble(t));
    }

    /** {@code [+-]digits[.digits][(e|E)[+-]digits]} as an exact base-10 value. */
    private static Asn1Real parseDecimal(String t, int at) {
        int i = 0;
        boolean negative = false;
        if (i < t.length() && (t.charAt(i) == '+' || t.charAt(i) == '-')) {
            negative = t.charAt(i++) == '-';
        }
        StringBuilder digits = new StringBuilder();
        while (i < t.length() && Character.isDigit(t.charAt(i))) {
            digits.append(t.charAt(i++));
        }
        if (digits.isEmpty()) {
            throw new DecodeException("JER: malformed decimal number: " + t, at);
        }
        int fracLen = 0;
        if (i < t.length() && t.charAt(i) == '.') {
            i++;
            while (i < t.length() && Character.isDigit(t.charAt(i))) {
                digits.append(t.charAt(i++));
                fracLen++;
            }
        }
        long exponent = 0;
        if (i < t.length() && (t.charAt(i) == 'e' || t.charAt(i) == 'E')) {
            String e = t.substring(i + 1);
            if (!e.matches("[+-]?\\d+")) {
                throw new DecodeException("JER: malformed decimal number: " + t, at);
            }
            try {
                exponent = Long.parseLong(e);
            } catch (NumberFormatException ex) {
                throw new DecodeException("JER: decimal exponent beyond 64 bits: " + t, at);
            }
            i = t.length();
        }
        if (i != t.length()) {
            throw new DecodeException("JER: malformed decimal number: " + t, at);
        }
        try {
            return Asn1Real.decimal(negative, digits.toString(), Math.subtractExact(exponent, fracLen));
        } catch (ArithmeticException ex) {
            throw new DecodeException("JER: decimal exponent beyond 64 bits: " + t, at);
        }
    }

    /** The bit count of a fixed, non-extensible SIZE, which X.697 §16.3 writes as a bare hex string; -1 otherwise. */
    private static long fixedSize(Constraints c) {
        if ((c.flags() & Constraints.SIZE_CONSTRAINED) == 0 || (c.flags() & Constraints.EXTENSIBLE) != 0) {
            return -1;
        }
        return c.sizeLower() == c.sizeUpper() && c.sizeLower() >= 0 ? c.sizeLower() : -1;
    }

    /** A bare hex string for a value of the fixed size, {@code {"value":"HEX","length":N}} otherwise. */
    private static void encodeBits(Asn1BitString b, Constraints c, JerWriter w) {
        if (fixedSize(c) == b.bitCount()) {
            w.hexString(b.bytes());
            return;
        }
        w.ascii("{\"value\":").hexString(b.bytes()).ascii(",\"length\":" + b.bitCount() + "}");
    }

    private static void decodeBits(Asn1BitString b, Constraints c, JerReader r) {
        int at = r.position();
        int first = r.peek();
        if (first == '"') {
            long n = fixedSize(c);
            if (n < 0) {
                throw new DecodeException("JER: BIT STRING is not fixed-size; expected {\"value\",\"length\"}", at);
            }
            byte[] bytes = hexPairs(r.readString());
            int byteCount = (int) ((n + 7) / 8);
            if (bytes.length != byteCount) {
                throw new DecodeException("JER: fixed-size BIT STRING: expected " + byteCount + " hex octets", at);
            }
            b.set(masked(bytes, (int) (byteCount * 8L - n)), (int) (byteCount * 8L - n));
            return;
        }
        if (first == '[') {
            // The named-bit list form carries no bit table here: the value is consumed and left empty.
            r.skipValue();
            b.set(new byte[0], 0);
            return;
        }
        r.expect('{');
        byte[] hex = new byte[0];
        long bits = 0;
        for (int k = 0; k < 2; k++) {
            String key = r.readStringText();
            r.expect(':');
            switch (key) {
                case "value" -> hex = hexPairs(r.readString());
                case "length" -> {
                    String t = r.readToken();
                    try {
                        bits = Long.parseLong(t);
                    } catch (NumberFormatException e) {
                        throw new DecodeException("JER: invalid BIT STRING length: " + t, at);
                    }
                }
                default -> r.skipValue();
            }
            r.consumeIf(',');
        }
        r.expect('}');
        if (bits < 0 || bits > 8L * Integer.MAX_VALUE - 7) {
            throw new DecodeException("JER: invalid BIT STRING length: " + bits, at);
        }
        int byteCount = (int) ((bits + 7) / 8);
        int unused = (int) (byteCount * 8L - bits);
        b.set(masked(Arrays.copyOf(hex, byteCount), unused), unused);
    }

    private static byte[] masked(byte[] bytes, int unused) {
        if (bytes.length > 0 && unused > 0) {
            bytes[bytes.length - 1] &= (byte) (0xFF << unused);
        }
        return bytes;
    }

    /** Hex pairs, whitespace allowed between them; stops at the first thing that is not a pair. */
    static byte[] hexPairs(byte[] text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(text.length / 2);
        int hi = -1;
        for (byte t : text) {
            if (t == ' ' || t == '\t' || t == '\n' || t == '\r') {
                continue;
            }
            int d = Character.digit(t, 16);
            if (d < 0) {
                break;
            }
            if (hi < 0) {
                hi = d;
            } else {
                out.write(hi << 4 | d);
                hi = -1;
            }
        }
        return out.toByteArray();
    }
}
