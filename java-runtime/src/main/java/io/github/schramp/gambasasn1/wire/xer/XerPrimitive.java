package io.github.schramp.gambasasn1.wire.xer;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.XerInstruction;
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
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * XER content of the builtin leaf values (X.693 §8, BASIC-XER), in the
 * exact text asn1c writes: one switch over the builtin wrappers. The
 * element around the content is the caller's.
 */
public final class XerPrimitive {
    /** The text forms {@code strtod} accepts for a REAL realnumber, without hex floats. */
    private static final Pattern DECIMAL = Pattern.compile("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?");

    private XerPrimitive() {
    }

    /**
     * Writes the content of {@code p}.
     *
     * @param depth the level of the element around the content; BIT STRING
     *              lines are indented one deeper
     */
    public static void encode(Asn1Primitive p, XerWriter w, int depth) {
        switch (p) {
            case Asn1Boolean b -> w.empty(b.get() ? "true" : "false");
            case Asn1Null n -> {
            }
            case Asn1Integer i -> w.ascii(Long.toString(i.get()));
            case Asn1UInteger u -> w.ascii(Long.toUnsignedString(u.get()));
            case Asn1Real r -> encodeReal(r, w);
            case Asn1OctetString o -> w.hex(o.get());
            case Asn1BitString b -> encodeBits(b, w, depth);
            case Asn1Arcs a -> w.ascii(a.toString());
            case Asn1Any a -> w.hex(a.get());
            // Not plain text: asn1c writes these as hex, as for an OCTET STRING.
            case Asn1T61String s -> w.hex(s.octets());
            case Asn1VideotexString s -> w.hex(s.octets());
            case Asn1GraphicString s -> w.hex(s.octets());
            case Asn1GeneralString s -> w.hex(s.octets());
            case Asn1BmpString s -> w.escaped(Asn1CharString.wideToUtf8(s.octets(), 2));
            case Asn1UniversalString s -> w.escaped(Asn1CharString.wideToUtf8(s.octets(), 4));
            case Asn1CharString s -> w.escaped(s.octets());
            default -> throw new IllegalStateException("no XER form for " + p.getClass().getName());
        }
    }

    /** Decodes the content at the cursor into {@code p}; the caller consumes the element around it. */
    public static void decode(Asn1Primitive p, XerReader r) {
        int at = r.position();
        switch (p) {
            case Asn1Boolean b -> b.set(decodeBoolean(r));
            case Asn1Null n -> r.skipWhitespace();
            case Asn1Integer i -> i.set(parse(r, at, "INTEGER", false));
            case Asn1UInteger u -> u.set(parse(r, at, "INTEGER", true));
            case Asn1Real real -> real.set(decodeReal(r));
            case Asn1OctetString o -> o.set(hexPairs(r.readText()));
            case Asn1BitString b -> decodeBits(b, r);
            case Asn1Arcs a -> a.set(Asn1Arcs.parseDotted(r.readTrimmedText()));
            case Asn1Any a -> a.set(hexPairs(r.readText()));
            case Asn1T61String s -> s.setOctets(hexPairs(r.readText()));
            case Asn1VideotexString s -> s.setOctets(hexPairs(r.readText()));
            case Asn1GraphicString s -> s.setOctets(hexPairs(r.readText()));
            case Asn1GeneralString s -> s.setOctets(hexPairs(r.readText()));
            case Asn1BmpString s -> s.setOctets(Asn1CharString.utf8ToWide(r.readText(), 2));
            case Asn1UniversalString s -> s.setOctets(Asn1CharString.utf8ToWide(r.readText(), 4));
            case Asn1CharString s -> s.setOctets(r.readText());
            default -> throw new DecodeException("XER: no XER form for " + p.getClass().getName(), at);
        }
    }

    private static long parse(XerReader r, int at, String what, boolean unsigned) {
        String t = r.readTrimmedText();
        try {
            return unsigned ? Long.parseUnsignedLong(t) : Long.parseLong(t);
        } catch (NumberFormatException e) {
            throw new DecodeException("XER: invalid " + what + " value: " + t, at);
        }
    }

    /** BASIC-XER {@code <true/>}/{@code <false/>}; lenient also accepts text (EXTENDED-XER §10). */
    private static boolean decodeBoolean(XerReader r) {
        int at = r.position();
        String text = r.readTrimmedText();
        if (!text.isEmpty()) {
            if (r.lenient() && (text.equals("true") || text.equals("false"))) {
                return text.equals("true");
            }
            throw new DecodeException("XER BOOLEAN: expected <true/> or <false/>", at);
        }
        XerReader.TagInfo t = r.consumeTag();
        if (t.selfClosing() && t.name().equals("true")) {
            return true;
        }
        if (t.selfClosing() && t.name().equals("false")) {
            return false;
        }
        throw new DecodeException("XER BOOLEAN: expected <true/> or <false/>", at);
    }

    /**
     * A {@code DECIMAL} value as its exact digits (an X.680 realnumber);
     * otherwise a special value element, {@code 0}/{@code -0}, or the
     * value at 15 decimals with trailing zeros dropped, as asn1c prints it
     * (C {@code %.15f}: the exact binary value, rounded half to even).
     *
     * @see "X.693 §17.9"
     */
    private static void encodeReal(Asn1Real r, XerWriter w) {
        Asn1Real.Exact x = r.exact();
        if (x != null && x.storage() == Asn1Real.Storage.DECIMAL) {
            w.ascii(x.negative() ? "-" : "").ascii(new String(x.mantissa(), StandardCharsets.US_ASCII));
            if (x.exponent() != 0) {
                w.ascii("E" + x.exponent());
            }
            return;
        }
        double d = r.value();
        if (Double.isNaN(d)) {
            w.empty("NOT-A-NUMBER");
        } else if (Double.isInfinite(d)) {
            w.empty(d > 0 ? "PLUS-INFINITY" : "MINUS-INFINITY");
        } else if (d == 0.0) {
            w.ascii(1 / d < 0 ? "-0" : "0");
        } else {
            String s = new BigDecimal(d).setScale(15, RoundingMode.HALF_EVEN).toPlainString();
            int dot = s.indexOf('.');
            int last = s.length() - 1;
            while (last > dot + 1 && s.charAt(last) == '0') {
                last--;
            }
            // %.15f keeps the sign of a value that rounds to zero; BigDecimal does not.
            w.ascii(d < 0 && s.charAt(0) != '-' ? "-" : "").ascii(s.substring(0, last + 1));
        }
    }

    private static double decodeReal(XerReader r) {
        int at = r.position();
        XerReader.TagInfo peek = r.peekTag();
        if (!peek.name().isEmpty() && !peek.closing()) {
            XerReader.TagInfo t = r.consumeTag();
            double d = switch (t.name()) {
                case "PLUS-INFINITY" -> Double.POSITIVE_INFINITY;
                case "MINUS-INFINITY" -> Double.NEGATIVE_INFINITY;
                case "NOT-A-NUMBER" -> Double.NaN;
                default -> throw new DecodeException("XER: unknown REAL special value: " + t.name(), at);
            };
            if (!t.selfClosing()) {
                r.consumeCloseTag(t.name());
            }
            return d;
        }
        String t = r.readTrimmedText();
        if (!DECIMAL.matcher(t).matches()) {
            throw new DecodeException("XER: invalid REAL value: " + t, at);
        }
        return Double.parseDouble(t);
    }

    /** {@code 0}/{@code 1} characters, 64 per line, each line one level deeper than the element. */
    private static void encodeBits(Asn1BitString b, XerWriter w, int depth) {
        int total = b.bitCount();
        byte[] bytes = b.bytes();
        int i = 0;
        do {
            w.ascii("\n").indent(depth + 1);
            int lineEnd = Math.min(i + 64, total);
            for (; i < lineEnd; i++) {
                w.ascii(((bytes[i / 8] >> (7 - (i % 8))) & 1) == 1 ? "1" : "0");
            }
        } while (i < total);
        w.ascii("\n").indent(depth);
    }

    /** xmlbstring (X.680 §22); lenient also accepts hex pairs, an asn1c extension. */
    private static void decodeBits(Asn1BitString b, XerReader r) {
        int at = r.position();
        StringBuilder content = new StringBuilder();
        boolean hex = false;
        for (byte c : r.readText()) {
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                continue;
            }
            if (c != '0' && c != '1') {
                if (Character.digit(c, 16) < 0) {
                    throw new DecodeException("XER: invalid BIT STRING character", at);
                }
                hex = true;
            }
            content.append((char) c);
        }
        if (hex) {
            if (!r.lenient()) {
                throw new DecodeException("XER: hex BIT STRING requires lenient mode (non-standard extension)", at);
            }
            if (content.length() % 2 != 0) {
                throw new DecodeException("XER: odd-length hex BIT STRING", at);
            }
            b.set(hexPairs(content.toString().getBytes(StandardCharsets.US_ASCII)), 0);
            return;
        }
        int n = content.length();
        byte[] bytes = new byte[(n + 7) / 8];
        for (int i = 0; i < n; i++) {
            if (content.charAt(i) == '1') {
                bytes[i / 8] |= (byte) (0x80 >> (i % 8));
            }
        }
        b.set(bytes, bytes.length * 8 - n);
    }

    /** X.680 §11.15.5 Table 3: the names of the C0 control characters an xmlcstring writes as empty elements. */
    private static final String[] CONTROL_NAMES = {
        "nul", "soh", "stx", "etx", "eot", "enq", "ack", "bel", "bs", null, null, "vt", "ff", null, "so", "si",
        "dle", "dc1", "dc2", "dc3", "dc4", "nak", "syn", "etb", "can", "em", "sub", "esc", "is4", "is3", "is2", "is1"};

    private static final String BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * An OCTET STRING under an X.693 §21 instruction: Base64 with {@code =}
     * padding, or the octets as UTF-8 text with {@code <}, {@code >} and
     * {@code &} escaped and the C0 controls other than tab, line feed and
     * carriage return as their empty elements.
     */
    public static void encodeOctets(byte[] octets, XerInstruction ins, XerWriter w) {
        switch (ins) {
            case BASE64 -> {
                StringBuilder s = new StringBuilder((octets.length + 2) / 3 * 4);
                for (int i = 0; i < octets.length; i += 3) {
                    int n = Math.min(3, octets.length - i);
                    int v = (octets[i] & 0xFF) << 16 | (n > 1 ? (octets[i + 1] & 0xFF) << 8 : 0) | (n > 2 ? octets[i + 2] & 0xFF : 0);
                    s.append(BASE64.charAt(v >> 18 & 63)).append(BASE64.charAt(v >> 12 & 63));
                    s.append(n > 1 ? BASE64.charAt(v >> 6 & 63) : '=').append(n > 2 ? BASE64.charAt(v & 63) : '=');
                }
                w.ascii(s.toString());
            }
            case UTF8 -> {
                int start = 0;
                for (int i = 0; i < octets.length; i++) {
                    int c = octets[i] & 0xFF;
                    if (c < 32 && CONTROL_NAMES[c] != null) {
                        w.escaped(java.util.Arrays.copyOfRange(octets, start, i)).empty(CONTROL_NAMES[c]);
                        start = i + 1;
                    }
                }
                w.escaped(java.util.Arrays.copyOfRange(octets, start, octets.length));
            }
            case DEFAULT -> w.hex(octets);
        }
    }

    /** Decode counterpart of {@link #encodeOctets}; Base64 skips anything outside its alphabet. */
    public static byte[] decodeOctets(XerInstruction ins, XerReader r) {
        return switch (ins) {
            case BASE64 -> {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int buf = 0;
                int bits = 0;
                for (byte c : r.readText()) {
                    int v = BASE64.indexOf(c);
                    if (c == '=' || v < 0) {
                        continue;
                    }
                    buf = buf << 6 | v;
                    bits += 6;
                    if (bits >= 8) {
                        bits -= 8;
                        out.write(buf >> bits & 0xFF);
                    }
                }
                yield out.toByteArray();
            }
            case UTF8 -> {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                while (true) {
                    out.writeBytes(r.readText());
                    XerReader.TagInfo peek = r.peekTag();
                    int code = peek.selfClosing() && !peek.closing() ? java.util.Arrays.asList(CONTROL_NAMES).indexOf(peek.name()) : -1;
                    if (code < 0) {
                        break;
                    }
                    r.consumeTag();
                    out.write(code);
                }
                yield out.toByteArray();
            }
            case DEFAULT -> hexPairs(r.readText());
        };
    }

    /**
     * Hex pairs, whitespace allowed between them; stops at the first thing
     * that is not a pair, as asn1c and the C++ runtime do.
     */
    static byte[] hexPairs(byte[] text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(text.length / 2);
        int i = 0;
        while (true) {
            while (i < text.length && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r')) {
                i++;
            }
            if (i + 1 >= text.length) {
                break;
            }
            int hi = Character.digit(text[i], 16);
            int lo = Character.digit(text[i + 1], 16);
            if (hi < 0 || lo < 0) {
                break;
            }
            out.write(hi << 4 | lo);
            i += 2;
        }
        return out.toByteArray();
    }
}
