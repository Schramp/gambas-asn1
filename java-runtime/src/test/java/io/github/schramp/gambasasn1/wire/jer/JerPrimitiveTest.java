package io.github.schramp.gambasasn1.wire.jer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1BmpString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import io.github.schramp.gambasasn1.wire.types.Asn1UniversalString;
import io.github.schramp.gambasasn1.wire.types.Asn1Utf8String;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class JerPrimitiveTest {
    private static final Constraints NONE = Constraints.UNCONSTRAINED;

    private static Constraints flags(int f, long sizeLower, long sizeUpper) {
        return new Constraints(f, 0, 0, 0, 0, 0, 0, sizeLower, sizeUpper, null, 0, null, 0, null, 0.0, 0.0);
    }

    private static String encode(Asn1Primitive p, Constraints c) {
        JerWriter w = new JerWriter();
        JerPrimitive.encode(p, c, w);
        return new String(w.toByteArray(), StandardCharsets.UTF_8);
    }

    private static <T extends Asn1Primitive> T decode(T p, Constraints c, String text) {
        JerPrimitive.decode(p, c, new JerReader(text.getBytes(StandardCharsets.UTF_8)));
        return p;
    }

    @Test
    void stringsEscapeQuoteBackslashAndControlsOnly() {
        Asn1Utf8String s = new Asn1Utf8String();
        s.set("a<b&c>\"\\\u0001\t/é");
        assertEquals("\"a<b&c>\\\"\\\\\\u0001\\u0009/é\"", encode(s, NONE));
        assertEquals(s.get(), decode(new Asn1Utf8String(), NONE, encode(s, NONE)).get());
    }

    /** BMPString and UniversalString are their characters, JSON-escaped, never XML text (X.697 §38.1). */
    @Test
    void wideStringsAreTheirCharacters() {
        Asn1BmpString b = new Asn1BmpString();
        b.setOctets(new byte[] {0, 'a', 0, '<', 0, '&', 0, '"', 0, 1, 0x20, (byte) 0xAC});
        assertEquals("\"a<&\\\"\\u0001€\"", encode(b, NONE));
        assertArrayEquals(b.octets(), decode(new Asn1BmpString(), NONE, encode(b, NONE)).octets());
        Asn1UniversalString u = new Asn1UniversalString();
        u.setOctets(new byte[] {0, 0, 0, 'x', 0, 1, (byte) 0xF6, 0});
        assertEquals("\"x😀\"", encode(u, NONE));
        assertArrayEquals(u.octets(), decode(new Asn1UniversalString(), NONE, "\"x\\ud83d\\ude00\"").octets());
    }

    @Test
    void stringEscapesFollowRfc8259() {
        assertEquals("A\b\f\n\r\t\"\\/", decode(new Asn1Utf8String(), NONE, "\"\\u0041\\b\\f\\n\\r\\t\\\"\\\\\\/\"").get());
        for (String bad : new String[] {"\"\\ud83dx\"", "\"\\ud83d\\u0041\"", "\"\\ude00\"", "\"\\u12\"", "\"\\u00g1\"", "\"\\x41\"", "\"open"}) {
            assertThrows(DecodeException.class, () -> decode(new Asn1Utf8String(), NONE, bad), bad);
        }
    }

    @Test
    void unsignedIntegerUsesTheFull64Bits() {
        Asn1UInteger u = new Asn1UInteger();
        u.set(-1L);
        assertEquals("18446744073709551615", encode(u, NONE));
        assertEquals(-1L, decode(new Asn1UInteger(), NONE, "18446744073709551615").get());
    }

    /** The C++/Rust rule: shortest round-trip digits, plain for exponents in [-4, 15). */
    @Test
    void realIsTheShortestRoundTripNumber() {
        assertEquals("0.1", encode(new Asn1Real(0.1), NONE));
        assertEquals("-193700.32316011307", encode(new Asn1Real(-193700.32316011307), NONE));
        assertEquals("0.0001", encode(new Asn1Real(1e-4), NONE));
        assertEquals("1E-5", encode(new Asn1Real(1e-5), NONE));
        assertEquals("100000000000000", encode(new Asn1Real(1e14), NONE));
        assertEquals("1E15", encode(new Asn1Real(1e15), NONE));
        assertEquals("1.2345E300", encode(new Asn1Real(1.2345e300), NONE));
        assertEquals("5E-324", encode(new Asn1Real(Double.MIN_VALUE), NONE));
        assertEquals("0", encode(new Asn1Real(0.0), NONE));
        assertEquals("\"-0\"", encode(new Asn1Real(-0.0), NONE));
        assertEquals("\"INF\"", encode(new Asn1Real(Double.POSITIVE_INFINITY), NONE));
        assertEquals("\"-INF\"", encode(new Asn1Real(Double.NEGATIVE_INFINITY), NONE));
        assertEquals("\"NaN\"", encode(new Asn1Real(Double.NaN), NONE));
    }

    @Test
    void realDecodesNumbersStringsAndBase10Objects() {
        assertEquals(-0.0, decode(new Asn1Real(), NONE, "\"-0\"").value());
        assertEquals(2.5, decode(new Asn1Real(), NONE, "\"2.5\"").value());
        assertEquals(1e-3, decode(new Asn1Real(), NONE, " 1E-3 ").value());
        assertThrows(DecodeException.class, () -> decode(new Asn1Real(), NONE, "0x1p3"));
        assertThrows(DecodeException.class, () -> decode(new Asn1Real(), NONE, "\"PLUS-INFINITY\""));
        Asn1Real d = decode(new Asn1Real(), NONE, "{\"base10Value\":-1.25E3}");
        assertEquals(Asn1Real.decimal(true, "125", 1), d);
        assertThrows(DecodeException.class, () -> decode(new Asn1Real(), NONE, "{\"other\":1}"));
    }

    /** A DECIMAL value is its exact digits: bare under a base-10-only constraint, else in base10Value (X.697 §23.1.4, §23.4). */
    @Test
    void decimalRealFormDependsOnTheBaseConstraint() {
        Asn1Real d = Asn1Real.decimal(true, "125", -2);
        assertEquals("{\"base10Value\":-125E-2}", encode(d, NONE));
        Constraints base10 = flags(Constraints.REAL_BASE_10, 0, 0);
        assertEquals("-125E-2", encode(d, base10));
        assertEquals(d, decode(new Asn1Real(), base10, "-1.25"));
    }

    /** X.697 §24.2, §24.3: a fixed, non-extensible SIZE gives a bare hex string; anything else the object form. */
    @Test
    void bitStringFormDependsOnAFixedSize() {
        Asn1BitString b = new Asn1BitString(new byte[] {(byte) 0xA5, (byte) 0xF0}, 4);
        Constraints fixed12 = flags(Constraints.SIZE_CONSTRAINED, 12, 12);
        assertEquals("\"A5F0\"", encode(b, fixed12));
        assertEquals("{\"value\":\"A5F0\",\"length\":12}", encode(b, NONE));
        assertEquals("{\"value\":\"A5F0\",\"length\":12}",
                encode(b, flags(Constraints.SIZE_CONSTRAINED | Constraints.EXTENSIBLE, 12, 12)));
        assertEquals(b, decode(new Asn1BitString(), fixed12, "\"A5FF\""));
        assertThrows(DecodeException.class, () -> decode(new Asn1BitString(), fixed12, "\"A5\""));
        assertThrows(DecodeException.class, () -> decode(new Asn1BitString(), NONE, "\"A5F0\""));
        assertEquals(b, decode(new Asn1BitString(), NONE, "{ \"length\" : 12 , \"value\" : \"a5ff\" }"));
    }
}
