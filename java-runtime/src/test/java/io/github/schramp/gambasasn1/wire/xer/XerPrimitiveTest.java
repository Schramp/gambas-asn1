package io.github.schramp.gambasasn1.wire.xer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1BmpString;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import io.github.schramp.gambasasn1.wire.types.Asn1Utf8String;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class XerPrimitiveTest {

    private static String encode(Asn1Primitive p, int depth) {
        XerWriter w = new XerWriter();
        XerPrimitive.encode(p, w, depth);
        return new String(w.toByteArray(), StandardCharsets.UTF_8);
    }

    private static <T extends Asn1Primitive> T decode(T p, String content, boolean lenient) {
        XerPrimitive.decode(p, new XerReader(content.getBytes(StandardCharsets.UTF_8), lenient));
        return p;
    }

    @Test
    void textEscapesMarkupAndReadsEntitiesBack() {
        Asn1Utf8String s = new Asn1Utf8String();
        s.set("a<b&c>d\"e");
        assertEquals("a&lt;b&amp;c&gt;d\"e", encode(s, 0));
        assertEquals("a<b&c>d\"e'A€", decode(new Asn1Utf8String(), "a&lt;b&amp;c&gt;d&quot;e&apos;&#65;&#x20AC;", false).get());
    }

    @Test
    void bitStringBreaksLinesAt64Bits() {
        Asn1BitString b = new Asn1BitString();
        byte[] bytes = new byte[9];
        bytes[8] = (byte) 0x80;
        b.set(bytes, 7);
        String zeros = "0".repeat(64);
        assertEquals("\n        " + zeros + "\n        1\n    ", encode(b, 1));
        Asn1BitString back = decode(new Asn1BitString(), encode(b, 1), false);
        assertArrayEquals(bytes, back.bytes());
        assertEquals(65, back.bitCount());
    }

    @Test
    void hexBitStringIsLenientOnly() {
        assertThrows(DecodeException.class, () -> decode(new Asn1BitString(), "A5", false));
        Asn1BitString b = decode(new Asn1BitString(), "A5", true);
        assertArrayEquals(new byte[] {(byte) 0xA5}, b.bytes());
        assertEquals(8, b.bitCount());
    }

    @Test
    void octetStringHexAllowsWhitespaceBetweenPairs() {
        assertArrayEquals(new byte[] {1, (byte) 0xAB}, decode(new Asn1OctetString(), " 01\n ab ", false).get());
    }

    @Test
    void unsignedIntegerUsesTheFull64Bits() {
        Asn1UInteger u = new Asn1UInteger();
        u.set(-1L);
        assertEquals("18446744073709551615", encode(u, 0));
        assertEquals(-1L, decode(new Asn1UInteger(), "18446744073709551615", false).get());
    }

    @Test
    void decimalRealWritesItsExactDigits() {
        assertEquals("-125E-2", encode(Asn1Real.decimal(true, "125", -2), 0));
        assertEquals("7", encode(Asn1Real.decimal(false, "7", 0), 0));
    }

    @Test
    void realMatchesCPrintfAt15Decimals() {
        assertEquals("0.333333333333333", encode(new Asn1Real(1.0 / 3), 0));
        assertEquals("-0.0", encode(new Asn1Real(-1e-20), 0));
        assertEquals("100.0", encode(new Asn1Real(100), 0));
        assertThrows(DecodeException.class, () -> decode(new Asn1Real(), "0x1p3", false));
        assertEquals(1e-3, decode(new Asn1Real(), " 1E-3 ", false).value());
    }

    @Test
    void bmpStringIsUtf8TextOfItsCodePoints() {
        Asn1BmpString s = new Asn1BmpString();
        s.setOctets(new byte[] {0, 'B', 0x20, (byte) 0xAC});
        assertEquals("B€", encode(s, 0));
        assertArrayEquals(new byte[] {0, 'B', 0x20, (byte) 0xAC}, decode(new Asn1BmpString(), "B€", false).octets());
    }
}
