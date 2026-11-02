package io.github.schramp.gambasasn1.wire.ber;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.types.Asn1Any;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1BmpString;
import io.github.schramp.gambasasn1.wire.types.Asn1GeneralizedTime;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Ia5String;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1ObjectIdentifier;
import io.github.schramp.gambasasn1.wire.types.Asn1RelativeOid;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import io.github.schramp.gambasasn1.wire.types.Asn1UniversalString;
import io.github.schramp.gambasasn1.wire.types.Asn1UtcTime;
import io.github.schramp.gambasasn1.wire.types.Asn1Utf8String;
import io.github.schramp.gambasasn1.wire.types.Asn1VisibleString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import org.junit.jupiter.api.Test;

/** BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER and RELATIVE-OID contents (X.690 §8.2, §8.3, §8.6, §8.7, §8.8, §8.19, §8.20) and the framing around them (X.690 §8.14). */
class BerPrimitiveTest {
    private static final BerTagging IMPLICIT_CTX5 = new BerTagging.Implicit(Tag.context(5, false));
    private static final BerTagging EXPLICIT_APP3 = new BerTagging.Explicit(new Tag(TagClass.APPLICATION, 3, true));

    private static byte[] bytes(int... b) {
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) {
            out[i] = (byte) b[i];
        }
        return out;
    }

    private static byte[] encode(Asn1Primitive p, BerTagging framing) {
        var out = new io.github.schramp.gambasasn1.wire.io.ByteSink();
        BerPrimitive.encode(p, framing, out);
        return out.toByteArray();
    }

    @Test
    void booleanIsDerOnEncode() {
        assertArrayEquals(bytes(0x01, 0x01, 0xFF), encode(new Asn1Boolean(true), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x01, 0x01, 0x00), encode(new Asn1Boolean(false), BerTagging.DELEGATE));
    }

    @Test
    void booleanAcceptsAnyNonZeroOctetAsTrue() {
        Asn1Boolean b = new Asn1Boolean();
        BerPrimitive.decode(b, BerTagging.DELEGATE, new BerReader(bytes(0x01, 0x01, 0x2A)));
        assertEquals(true, b.get());
        BerPrimitive.decode(b, BerTagging.DELEGATE, new BerReader(bytes(0x01, 0x01, 0x00)));
        assertEquals(false, b.get());
    }

    @Test
    void booleanContentsMustBeOneOctet() {
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1Boolean(), BerTagging.DELEGATE, new BerReader(bytes(0x01, 0x00))));
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1Boolean(), BerTagging.DELEGATE, new BerReader(bytes(0x01, 0x02, 0xFF, 0x00))));
    }

    @Test
    void nullHasNoContents() {
        assertArrayEquals(bytes(0x05, 0x00), encode(new Asn1Null(), BerTagging.DELEGATE));
        BerPrimitive.decode(new Asn1Null(), BerTagging.DELEGATE, new BerReader(bytes(0x05, 0x00)));
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1Null(), BerTagging.DELEGATE, new BerReader(bytes(0x05, 0x01, 0x00))));
    }

    @Test
    void wrongTagIsRejected() {
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1Boolean(), BerTagging.DELEGATE, new BerReader(bytes(0x02, 0x01, 0x00))));
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1Null(), IMPLICIT_CTX5, new BerReader(bytes(0x05, 0x00))));
    }

    @Test
    void implicitReplacesTheNaturalTag() {
        byte[] wire = encode(new Asn1Boolean(true), IMPLICIT_CTX5);
        assertArrayEquals(bytes(0x85, 0x01, 0xFF), wire);
        Asn1Boolean b = new Asn1Boolean();
        BerPrimitive.decode(b, IMPLICIT_CTX5, new BerReader(wire));
        assertEquals(true, b.get());
    }

    @Test
    void explicitWrapsTheNaturalEncoding() {
        byte[] wire = encode(new Asn1Null(), EXPLICIT_APP3);
        assertArrayEquals(bytes(0x63, 0x02, 0x05, 0x00), wire);
        BerPrimitive.decode(new Asn1Null(), EXPLICIT_APP3, new BerReader(wire));
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1Null(), EXPLICIT_APP3, new BerReader(bytes(0x05, 0x00))));
    }

    @Test
    void ofTypeUsesTheTypesFraming() {
        assertArrayEquals(bytes(0x85, 0x01, 0x00), encode(new Asn1Boolean(false), new BerTagging.OfType(IMPLICIT_CTX5)));
    }

    @Test
    void decodeLeavesTheReaderAfterTheValue() {
        BerReader r = new BerReader(bytes(0x05, 0x00, 0x01, 0x01, 0xFF));
        BerPrimitive.decode(new Asn1Null(), BerTagging.DELEGATE, r);
        Asn1Boolean b = new Asn1Boolean();
        BerPrimitive.decode(b, BerTagging.DELEGATE, r);
        assertEquals(true, b.get());
        assertEquals(true, r.atEnd());
    }

    @Test
    void integerUsesTheFewestOctets() {
        assertArrayEquals(bytes(0x02, 0x01, 0x00), encode(new Asn1Integer(0), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x02, 0x01, 0x7F), encode(new Asn1Integer(127), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x02, 0x02, 0x00, 0x80), encode(new Asn1Integer(128), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x02, 0x01, 0x80), encode(new Asn1Integer(-128), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x02, 0x02, 0xFF, 0x7F), encode(new Asn1Integer(-129), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x02, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0), encode(new Asn1Integer(Long.MIN_VALUE), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
                encode(new Asn1Integer(Long.MAX_VALUE), BerTagging.DELEGATE));
    }

    @Test
    void integerRoundTrips() {
        for (long n : new long[] {0, 1, -1, 127, 128, -128, -129, 255, 256, 65535, -65536, Integer.MAX_VALUE,
                Integer.MIN_VALUE, Long.MAX_VALUE, Long.MIN_VALUE}) {
            Asn1Integer back = new Asn1Integer();
            BerPrimitive.decode(back, BerTagging.DELEGATE, new BerReader(encode(new Asn1Integer(n), BerTagging.DELEGATE)));
            assertEquals(n, back.get());
        }
    }

    @Test
    void integerContentsMustFit64Bits() {
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1Integer(), BerTagging.DELEGATE, new BerReader(bytes(0x02, 0x00))));
        assertThrows(DecodeException.class, () -> BerPrimitive.decode(new Asn1Integer(), BerTagging.DELEGATE,
                new BerReader(bytes(0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0))));
    }

    @Test
    void octetStringContentsAreTheOctets() {
        assertArrayEquals(bytes(0x04, 0x03, 0x01, 0x02, 0x03), encode(new Asn1OctetString(bytes(1, 2, 3)), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x04, 0x00), encode(new Asn1OctetString(), BerTagging.DELEGATE));
        Asn1OctetString o = new Asn1OctetString();
        BerPrimitive.decode(o, BerTagging.DELEGATE, new BerReader(bytes(0x04, 0x02, 0xAB, 0xCD)));
        assertArrayEquals(bytes(0xAB, 0xCD), o.get());
    }

    @Test
    void longOctetStringUsesTheLongLengthForm() {
        byte[] big = new byte[300];
        big[299] = 7;
        byte[] wire = encode(new Asn1OctetString(big), BerTagging.DELEGATE);
        assertArrayEquals(bytes(0x04, 0x82, 0x01, 0x2C), java.util.Arrays.copyOf(wire, 4));
        Asn1OctetString o = new Asn1OctetString();
        BerPrimitive.decode(o, BerTagging.DELEGATE, new BerReader(wire));
        assertArrayEquals(big, o.get());
    }

    @Test
    void bitStringLeadsWithTheUnusedBitCount() {
        assertArrayEquals(bytes(0x03, 0x03, 0x04, 0xA5, 0xF0), encode(new Asn1BitString(bytes(0xA5, 0xF0), 4), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x03, 0x01, 0x00), encode(new Asn1BitString(), BerTagging.DELEGATE));
        Asn1BitString b = new Asn1BitString();
        BerPrimitive.decode(b, BerTagging.DELEGATE, new BerReader(bytes(0x03, 0x02, 0x07, 0x80)));
        assertEquals(1, b.bitCount());
        assertArrayEquals(bytes(0x80), b.bytes());
    }

    @Test
    void bitStringUnusedBitsMustFit() {
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1BitString(), BerTagging.DELEGATE, new BerReader(bytes(0x03, 0x00))));
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1BitString(), BerTagging.DELEGATE, new BerReader(bytes(0x03, 0x02, 0x08, 0x00))));
        // X.690 §8.6.2.3: an empty BIT STRING has a zero initial octet.
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1BitString(), BerTagging.DELEGATE, new BerReader(bytes(0x03, 0x01, 0x07))));
        assertThrows(IllegalArgumentException.class, () -> new Asn1BitString(new byte[0], 3));
    }

    @Test
    void constructedStringFormIsRejected() {
        assertThrows(DecodeException.class, () -> BerPrimitive.decode(new Asn1OctetString(), BerTagging.DELEGATE,
                new BerReader(bytes(0x24, 0x04, 0x04, 0x02, 0x01, 0x02))));
    }

    @Test
    void charStringsUseTheirOwnUniversalTag() {
        assertArrayEquals(bytes(0x16, 0x02, 'h', 'i'), encode(new Asn1Ia5String("hi"), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x1A, 0x01, 'x'), encode(new Asn1VisibleString("x"), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x0C, 0x02, 0xC3, 0xA9), encode(new Asn1Utf8String("\u00e9"), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x1E, 0x02, 0x00, 'A'), encode(new Asn1BmpString("A"), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x1C, 0x04, 0x00, 0x01, 0xF6, 0x00), encode(new Asn1UniversalString("\uD83D\uDE00"), BerTagging.DELEGATE));
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1VisibleString(), BerTagging.DELEGATE, new BerReader(bytes(0x16, 0x01, 'x'))));
    }

    @Test
    void charStringOctetsSurviveARoundTrip() {
        // Not UTF-8: kept as sent, as the C++ runtime does.
        Asn1Utf8String s = new Asn1Utf8String();
        BerPrimitive.decode(s, BerTagging.DELEGATE, new BerReader(bytes(0x0C, 0x02, 0xFF, 0xFE)));
        assertArrayEquals(bytes(0x0C, 0x02, 0xFF, 0xFE), encode(s, BerTagging.DELEGATE));
        Asn1BmpString b = new Asn1BmpString();
        BerPrimitive.decode(b, BerTagging.DELEGATE, new BerReader(bytes(0x1E, 0x04, 0x00, 'h', 0x00, 'i')));
        assertEquals("hi", b.get());
        assertEquals(false, new Asn1Ia5String("a").equals(new Asn1VisibleString("a")));
    }

    @Test
    void objectIdentifierCombinesTheFirstTwoArcs() {
        assertArrayEquals(bytes(0x06, 0x03, 0x55, 0x04, 0x03), encode(new Asn1ObjectIdentifier(2, 5, 4, 3), BerTagging.DELEGATE));
        // X.690 §8.19.5 example: {2 999 3}, first subidentifier 1079.
        assertArrayEquals(bytes(0x06, 0x03, 0x88, 0x37, 0x03), encode(new Asn1ObjectIdentifier(2, 999, 3), BerTagging.DELEGATE));
        Asn1ObjectIdentifier o = new Asn1ObjectIdentifier();
        BerPrimitive.decode(o, BerTagging.DELEGATE, new BerReader(bytes(0x06, 0x03, 0x88, 0x37, 0x03)));
        assertEquals(new Asn1ObjectIdentifier(2, 999, 3), o);
        assertEquals("2.999.3", o.toString());
    }

    @Test
    void objectIdentifierFirstSubidentifierBoundaries() {
        for (long[] arcs : new long[][] {{0, 39}, {1, 0}, {1, 39}, {2, 0}, {2, Asn1ObjectIdentifier.MAX_ARC}}) {
            byte[] wire = encode(new Asn1ObjectIdentifier(arcs), BerTagging.DELEGATE);
            Asn1ObjectIdentifier o = new Asn1ObjectIdentifier();
            BerPrimitive.decode(o, BerTagging.DELEGATE, new BerReader(wire));
            assertArrayEquals(arcs, o.get());
        }
        Asn1ObjectIdentifier empty = new Asn1ObjectIdentifier();
        BerPrimitive.decode(empty, BerTagging.DELEGATE, new BerReader(bytes(0x06, 0x00)));
        assertEquals(0, empty.get().length);
    }

    @Test
    void arcsAreBoundedTo32Bits() {
        // 1.2.(2^32)
        assertThrows(DecodeException.class, () -> BerPrimitive.decode(new Asn1ObjectIdentifier(), BerTagging.DELEGATE,
                new BerReader(bytes(0x06, 0x06, 0x2A, 0x90, 0x80, 0x80, 0x80, 0x00))));
        assertThrows(DecodeException.class, () -> BerPrimitive.decode(new Asn1RelativeOid(), BerTagging.DELEGATE,
                new BerReader(bytes(0x0D, 0x05, 0x90, 0x80, 0x80, 0x80, 0x00))));
        assertThrows(DecodeException.class, () -> BerPrimitive.decode(new Asn1RelativeOid(), BerTagging.DELEGATE,
                new BerReader(bytes(0x0D, 0x01, 0x86))));
        assertThrows(IllegalArgumentException.class, () -> new Asn1RelativeOid(1L << 32));
        assertThrows(IllegalArgumentException.class, () -> new Asn1RelativeOid(-1));
    }

    @Test
    void relativeOidHasOneSubidentifierPerArc() {
        assertArrayEquals(bytes(0x0D, 0x04, 0xC2, 0x7B, 0x03, 0x02), encode(new Asn1RelativeOid(8571, 3, 2), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x8D, 0x02, 0x01, 0x02), encode(new Asn1RelativeOid(1, 2), new BerTagging.Implicit(Tag.context(13, false))));
        Asn1RelativeOid r = new Asn1RelativeOid();
        BerPrimitive.decode(r, BerTagging.DELEGATE, new BerReader(bytes(0x0D, 0x05, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F)));
        assertArrayEquals(new long[] {Asn1RelativeOid.MAX_ARC}, r.get());
        assertEquals(false, new Asn1RelativeOid(1).equals(new Asn1ObjectIdentifier(1)));
    }

    @Test
    void timeTypesAreTheirTextUnderTheirOwnTag() {
        byte[] utc = encode(new Asn1UtcTime("240115143000Z"), BerTagging.DELEGATE);
        assertArrayEquals(bytes(0x17, 0x0D), java.util.Arrays.copyOf(utc, 2));
        Asn1GeneralizedTime g = new Asn1GeneralizedTime();
        BerPrimitive.decode(g, BerTagging.DELEGATE, new BerReader(encode(new Asn1GeneralizedTime("20240115143000.5+0200"), BerTagging.DELEGATE)));
        assertEquals("20240115143000.5+0200", g.get());
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1UtcTime(), BerTagging.DELEGATE, new BerReader(encode(g, BerTagging.DELEGATE))));
        assertEquals(false, new Asn1UtcTime("x").equals(new Asn1GeneralizedTime("x")));
    }

    @Test
    void unsignedIntegerUsesNineOctetsAboveInt64Max() {
        // X.690 §8.3: two's complement in the fewest octets, so a set top bit needs a leading 00.
        // The C++ runtime's UInteger encodes these values identically; asn1c cannot encode them.
        assertArrayEquals(bytes(0x02, 0x01, 0x00), encode(new Asn1UInteger(0), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x02, 0x02, 0x00, 0x80), encode(new Asn1UInteger(128), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x02, 0x09, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0), encode(new Asn1UInteger(Long.MIN_VALUE), BerTagging.DELEGATE));
        assertArrayEquals(bytes(0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF), encode(new Asn1UInteger(-1L), BerTagging.DELEGATE));
        Asn1UInteger u = new Asn1UInteger();
        BerPrimitive.decode(u, BerTagging.DELEGATE, new BerReader(bytes(0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)));
        assertEquals("18446744073709551615", u.toString());
        BerPrimitive.decode(u, BerTagging.DELEGATE, new BerReader(bytes(0x02, 0x02, 0x00, 0x7F)));
        assertEquals(127L, u.get());
    }

    @Test
    void unsignedIntegerRejectsNegativeAndWideValues() {
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1UInteger(), BerTagging.DELEGATE, new BerReader(bytes(0x02, 0x01, 0x80))));
        assertThrows(DecodeException.class, () -> BerPrimitive.decode(new Asn1UInteger(), BerTagging.DELEGATE,
                new BerReader(bytes(0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0))));
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1UInteger(), BerTagging.DELEGATE, new BerReader(bytes(0x02, 0x00))));
    }

    @Test
    void anyReplaysItsCapturedEncoding() {
        Asn1Any a = new Asn1Any();
        BerPrimitive.decode(a, BerTagging.DELEGATE, new BerReader(bytes(0x02, 0x01, 0x05, 0x05, 0x00)));
        assertArrayEquals(bytes(0x02, 0x01, 0x05, 0x05, 0x00), a.get());
        assertArrayEquals(a.get(), encode(a, BerTagging.DELEGATE));
        // X.690 §8.14: an EXPLICIT tag wraps the captured encoding.
        BerTagging explicit21 = new BerTagging.Explicit(Tag.context(21, true));
        assertArrayEquals(bytes(0xB5, 0x03, 0x01, 0x01, 0xFF), encode(new Asn1Any(bytes(0x01, 0x01, 0xFF)), explicit21));
        BerPrimitive.decode(a, explicit21, new BerReader(bytes(0xB5, 0x03, 0x01, 0x01, 0xFF)));
        assertArrayEquals(bytes(0x01, 0x01, 0xFF), a.get());
        assertThrows(DecodeException.class, () -> BerPrimitive.decode(new Asn1Any(), explicit21, new BerReader(bytes(0x01, 0x01, 0xFF))));
        assertThrows(io.github.schramp.gambasasn1.wire.io.EncodeException.class,
                () -> encode(new Asn1Any(bytes(0x05, 0x00)), IMPLICIT_CTX5));
    }
}
