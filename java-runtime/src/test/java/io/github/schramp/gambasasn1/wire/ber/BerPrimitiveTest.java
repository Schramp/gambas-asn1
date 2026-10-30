package io.github.schramp.gambasasn1.wire.ber;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import org.junit.jupiter.api.Test;

/** BOOLEAN, INTEGER, BIT STRING, OCTET STRING and NULL contents (X.690 §8.2, §8.3, §8.6, §8.7, §8.8) and the framing around them (X.690 §8.14). */
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
}
