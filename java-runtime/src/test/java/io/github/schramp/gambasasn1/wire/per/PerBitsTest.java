package io.github.schramp.gambasasn1.wire.per;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * The unaligned PER bit layer and the whole-number encodings of X.691
 * §11.3–§11.5, each on its own. The bit sequences are those of the Rust
 * {@code per::Writer} tests, which were checked against the C++
 * {@code PerEncodeStream}.
 */
class PerBitsTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    @Test
    void bitsPackMostSignificantFirst() {
        PerWriter w = new PerWriter().putBits(0b10110, 5).putBits(1, 1).putBits(0b11, 2).putBits(0xABCD, 16);
        assertArrayEquals(hex("B7ABCD"), w.toByteArray());
    }

    @Test
    void bitsSpanOctets() {
        assertArrayEquals(hex("FF80"), new PerWriter().putBits(0xFF, 8).putBits(1, 1).toByteArray());
    }

    @Test
    void zeroWidthFieldWritesNothing() {
        PerWriter w = new PerWriter().putBits(0, 0).putBits(0b1010, 4);
        assertEquals(4, w.bitPos());
    }

    /** X.691 §11.1.3.1: an empty encoding is one zero octet; a partial octet is padded with zero bits. */
    @Test
    void completeEncodingPadsToOctets() {
        assertArrayEquals(hex("00"), new PerWriter().toByteArray());
        assertArrayEquals(hex("A0"), new PerWriter().putBits(0b101, 3).toByteArray());
        assertArrayEquals(hex("AB"), new PerWriter().putBits(0xAB, 8).toByteArray());
    }

    @Test
    void sixtyFourBitField() {
        PerWriter w = new PerWriter().putBits(1, 1).putBits(0x8000000000000001L, 64);
        assertArrayEquals(hex("C00000000000000080"), w.toByteArray());
        PerReader r = new PerReader(w.toByteArray());
        assertEquals(1, r.getBits(1));
        assertEquals(0x8000000000000001L, r.getBits(64));
    }

    @Test
    void bitStringSplicesExactBits() {
        PerWriter part = new PerWriter().putBits(0b101, 3).putBits(0xAB, 8);
        PerWriter w = new PerWriter().putBits(1, 1).putBitString(part.toByteArray(), part.bitPos());
        assertArrayEquals(hex("DAB0"), w.toByteArray());
    }

    @Test
    void readerReadsBackAndStopsAtTheEnd() {
        PerReader r = new PerReader(hex("B7ABCD"));
        assertEquals(0b10110, r.getBits(5));
        assertEquals(1, r.getBits(1));
        assertEquals(0b11, r.getBits(2));
        assertEquals(0xABCD, r.getBits(16));
        assertEquals(0, r.remaining());
        DecodeException e = assertThrows(DecodeException.class, () -> r.getBits(1));
        assertEquals(3, e.position());
        assertTrue(e.getMessage().contains("(bit 24)"), e.getMessage());
    }

    /** X.691 §11.5.4, §11.5.6: the fewest bits for the range, none for a single value. */
    @Test
    void constrainedWholeNumberWidth() {
        assertEquals(0, PerWhole.rangeBits(5, 5));
        assertEquals(1, PerWhole.rangeBits(0, 1));
        assertEquals(8, PerWhole.rangeBits(0, 255));
        assertEquals(9, PerWhole.rangeBits(0, 256));
        assertEquals(3, PerWhole.rangeBits(-3, 3));
        assertEquals(64, PerWhole.rangeBits(Long.MIN_VALUE, Long.MAX_VALUE));
    }

    @Test
    void constrainedWholeNumberRoundTrips() {
        long[][] cases = {{5, 5, 5}, {0, 0, 1}, {200, 0, 255}, {-3, -3, 3}, {3, -3, 3},
            {Long.MIN_VALUE, Long.MIN_VALUE, Long.MAX_VALUE}, {Long.MAX_VALUE, Long.MIN_VALUE, Long.MAX_VALUE}, {-1, Long.MIN_VALUE, Long.MAX_VALUE}};
        for (long[] c : cases) {
            PerWriter w = new PerWriter();
            PerWhole.putConstrained(w, c[0], c[1], c[2]);
            assertEquals(PerWhole.rangeBits(c[1], c[2]), w.bitPos());
            assertEquals(c[0], PerWhole.getConstrained(new PerReader(w.toByteArray()), c[1], c[2]));
        }
        PerWriter w = new PerWriter();
        PerWhole.putConstrained(w, 200, 0, 255);
        assertArrayEquals(hex("C8"), w.toByteArray());
    }

    @Test
    void constrainedWholeNumberOutsideTheRange() {
        assertThrows(EncodeException.class, () -> PerWhole.putConstrained(new PerWriter(), 4, 0, 3));
        // 0..4 takes 3 bits; 111 = 7 is beyond the range.
        assertThrows(DecodeException.class, () -> PerWhole.getConstrained(new PerReader(hex("E0")), 0, 4));
    }

    /** X.691 §11.4.6: the minimum octets, as BER INTEGER contents (X.690 §8.3.2). */
    @Test
    void twosComplementMinimumOctets() {
        assertArrayEquals(hex("00"), PerWhole.twosComplementOctets(0));
        assertArrayEquals(hex("7F"), PerWhole.twosComplementOctets(127));
        assertArrayEquals(hex("0080"), PerWhole.twosComplementOctets(128));
        assertArrayEquals(hex("80"), PerWhole.twosComplementOctets(-128));
        assertArrayEquals(hex("FF7F"), PerWhole.twosComplementOctets(-129));
        assertArrayEquals(hex("FF"), PerWhole.twosComplementOctets(-1));
        assertArrayEquals(hex("8000000000000000"), PerWhole.twosComplementOctets(Long.MIN_VALUE));
        assertArrayEquals(hex("7FFFFFFFFFFFFFFF"), PerWhole.twosComplementOctets(Long.MAX_VALUE));
        for (long n : new long[] {0, 127, 128, -128, -129, -1, Long.MIN_VALUE, Long.MAX_VALUE, 1L << 40}) {
            assertEquals(n, PerWhole.fromTwosComplement(PerWhole.twosComplementOctets(n)));
        }
    }

    /** X.691 §11.3.6: no leading zero octet, one octet for zero; read as unsigned. */
    @Test
    void nonNegativeMinimumOctets() {
        assertArrayEquals(hex("00"), PerWhole.nonNegativeOctets(0));
        assertArrayEquals(hex("FF"), PerWhole.nonNegativeOctets(255));
        assertArrayEquals(hex("0100"), PerWhole.nonNegativeOctets(256));
        assertArrayEquals(hex("FFFFFFFFFFFFFFFF"), PerWhole.nonNegativeOctets(-1));
        for (long n : new long[] {0, 255, 256, -1, 1L << 63}) {
            assertEquals(n, PerWhole.fromNonNegative(PerWhole.nonNegativeOctets(n)));
        }
    }

    /** X.691 §12: one bit; §18: no field, so a NULL alone is the one zero octet of §11.1.3.1. */
    @Test
    void booleanAndNull() {
        assertArrayEquals(hex("80"), PerObject.encode(new Asn1Boolean(true)));
        assertArrayEquals(hex("00"), PerObject.encode(new Asn1Boolean(false)));
        assertArrayEquals(hex("00"), PerObject.encode(new Asn1Null()));
        Asn1Boolean b = new Asn1Boolean();
        PerObject.decode(b, hex("80"));
        assertEquals(true, b.get());
        PerObject.decode(new Asn1Null(), hex("00"));
        assertThrows(DecodeException.class, () -> PerObject.decode(new Asn1Boolean(), hex("8000")));
    }
}
