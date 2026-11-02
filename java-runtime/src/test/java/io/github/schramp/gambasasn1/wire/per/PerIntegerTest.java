package io.github.schramp.gambasasn1.wire.per;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * INTEGER in unaligned PER (X.691 §13). The expected bytes are asn1c's UPER
 * for the same type and value, except where asn1c has no PER encoding (ranges
 * as wide as 64 bits, values from 2^63 up).
 */
class PerIntegerTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static Constraints range(long lb, long ub, boolean ext) {
        return new Constraints(Constraints.CONSTRAINED | (ext ? Constraints.EXTENSIBLE : 0), PerWhole.rangeBits(lb, ub),
                lb, ub, 0, 0, 0, 0, 0, null, 0, null, 0, null, 0.0, 0.0);
    }

    private static Constraints semi(long lb, boolean ext) {
        return new Constraints(Constraints.SEMI_CONSTRAINED | (ext ? Constraints.EXTENSIBLE : 0), 0,
                lb, 0, 0, 0, 0, 0, 0, null, 0, null, 0, null, 0.0, 0.0);
    }

    private static Constraints urange(long lb, long ub, boolean ext) {
        return new Constraints(Constraints.CONSTRAINED | (ext ? Constraints.EXTENSIBLE : 0), PerWhole.rangeBits(lb, ub),
                0, 0, lb, ub, 0, 0, 0, null, 0, null, 0, null, 0.0, 0.0);
    }

    private static void signed(Constraints c, long v, String uper) {
        assertArrayEquals(hex(uper), PerObject.encode(new Asn1Integer(v), c), "value " + v);
        Asn1Integer back = new Asn1Integer();
        PerObject.decode(back, hex(uper), c);
        assertEquals(v, back.get());
    }

    private static void unsigned(Constraints c, long v, String uper) {
        assertArrayEquals(hex(uper), PerObject.encode(new Asn1UInteger(v), c), "value " + Long.toUnsignedString(v));
        Asn1UInteger back = new Asn1UInteger();
        PerObject.decode(back, hex(uper), c);
        assertEquals(v, back.get());
    }

    /** X.691 §13.2.2, §11.5.6: the offset from lb in the fewest bits; none for a single value. */
    @Test
    void constrained() {
        signed(range(0, 7, false), 3, "60");
        signed(range(-1000, -990, false), -995, "50");
        signed(range(42, 42, false), 42, "00");
        signed(range(0, 4294967295L, false), 4294967295L, "FFFFFFFF");
    }

    /** X.691 §13.1: an extensible range adds a bit; outside it, the unconstrained form. */
    @Test
    void extensibleRange() {
        Constraints c = range(0, 7, true);
        signed(c, 3, "30");
        signed(c, 8, "808400");
        signed(c, -1, "80FF80");
    }

    /** X.691 §13.2.3, §11.7: the offset from lb as a non-negative-binary-integer. */
    @Test
    void semiConstrained() {
        Constraints c = semi(5, true);
        signed(c, 5, "008000");
        signed(c, 300, "01009380");
        signed(c, 4, "808200");
        signed(semi(5, false), 300, "020127");
        signed(semi(Long.MIN_VALUE, false), Long.MAX_VALUE, "08FFFFFFFFFFFFFFFF");
    }

    /** X.691 §11.5.6: a range of 2^64 values is a 64-bit field. */
    @Test
    void sixtyFourBitRange() {
        Constraints c = range(Long.MIN_VALUE, Long.MAX_VALUE, false);
        signed(c, Long.MIN_VALUE, "0000000000000000");
        signed(c, -1, "7FFFFFFFFFFFFFFF");
        signed(c, Long.MAX_VALUE, "FFFFFFFFFFFFFFFF");
    }

    @Test
    void unsignedStorage() {
        unsigned(urange(0, -1L, false), -1L, "FFFFFFFFFFFFFFFF");
        unsigned(urange(1L << 63, -1L, false), 1L << 63, "0000000000000000");
        unsigned(urange(0, -1L, false), 5, "0000000000000005");
        // §11.8.3: 2^64 - 1 outside the root takes nine 2's-complement octets.
        unsigned(urange(1L << 63, -2L, true), -1L, "84807FFFFFFFFFFFFFFF80");
    }

    @Test
    void outsideTheRoot() {
        assertThrows(EncodeException.class, () -> PerObject.encode(new Asn1Integer(8), range(0, 7, false)));
        assertThrows(EncodeException.class, () -> PerObject.encode(new Asn1Integer(4), semi(5, false)));
        // 0..4 takes 3 bits; 111 = 7 lies beyond.
        assertThrows(DecodeException.class, () -> PerObject.decode(new Asn1Integer(), hex("E0"), range(0, 4, false)));
        // lb 1 + offset 2^63 - 1 exceeds signed storage.
        assertThrows(DecodeException.class,
                () -> PerObject.decode(new Asn1Integer(), hex("087FFFFFFFFFFFFFFF"), semi(1, false)));
        // A negative value has no unsigned storage.
        assertThrows(DecodeException.class,
                () -> PerObject.decode(new Asn1UInteger(), hex("80FF80"), urange(10, -1L, true)));
    }
}
