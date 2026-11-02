package io.github.schramp.gambasasn1.wire.per;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Length determinants (X.691 §11.9) and the length-prefixed whole numbers
 * (§11.6–§11.8). Byte sequences are those of the Rust {@code per::length}
 * tests, checked there against the C++ {@code PerCodec}, and of asn1c's
 * UPER where noted.
 */
class PerLengthTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static Constraints sized(long lower, long upper, boolean extensible) {
        int bits = PerWhole.rangeBits(lower, upper);
        int flags = Constraints.SIZE_CONSTRAINED | (extensible ? Constraints.EXTENSIBLE : 0);
        return new Constraints(flags, 0, 0, 0, 0, 0, bits, lower, upper, null, 0, null, 0, null, 0.0, 0.0);
    }

    private static final PerLength.ItemWriter NO_ITEMS = (w, from, to) -> { };
    private static final PerLength.ItemReader SKIP_ITEMS = (r, count) -> { };

    /** X.691 §11.9.3.6, §11.9.3.7: one octet up to 127, two octets below 16K. */
    @Test
    void shortAndLongForm() {
        int[] ns = {0, 1, 127, 128, 200, 16383};
        String[] wire = {"00", "01", "7F", "8080", "80C8", "BFFF"};
        for (int i = 0; i < ns.length; i++) {
            PerWriter w = new PerWriter();
            PerLength.putLength(w, ns[i]);
            assertArrayEquals(hex(wire[i]), w.toByteArray(), "n = " + ns[i]);
            assertEquals(ns[i], PerLength.getLength(new PerReader(w.toByteArray())));
        }
        assertThrows(EncodeException.class, () -> PerLength.putLength(new PerWriter(), 16384));
        assertThrows(DecodeException.class, () -> PerLength.getLength(new PerReader(hex("C1"))));
    }

    private static byte[] fragmentRoundTrip(int n) {
        byte[] data = new byte[n];
        for (int i = 0; i < n; i++) {
            data[i] = (byte) (i % 251);
        }
        PerWriter w = new PerWriter();
        PerLength.putOctets(w, data);
        byte[] wire = w.toByteArray();
        assertArrayEquals(data, PerLength.getOctets(new PerReader(wire)), "n = " + n);
        return wire;
    }

    /** X.691 §11.9.3.8: 16K-unit fragments, the largest multiplier first, a closing length. */
    @Test
    void fragmentHeaders() {
        byte[] b = fragmentRoundTrip(16383);
        assertEquals((byte) 0xBF, b[0]);
        assertEquals((byte) 0xFF, b[1]);
        b = fragmentRoundTrip(16384);
        assertEquals((byte) 0xC1, b[0]);
        assertEquals(0x00, b[1 + 16384]);
        assertEquals(1 + 16384 + 1, b.length);
        b = fragmentRoundTrip(65536);
        assertEquals((byte) 0xC4, b[0]);
        assertEquals(0x00, b[1 + 65536]);
        b = fragmentRoundTrip(65537);
        assertEquals(0x01, b[1 + 65536]);
        assertEquals(1 + 65536 + 1 + 1, b.length);
        // §11.9.3.8.1 note: 144K + 1 = 64K + 64K + 16K + 1.
        b = fragmentRoundTrip(144 * 1024 + 1);
        assertEquals((byte) 0xC4, b[0]);
        assertEquals((byte) 0xC4, b[1 + 65536]);
        assertEquals((byte) 0xC1, b[2 + 2 * 65536]);
        assertEquals(0x01, b[3 + 2 * 65536 + 16384]);
    }

    @Test
    void badFragmentMultiplierAndShortFragment() {
        assertThrows(DecodeException.class, () -> PerLength.getOctets(new PerReader(hex("C5"))));
        assertThrows(DecodeException.class, () -> PerLength.getOctets(new PerReader(hex("C10000"))));
    }

    /** X.691 §11.9.3.4: 1..64 as n - 1 in 6 bits behind a 0 bit. */
    @Test
    void normallySmallLength() {
        PerWriter w = new PerWriter();
        PerLength.putNormallySmallLength(w, 3);
        assertArrayEquals(hex("04"), w.toByteArray());
        for (int n : new int[] {1, 32, 64, 65, 200}) {
            w = new PerWriter();
            PerLength.putNormallySmallLength(w, n);
            assertEquals(n, PerLength.getNormallySmallLength(new PerReader(w.toByteArray())));
        }
    }

    /**
     * X.691 §11.6: 6 bits up to 63, then bit 1, the octet count and the
     * octets. asn1c writes an extensible ENUMERATED's extension items 0, 63
     * and 64 as {@code 80}, {@code BF} and {@code C05000}: the extension bit 1,
     * then this field.
     */
    @Test
    void normallySmallMatchesAsn1c() {
        long[] ns = {0, 63, 64};
        String[] uper = {"80", "BF", "C05000"};
        for (int i = 0; i < ns.length; i++) {
            PerWriter w = new PerWriter().putBits(1, 1);
            PerLength.putNormallySmall(w, ns[i]);
            assertArrayEquals(hex(uper[i]), w.toByteArray(), "n = " + ns[i]);
            PerReader r = new PerReader(hex(uper[i]));
            r.getBits(1);
            assertEquals(ns[i], PerLength.getNormallySmall(r));
        }
        for (long n : new long[] {255, 256, 65535, 1L << 40, Long.MAX_VALUE}) {
            PerWriter w = new PerWriter();
            PerLength.putNormallySmall(w, n);
            assertEquals(n, PerLength.getNormallySmall(new PerReader(w.toByteArray())));
        }
        assertThrows(EncodeException.class, () -> PerLength.putNormallySmall(new PerWriter(), -1));
    }

    /** X.691 §11.7.4: minimum non-negative octets after their count. */
    @Test
    void semiConstrained() {
        long[] ns = {0, 255, 256, -1};
        String[] wire = {"0100", "01FF", "020100", "08FFFFFFFFFFFFFFFF"};
        for (int i = 0; i < ns.length; i++) {
            PerWriter w = new PerWriter();
            PerLength.putSemiConstrained(w, ns[i]);
            assertArrayEquals(hex(wire[i]), w.toByteArray());
            assertEquals(ns[i], PerLength.getSemiConstrained(new PerReader(w.toByteArray())));
        }
        assertThrows(DecodeException.class, () -> PerLength.getSemiConstrained(new PerReader(hex("00"))));
        assertThrows(DecodeException.class,
                () -> PerLength.getSemiConstrained(new PerReader(hex("09010000000000000000"))));
    }

    /** X.691 §11.8.3: minimum 2's-complement octets after their count. */
    @Test
    void unconstrained() {
        long[] ns = {0, 127, 128, -128, -129, Long.MIN_VALUE};
        String[] wire = {"0100", "017F", "020080", "0180", "02FF7F", "088000000000000000"};
        for (int i = 0; i < ns.length; i++) {
            PerWriter w = new PerWriter();
            PerLength.putUnconstrained(w, ns[i]);
            assertArrayEquals(hex(wire[i]), w.toByteArray());
            assertEquals(ns[i], PerLength.getUnconstrained(new PerReader(w.toByteArray())));
        }
    }

    @Test
    void fixedSizeWritesNothing() {
        PerWriter w = new PerWriter();
        PerLength.putSize(w, sized(5, 5, false), 5, NO_ITEMS);
        assertEquals(0, w.bitPos());
        assertEquals(5, PerLength.getSize(new PerReader(new byte[0]), sized(5, 5, false), SKIP_ITEMS));
    }

    /** X.691 §11.9.4.1: ub below 64K takes the offset from lb in the fewest bits. */
    @Test
    void constrainedSize() {
        Constraints c = sized(1, 8, false);
        PerWriter w = new PerWriter();
        PerLength.putSize(w, c, 5, NO_ITEMS);
        assertArrayEquals(hex("80"), w.toByteArray());
        for (int n = 1; n <= 8; n++) {
            w = new PerWriter();
            PerLength.putSize(w, c, n, NO_ITEMS);
            assertEquals(n, PerLength.getSize(new PerReader(w.toByteArray()), c, SKIP_ITEMS));
        }
        // 1..5 takes 3 bits; 111 is 8, beyond the SIZE.
        assertThrows(DecodeException.class, () -> PerLength.getSize(new PerReader(hex("E0")), sized(1, 5, false), SKIP_ITEMS));
    }

    @Test
    void unconstrainedSizeIsAGeneralLength() {
        PerWriter w = new PerWriter();
        PerLength.putSize(w, Constraints.UNCONSTRAINED, 200, NO_ITEMS);
        assertArrayEquals(hex("80C8"), w.toByteArray());
        assertEquals(200, PerLength.getSize(new PerReader(w.toByteArray()), Constraints.UNCONSTRAINED, SKIP_ITEMS));
    }

    /** X.691 §11.9.4.1 holds for ub below 64K only; SIZE (16384..70000) is a general length. */
    @Test
    void sizeUpperBound64kOrMoreIsAGeneralLength() {
        PerWriter w = new PerWriter();
        PerLength.putSize(w, sized(16384, 70000, false), 16384, (out, from, to) -> {
            for (int i = from; i < to; i++) {
                out.putBits(0, 8);
            }
        });
        assertEquals((byte) 0xC1, w.toByteArray()[0]);
        w = new PerWriter();
        PerLength.putSize(w, sized(16384, 20000, false), 16385, NO_ITEMS);
        assertEquals(12, w.bitPos());
    }

    /** X.691 §17.3, §16.6, §20.4: an extensible SIZE adds the extension bit. */
    @Test
    void extensibleSize() {
        Constraints c = sized(1, 4, true);
        PerWriter w = new PerWriter();
        PerLength.putExtSize(w, c, 2, NO_ITEMS);
        assertArrayEquals(hex("20"), w.toByteArray());
        w = new PerWriter();
        PerLength.putExtSize(w, c, 6, NO_ITEMS);
        assertArrayEquals(hex("8300"), w.toByteArray());
        assertEquals(6, PerLength.getExtSize(new PerReader(w.toByteArray()), c, SKIP_ITEMS));
        assertEquals(2, PerLength.getExtSize(new PerReader(hex("20")), c, SKIP_ITEMS));
    }

    /** X.691 §11.9.4.1: a count outside a non-extensible SIZE has no encoding. */
    @Test
    void countOutsideNonExtensibleSize() {
        Constraints c = sized(1, 4, false);
        for (int n : new int[] {0, 5, 15}) {
            PerWriter w = new PerWriter();
            assertThrows(EncodeException.class, () -> PerLength.putSize(w, c, n, NO_ITEMS));
            assertThrows(EncodeException.class, () -> PerLength.putExtSize(w, c, n, NO_ITEMS));
            assertEquals(0, w.bitPos());
        }
    }
}
