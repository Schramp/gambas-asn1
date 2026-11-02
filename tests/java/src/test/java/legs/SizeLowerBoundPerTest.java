package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gen.size_lower_bound.Lb10Max;
import gen.size_lower_bound.Lb10Ub70k;
import gen.size_lower_bound.Probe;
import gen.size_lower_bound.Ub65535;
import gen.size_lower_bound.Ub65536;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Unaligned PER of SIZE(lb..MAX) and of the 64K edge of the length
 * determinant (X.691 §11.9.4): below 64K the length is n - lb in the
 * range's bits (§11.9.4.1); with an upper bound of 64K or more, or none, it
 * is n itself, fragmented from 16K on (§11.9.4.2, §11.9.3.8). Vectors from
 * asn1c, cross-checked with Erlang/OTP -buper, as in
 * tests/per/test_size_lower_bound.cpp; the long rows give the total size and
 * the offset and value of each length octet, the rest are 0xAB.
 */
class SizeLowerBoundPerTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static Probe probe(int osLen, String ia5, int bitCount, int ints) {
        Probe p = new Probe();
        byte[] os = new byte[osLen];
        for (int i = 0; i < osLen; i++) {
            os[i] = (byte) (i + 1);
        }
        p.os().value.set(os);
        p.ia5().value.set(ia5);
        // 1010 0101 1...: the bit pattern of the vectors below.
        byte[] bits = new byte[(bitCount + 7) / 8];
        bits[0] = (byte) 0xA5;
        if (bitCount > 8) {
            bits[1] = (byte) 0x80;
        }
        p.bits().value.set(bits, (8 - bitCount % 8) % 8);
        long[] vals = {1, 2, 7};
        for (int i = 0; i < ints; i++) {
            p.ints().add(new Asn1Integer(vals[i]));
        }
        return p;
    }

    @Test
    void lowerBoundOnlyUsesUnconstrainedLength() {
        for (Object[] row : new Object[][] {
                {probe(4, "abc", 8, 2), "040102030403c38b1845281140"},
                {probe(5, "abcd", 9, 3), "05010203040504c38b1e409a58195c"}}) {
            Probe p = (Probe) row[0];
            byte[] buf = PerObject.encode(p);
            assertArrayEquals(hex((String) row[1]), buf);
            Probe back = new Probe();
            PerObject.decode(back, buf);
            assertArrayEquals(p.os().value.get(), back.os().value.get());
            assertEquals(p.ia5().value.get(), back.ia5().value.get());
            assertEquals(p.bits().value, back.bits().value);
            assertEquals(p.ints().size(), back.ints().size());
        }
    }

    private static byte[] octets(int n) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) 0xAB);
        return b;
    }

    private static byte[] encodeOctets(Constraints c, int n) {
        Ub65535 v = new Ub65535();
        v.value.set(octets(n));
        return PerObject.encode(v, c);
    }

    @Test
    void shortLengthsAtThe64KEdge() {
        String ab10 = "ab".repeat(10);
        String ab200 = "ab".repeat(200);
        assertArrayEquals(hex("000a" + ab10), encodeOctets(Ub65535.CONSTRAINTS, 10));
        assertArrayEquals(hex("00c8" + ab200), encodeOctets(Ub65535.CONSTRAINTS, 200));
        assertArrayEquals(hex("0a" + ab10), encodeOctets(Ub65536.CONSTRAINTS, 10));
        assertArrayEquals(hex("80c8" + ab200), encodeOctets(Ub65536.CONSTRAINTS, 200));
        assertArrayEquals(hex("0a" + ab10), encodeOctets(Lb10Ub70k.CONSTRAINTS, 10));
        assertArrayEquals(hex("80c8" + ab200), encodeOctets(Lb10Ub70k.CONSTRAINTS, 200));
        assertArrayEquals(hex("0a" + ab10), encodeOctets(Lb10Max.CONSTRAINTS, 10));
        assertArrayEquals(hex("80c8" + ab200), encodeOctets(Lb10Max.CONSTRAINTS, 200));
    }

    private static void longRow(Constraints c, int n, int total, int[][] headers) {
        byte[] buf = encodeOctets(c, n);
        byte[] want = new byte[total];
        Arrays.fill(want, (byte) 0xAB);
        for (int[] h : headers) {
            want[h[0]] = (byte) h[1];
        }
        assertArrayEquals(want, buf);
        Ub65535 back = new Ub65535();
        PerObject.decode(back, buf, c);
        assertArrayEquals(octets(n), back.value.get());
    }

    @Test
    void fragmentedLengthsAtThe64KEdge() {
        longRow(Ub65535.CONSTRAINTS, 65535, 65537, new int[][] {{0, 0xff}, {1, 0xff}});
        longRow(Ub65536.CONSTRAINTS, 65535, 65538, new int[][] {{0, 0xc3}, {49153, 0xbf}, {49154, 0xff}});
        longRow(Lb10Max.CONSTRAINTS, 16384, 16386, new int[][] {{0, 0xc1}, {16385, 0x00}});
        longRow(Lb10Ub70k.CONSTRAINTS, 65536, 65538, new int[][] {{0, 0xc4}, {65537, 0x00}});
    }
}
