package io.github.schramp.gambasasn1.wire.ber;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.LongStream;
import org.junit.jupiter.api.Test;

/**
 * REAL contents octets (X.690 §8.5) and storage classes. The decode and
 * storage vector tables are the ones the C++ runtime
 * ({@code tests/ber/test_real_ber.cpp}) and the Rust runtime
 * ({@code real.rs}) share: every runtime must give the same double bit for
 * bit (or an error), the same storage class and the same CER/DER
 * re-encoding (X.690 §11.3).
 */
class BerRealTest {
    private record DecodeVector(String label, byte[] contents, Long bits) {
    }

    private record StorageVector(String label, byte[] contents, Asn1Real.Storage storage, byte[] reencoded) {
    }

    private static byte[] bytes(int... b) {
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) {
            out[i] = (byte) b[i];
        }
        return out;
    }

    private static byte[] zeros(byte[] head, int zeros, byte[] tail) {
        byte[] out = Arrays.copyOf(head, head.length + zeros + tail.length);
        System.arraycopy(tail, 0, out, head.length + zeros, tail.length);
        return out;
    }

    private static byte[] ascii(int head, String t) {
        byte[] text = t.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[text.length + 1];
        out[0] = (byte) head;
        System.arraycopy(text, 0, out, 1, text.length);
        return out;
    }

    private static final List<DecodeVector> DECODE_VECTORS = List.of(
            new DecodeVector("plus zero, no contents (§8.5.2)", bytes(), 0x0000000000000000L),
            new DecodeVector("1.0, exponent format a", bytes(0x80, 0x00, 0x01), 0x3FF0000000000000L),
            new DecodeVector("-1.0 (§8.5.7.1)", bytes(0xC0, 0x00, 0x01), 0xBFF0000000000000L),
            new DecodeVector("2.0 via scaling factor F=1 (§8.5.7.3)", bytes(0x84, 0x00, 0x01), 0x4000000000000000L),
            new DecodeVector("1.0, format d, X=1 (§8.5.7.4 d)", bytes(0x83, 0x01, 0x00, 0x01), 0x3FF0000000000000L),
            new DecodeVector("1.0, format d, X=2", bytes(0x83, 0x02, 0x00, 0x00, 0x01), 0x3FF0000000000000L),
            new DecodeVector("1.0, format d, X=5", bytes(0x83, 0x05, 0, 0, 0, 0, 0, 0x01), 0x3FF0000000000000L),
            new DecodeVector("1.0, format d, exponent -1 in 9 octets", bytes(0x83, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02), 0x3FF0000000000000L),
            new DecodeVector("2^72, 10-octet mantissa (§8.5.7.5 NOTE 1)", zeros(bytes(0x80, 0x00, 0x01), 9, bytes()), 0x4470000000000000L),
            new DecodeVector("2^-64, 11-octet mantissa, exponent -80", zeros(bytes(0x80, 0xB0), 8, bytes(0x01, 0x00, 0x00)), 0x3BF0000000000000L),
            new DecodeVector("2^53+1 rounds to even 2^53", bytes(0x80, 0x00, 0x20, 0, 0, 0, 0, 0, 0x01), 0x4340000000000000L),
            new DecodeVector("2^53+3 rounds up to 2^53+4", bytes(0x80, 0x00, 0x20, 0, 0, 0, 0, 0, 0x03), 0x4340000000000002L),
            new DecodeVector("leading zero mantissa octets", bytes(0x80, 0x00, 0x00, 0x00, 0x01), 0x3FF0000000000000L),
            new DecodeVector("zero mantissa is zero", bytes(0xC0, 0x00, 0x00), 0x8000000000000000L),
            new DecodeVector("largest double (2^53-1) * 2^971", bytes(0x81, 0x03, 0xCB, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF), 0x7FEFFFFFFFFFFFFFL),
            new DecodeVector("smallest subnormal 2^-1074", bytes(0x81, 0xFB, 0xCE, 0x01), 0x0000000000000001L),
            new DecodeVector("3 * 2^-1076 rounds to 2^-1074", bytes(0x81, 0xFB, 0xCC, 0x03), 0x0000000000000001L),
            new DecodeVector("subnormal 3 * 2^-1074", bytes(0x81, 0xFB, 0xCE, 0x03), 0x0000000000000003L),
            new DecodeVector("smallest normal 2^-1022", bytes(0x81, 0xFC, 0x02, 0x01), 0x0010000000000000L),
            new DecodeVector("2^1024: Binary, value +inf", bytes(0x81, 0x04, 0x00, 0x01), 0x7FF0000000000000L),
            new DecodeVector("exponent ~2^31: Binary, value +inf", bytes(0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01), 0x7FF0000000000000L),
            new DecodeVector("2^-1076: Binary, value +0", bytes(0x81, 0xFB, 0xCC, 0x01), 0x0000000000000000L),
            new DecodeVector("format d without length octet", bytes(0x83), null),
            new DecodeVector("format d, X=0", bytes(0x83, 0x00, 0x01), null),
            new DecodeVector("format d, truncated exponent", bytes(0x83, 0x02, 0x00), null),
            new DecodeVector("format b, truncated exponent", bytes(0x81, 0x00), null),
            new DecodeVector("special value with extra octet", bytes(0x40, 0x00), null),
            new DecodeVector("reserved special value 0x44 (§8.5.9)", bytes(0x44), null),
            new DecodeVector("decimal NR1 14 (§8.5.8)", bytes(0x01, 0x31, 0x34), 0x402C000000000000L),
            new DecodeVector("decimal NR1 with spaces and sign", bytes(0x01, 0x20, 0x20, 0x2D, 0x31, 0x34), 0xC02C000000000000L),
            new DecodeVector("decimal NR1 -0", bytes(0x01, 0x2D, 0x30), 0x8000000000000000L),
            new DecodeVector("decimal NR2 14.56", bytes(0x02, 0x31, 0x34, 0x2E, 0x35, 0x36), 0x402D1EB851EB851FL),
            new DecodeVector("decimal NR2 ISO 6093 comma 14,56", bytes(0x02, 0x31, 0x34, 0x2C, 0x35, 0x36), 0x402D1EB851EB851FL),
            new DecodeVector("decimal NR2 .5", bytes(0x02, 0x2E, 0x35), 0x3FE0000000000000L),
            new DecodeVector("decimal NR2 5.", bytes(0x02, 0x35, 0x2E), 0x4014000000000000L),
            new DecodeVector("decimal NR3 14.56E0", bytes(0x03, 0x31, 0x34, 0x2E, 0x35, 0x36, 0x45, 0x30), 0x402D1EB851EB851FL),
            new DecodeVector("decimal NR3 1456e-2, no decimal mark", bytes(0x03, 0x31, 0x34, 0x35, 0x36, 0x65, 0x2D, 0x32), 0x402D1EB851EB851FL),
            new DecodeVector("decimal NR3 +1.456E+1", bytes(0x03, 0x2B, 0x31, 0x2E, 0x34, 0x35, 0x36, 0x45, 0x2B, 0x31), 0x402D1EB851EB851FL),
            new DecodeVector("decimal NR1 with a mark is malformed", bytes(0x01, 0x31, 0x2E, 0x35), null),
            new DecodeVector("decimal NR2 without a mark is malformed", bytes(0x02, 0x31, 0x34), null),
            new DecodeVector("decimal NR3 without exponent is malformed", bytes(0x03, 0x31, 0x34, 0x2E, 0x35, 0x36), null),
            new DecodeVector("decimal NR3 without exponent digits", bytes(0x03, 0x31, 0x45), null),
            new DecodeVector("decimal trailing space is malformed", bytes(0x01, 0x31, 0x34, 0x20), null),
            new DecodeVector("decimal empty field", bytes(0x01), null),
            new DecodeVector("decimal NR3 1E400: value +inf", bytes(0x03, 0x31, 0x45, 0x34, 0x30, 0x30), 0x7FF0000000000000L),
            new DecodeVector("decimal NR3 1E-400: value +0", bytes(0x03, 0x31, 0x45, 0x2D, 0x34, 0x30, 0x30), 0x0000000000000000L),
            new DecodeVector("base 8, exponent 0 (§8.5.7.2)", bytes(0x90, 0x00, 0x01), 0x3FF0000000000000L),
            new DecodeVector("base 8, exponent 1 is 8", bytes(0x90, 0x01, 0x01), 0x4020000000000000L),
            new DecodeVector("base 8, exponent 1, F=2 is 32", bytes(0x98, 0x01, 0x01), 0x4040000000000000L),
            new DecodeVector("base 16, exponent 1 is 16", bytes(0xA0, 0x01, 0x01), 0x4030000000000000L),
            new DecodeVector("base 16, exponent -1 is 1/16", bytes(0xA0, 0xFF, 0x01), 0x3FB0000000000000L),
            new DecodeVector("reserved base 11", bytes(0xB0, 0x00, 0x01), null),
            new DecodeVector("reserved decimal form 0", bytes(0x00, 0x31), null),
            new DecodeVector("reserved decimal form 4", bytes(0x04, 0x31), null),
            new DecodeVector("PLUS-INFINITY (§8.5.9)", bytes(0x40), 0x7FF0000000000000L),
            new DecodeVector("MINUS-INFINITY", bytes(0x41), 0xFFF0000000000000L),
            new DecodeVector("minus zero", bytes(0x43), 0x8000000000000000L));

    private static final List<StorageVector> STORAGE_VECTORS = List.of(
            new StorageVector("1.0 is Double", bytes(0x80, 0x00, 0x01), Asn1Real.Storage.DOUBLE, bytes(0x80, 0x00, 0x01)),
            new StorageVector("2^72, 10-octet mantissa, is exact: Double", zeros(bytes(0x80, 0x00, 0x01), 9, bytes()), Asn1Real.Storage.DOUBLE, bytes(0x80, 0x48, 0x01)),
            new StorageVector("2^60+1 needs 61 bits: Binary, kept exactly", bytes(0x80, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x01), Asn1Real.Storage.BINARY, bytes(0x80, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x01)),
            new StorageVector("Binary mantissa normalized odd, base 16 to base 2", bytes(0xA0, 0x01, 0x20, 0, 0, 0, 0, 0, 0, 0x02), Asn1Real.Storage.BINARY, bytes(0x80, 0x05, 0x10, 0, 0, 0, 0, 0, 0, 0x01)),
            new StorageVector("2^1024: Binary", bytes(0x81, 0x04, 0x00, 0x01), Asn1Real.Storage.BINARY, bytes(0x81, 0x04, 0x00, 0x01)),
            new StorageVector("-2^-1076: Binary", bytes(0xC1, 0xFB, 0xCC, 0x01), Asn1Real.Storage.BINARY, bytes(0xC1, 0xFB, 0xCC, 0x01)),
            new StorageVector("exponent 2^31 in format d: Binary, 4 exponent octets", bytes(0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01), Asn1Real.Storage.BINARY, bytes(0x83, 0x04, 0x7F, 0x00, 0x00, 0x00, 0x01)),
            new StorageVector("NR2 14.56: Decimal, NR3 1456.E-2", ascii(0x02, "14.56"), Asn1Real.Storage.DECIMAL, ascii(0x03, "1456.E-2")),
            new StorageVector("NR1 100: Decimal, NR3 1.E2", ascii(0x01, "100"), Asn1Real.Storage.DECIMAL, ascii(0x03, "1.E2")),
            new StorageVector("NR1 -7: Decimal, NR3 -7.E+0", ascii(0x01, "-7"), Asn1Real.Storage.DECIMAL, ascii(0x03, "-7.E+0")),
            new StorageVector("NR3 0.0012E3 normalizes to 12.E-1", ascii(0x03, "0.0012E3"), Asn1Real.Storage.DECIMAL, ascii(0x03, "12.E-1")),
            new StorageVector("NR3 1E400: Decimal beyond the double range", ascii(0x03, "1E400"), Asn1Real.Storage.DECIMAL, ascii(0x03, "1.E400")),
            new StorageVector("X.680 pi {3141592653589793238462643383279, 10, -30}", ascii(0x03, "3141592653589793238462643383279E-30"), Asn1Real.Storage.DECIMAL, ascii(0x03, "3141592653589793238462643383279.E-30")),
            new StorageVector("NR1 000 is plus zero (Double)", ascii(0x01, "000"), Asn1Real.Storage.DOUBLE, bytes()));

    @Test
    void decodeVectorsMatchTheOtherRuntimes() {
        for (DecodeVector v : DECODE_VECTORS) {
            if (v.bits() == null) {
                assertThrows(DecodeException.class, () -> BerReal.decode(v.contents(), 0), v.label());
            } else {
                assertEquals(v.bits().longValue(), Double.doubleToRawLongBits(BerReal.decode(v.contents(), 0).value()),
                        v.label());
            }
        }
        assertTrue(Double.isNaN(BerReal.decode(bytes(0x42), 0).value()));
    }

    @Test
    void storageClassesMatchTheOtherRuntimes() {
        for (StorageVector v : STORAGE_VECTORS) {
            Asn1Real got = BerReal.decode(v.contents(), 0);
            assertEquals(v.storage(), got.storage(), v.label());
            assertArrayEquals(v.reencoded(), BerReal.encode(got), v.label());
        }
    }

    /** The direct IEEE path for short mantissas agrees with the general {@link Asn1Real#binary} at every scale. */
    @Test
    void shortMantissaPathMatchesGeneralBinary() {
        long x = 0x9E37_79B9_7F4A_7C15L;
        List<Long> mantissas = new ArrayList<>(List.of(1L, 3L, 0xFFL, (1L << 53) - 1, (1L << 53) + 1, (1L << 54) - 2, -1L));
        for (int i = 0; i < 64; i++) {
            x ^= x << 13;
            x ^= x >>> 7;
            x ^= x << 17;
            mantissas.add(x >>> Long.remainderUnsigned(x, 60));
        }
        long[] exponents = LongStream.concat(LongStream.iterate(-1200, e -> e < 1100, e -> e + 7),
                LongStream.concat(LongStream.range(-1140, -1060), LongStream.range(960, 1030))).toArray();
        for (long m : mantissas) {
            byte[] mb = ByteBuffer.allocate(8).putLong(m).array();
            for (long e : exponents) {
                for (boolean negative : new boolean[] {false, true}) {
                    byte[] v = new byte[11];
                    v[0] = (byte) (0x81 | (negative ? 0x40 : 0));
                    v[1] = (byte) (e >> 8);
                    v[2] = (byte) e;
                    System.arraycopy(mb, 0, v, 3, 8);
                    assertEquals(Asn1Real.binary(negative, mb, e), BerReal.decode(v, 0),
                            "m=" + Long.toHexString(m) + " e=" + e + " neg=" + negative);
                }
            }
        }
    }

    @Test
    void doublesEncodeInTheFewestOctets() {
        assertArrayEquals(bytes(), BerReal.encode(new Asn1Real(0.0)));
        assertArrayEquals(bytes(0x43), BerReal.encode(new Asn1Real(-0.0)));
        assertArrayEquals(bytes(0x40), BerReal.encode(new Asn1Real(Double.POSITIVE_INFINITY)));
        assertArrayEquals(bytes(0x41), BerReal.encode(new Asn1Real(Double.NEGATIVE_INFINITY)));
        assertArrayEquals(bytes(0x42), BerReal.encode(new Asn1Real(Double.NaN)));
        assertArrayEquals(bytes(0x80, 0x00, 0x01), BerReal.encode(new Asn1Real(1.0)));
        // X.690 §8.5.7: a subnormal is M x 2^-1074, with no implicit leading 1.
        assertArrayEquals(bytes(0x81, 0xFB, 0xCE, 0x01), BerReal.encode(new Asn1Real(Double.MIN_VALUE)));
    }

    @Test
    void doublesRoundTripBitForBit() {
        for (double d : new double[] {1.0, -1.0, 0.5, 3.14159265358979, -2.71828, 1e10, -1e-10, 100.0, 65535.0, -0.0,
                Double.MAX_VALUE, Double.MIN_NORMAL, Double.MIN_VALUE, Double.longBitsToDouble(0x000F_FFFF_FFFF_FFFFL),
                -Double.MIN_VALUE, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY}) {
            double back = BerReal.decode(BerReal.encode(new Asn1Real(d)), 0).value();
            assertEquals(Double.doubleToRawLongBits(d), Double.doubleToRawLongBits(back), Double.toString(d));
        }
    }

    @Test
    void decimalAndBinaryValueSemantics() {
        Asn1Real pi = BerReal.decode(ascii(0x03, "3141592653589793238462643383279E-30"), 0);
        assertEquals(10, pi.base());
        assertEquals("3141592653589793238462643383279", new String(pi.exact().mantissa(), StandardCharsets.US_ASCII));
        assertEquals(-30, pi.exact().exponent());
        assertEquals(3.141592653589793, pi.value());
        Asn1Real dec = Asn1Real.decimal(false, "1456", -2);
        assertNotEquals(new Asn1Real(14.56), dec, "X.680 §21.5 NOTE 1");
        assertTrue(dec.numericallyEqual(new Asn1Real(14.56)));
        assertEquals(Asn1Real.decimal(false, "14560", -3), dec);
        assertNotEquals(Asn1Real.decimal(true, "1456", -2), dec);
        assertEquals(new Asn1Real(1.5), Asn1Real.binary(false, bytes(0x03), -1));
        assertNotEquals(new Asn1Real(0.0), new Asn1Real(-0.0));
        assertEquals(new Asn1Real(Double.NaN), new Asn1Real(Double.NaN));
        Asn1Real r = Asn1Real.decimal(false, "1456", -2);
        r.set(2.0);
        assertEquals(Asn1Real.Storage.DOUBLE, r.storage());
        assertEquals(new Asn1Real(2.0), r);
    }

    @Test
    void framingAppliesAroundTheContents() {
        BerTagging ctx5 = new BerTagging.Implicit(Tag.context(5, false));
        ByteSink out = new ByteSink();
        BerPrimitive.encode(new Asn1Real(1.0), ctx5, out);
        assertArrayEquals(bytes(0x85, 0x03, 0x80, 0x00, 0x01), out.toByteArray());
        Asn1Real r = new Asn1Real();
        BerPrimitive.decode(r, BerTagging.DELEGATE, new BerReader(bytes(0x09, 0x03, 0x80, 0x00, 0x01)));
        assertEquals(new Asn1Real(1.0), r);
        assertThrows(DecodeException.class,
                () -> BerPrimitive.decode(new Asn1Real(), ctx5, new BerReader(bytes(0x09, 0x03, 0x80, 0x00, 0x01))));
    }
}
