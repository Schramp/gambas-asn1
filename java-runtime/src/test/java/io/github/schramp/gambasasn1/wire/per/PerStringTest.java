package io.github.schramp.gambasasn1.wire.per;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * OCTET STRING and BIT STRING in unaligned PER (X.691 §16, §17). The
 * expected bytes are asn1c's UPER for the same type and value.
 */
class PerStringTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static Constraints size(long lb, long ub, int extraFlags) {
        return new Constraints(Constraints.SIZE_CONSTRAINED | extraFlags, 0, 0, 0, 0, 0, PerWhole.rangeBits(lb, ub),
                lb, ub, null, 0, null, 0, null, 0.0, 0.0);
    }

    private static final Constraints NAMED = new Constraints(Constraints.NAMED_BITS, 0, 0, 0, 0, 0, 0, 0, 0, null, 0,
            null, 0, null, 0.0, 0.0);

    private static void octets(Constraints c, String value, String uper) {
        assertArrayEquals(hex(uper), PerObject.encode(new Asn1OctetString(hex(value)), c), value);
        Asn1OctetString back = new Asn1OctetString();
        PerObject.decode(back, hex(uper), c);
        assertArrayEquals(hex(value), back.get());
    }

    private static Asn1BitString bits(String binary) {
        byte[] packed = new byte[(binary.length() + 7) / 8];
        for (int i = 0; i < binary.length(); i++) {
            if (binary.charAt(i) == '1') {
                packed[i / 8] |= (byte) (0x80 >>> (i % 8));
            }
        }
        return new Asn1BitString(packed, packed.length * 8 - binary.length());
    }

    private static void bitString(Constraints c, String value, String uper, String decoded) {
        assertArrayEquals(hex(uper), PerObject.encode(bits(value), c), value);
        Asn1BitString back = new Asn1BitString();
        PerObject.decode(back, hex(uper), c);
        assertEquals(bits(decoded), back);
    }

    /** X.691 §17.3: an extensible SIZE's bit, then the root count or a general length. */
    @Test
    void octetStringSizes() {
        octets(size(1, 4, Constraints.EXTENSIBLE), "0102", "202040");
        octets(size(1, 4, Constraints.EXTENSIBLE), "0102030405", "82808101820280");
        octets(size(3, 3, 0), "010203", "010203");
        octets(Constraints.UNCONSTRAINED, "", "00");
    }

    /** X.691 §11.9.3.8: 16K octets and more are fragmented. */
    @Test
    void fragmentedOctetString() {
        byte[] value = new byte[16385];
        Arrays.fill(value, (byte) 0xAB);
        byte[] uper = PerObject.encode(new Asn1OctetString(value));
        assertEquals(16387, uper.length);
        assertEquals((byte) 0xC1, uper[0]);
        assertEquals(0x01, uper[1 + 16384]);
        Asn1OctetString back = new Asn1OctetString();
        PerObject.decode(back, uper);
        assertArrayEquals(value, back.get());
    }

    /** X.691 §16.6: the extension bit of an extensible SIZE. */
    @Test
    void bitStringSizes() {
        bitString(size(2, 3, Constraints.EXTENSIBLE), "101", "68", "101");
        bitString(size(2, 3, Constraints.EXTENSIBLE), "1011", "8258", "1011");
    }

    /** X.691 §16.2, §16.3: trailing 0 bits dropped with a NamedBitList, kept up to the SIZE's lower bound. */
    @Test
    void namedBitsDropTrailingZeros() {
        bitString(NAMED, "01000000", "0240", "01");
        bitString(NAMED, "00000000", "00", "");
        bitString(size(4, 8, Constraints.NAMED_BITS), "01000000", "08", "0100");
    }

    /** X.691 §11.9.4.1: a count outside a non-extensible SIZE has no encoding. */
    @Test
    void lengthOutsideTheSize() {
        assertThrows(EncodeException.class, () -> PerObject.encode(new Asn1OctetString(hex("0102")), size(3, 3, 0)));
        // 1..5 takes 3 bits; 111 is 8.
        assertThrows(DecodeException.class, () -> PerObject.decode(new Asn1OctetString(), hex("E0"), size(1, 5, 0)));
        // SIZE (5..70000) is a general length; 1 lies outside it.
        assertThrows(DecodeException.class,
                () -> PerObject.decode(new Asn1OctetString(), hex("0101"), size(5, 70000, 0)));
        assertThrows(DecodeException.class, () -> PerObject.decode(new Asn1OctetString(), hex("05AB")));
    }
}
