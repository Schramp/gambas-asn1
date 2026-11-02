package io.github.schramp.gambasasn1.wire.per;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.types.Asn1BmpString;
import io.github.schramp.gambasasn1.wire.types.Asn1CharString;
import io.github.schramp.gambasasn1.wire.types.Asn1Ia5String;
import io.github.schramp.gambasasn1.wire.types.Asn1NumericString;
import io.github.schramp.gambasasn1.wire.types.Asn1PrintableString;
import io.github.schramp.gambasasn1.wire.types.Asn1UniversalString;
import io.github.schramp.gambasasn1.wire.types.Asn1VisibleString;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * Known-multiplier character strings in unaligned PER (X.691 §30.5). The
 * expected bytes are asn1c's UPER for the same type and value.
 */
class PerCharStringTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static Constraints size(long lb, long ub, boolean ext) {
        return new Constraints(Constraints.SIZE_CONSTRAINED | (ext ? Constraints.EXTENSIBLE : 0), 0, 0, 0, 0, 0,
                PerWhole.rangeBits(lb, ub), lb, ub, null, 0, null, 0, null, 0.0, 0.0);
    }

    /**
     * A FROM table over {@code chars} remapped to their sorted index, as the
     * generated tables carry it when the largest character does not fit the
     * index bits (§30.5.4), optionally with a SIZE.
     */
    private static Constraints from(String chars, Constraints sized) {
        byte[] alphabet = chars.chars().sorted().collect(StringBuilder::new, StringBuilder::appendCodePoint,
                StringBuilder::append).toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        char[] table = new char[256];
        Arrays.fill(table, (char) 0xFFFF);
        for (int i = 0; i < alphabet.length; i++) {
            table[alphabet[i] & 0xFF] = (char) i;
        }
        int bits = PerWhole.rangeBits(0, alphabet.length - 1);
        Constraints s = sized == null ? Constraints.UNCONSTRAINED : sized;
        return new Constraints(s.flags(), 0, 0, 0, 0, 0, s.sizeRangeBits(), s.sizeLower(), s.sizeUpper(), table, bits,
                alphabet, alphabet.length, null, 0.0, 0.0);
    }

    private static void roundTrip(Supplier<? extends Asn1CharString> kind, Constraints c, String value, String uper) {
        Asn1CharString v = kind.get();
        v.set(value);
        assertArrayEquals(hex(uper), PerObject.encode(v, c), value);
        Asn1CharString back = kind.get();
        PerObject.decode(back, hex(uper), c);
        assertEquals(v, back);
    }

    /** §30.5.4: NumericString maps space to 0 and the digits to 1..10, in 4 bits. */
    @Test
    void numericString() {
        roundTrip(Asn1NumericString::new, size(1, 8, false), "12 3", "646080");
        assertThrows(EncodeException.class, () -> PerObject.encode(new Asn1NumericString("1a")));
        // 4-bit value 11 is no NumericString character.
        assertThrows(DecodeException.class, () -> PerObject.decode(new Asn1NumericString(), hex("01B0")));
    }

    /** §30.5.2: the 128-character kinds take 7 bits, unmapped. */
    @Test
    void sevenBitKinds() {
        roundTrip(Asn1PrintableString::new, Constraints.UNCONSTRAINED, "Ab 1", "0483890310");
        roundTrip(Asn1VisibleString::new, size(2, 4, true), "abc", "387163");
        roundTrip(Asn1VisibleString::new, size(2, 4, true), "abcdef", "8361C58F265CC0");
        assertThrows(EncodeException.class, () -> PerObject.encode(new Asn1Ia5String("é")));
    }

    /** §30.5.4: a FROM alphabet whose largest character does not fit the index bits is remapped. */
    @Test
    void permittedAlphabet() {
        roundTrip(Asn1Ia5String::new, from("ABC", null), "CAB", "0384");
        roundTrip(Asn1Ia5String::new, from("0123456789", size(1, 4, false)), "0912", "C24480");
        roundTrip(Asn1VisibleString::new, from("0123456789ABCDEF", null), "F0A", "03F0A0");
        roundTrip(Asn1BmpString::new, from("ABCD", null), "DAB", "03C4");
        assertThrows(EncodeException.class, () -> PerObject.encode(new Asn1Ia5String("ABD"), from("ABC", null)));
        // Index 3 is past the three characters.
        assertThrows(DecodeException.class, () -> PerObject.decode(new Asn1Ia5String(), hex("01C0"), from("ABC", null)));
    }

    /** §30.5.2: BMPString 16 bits, UniversalString 32 bits a character. */
    @Test
    void wideKinds() {
        roundTrip(Asn1BmpString::new, size(1, 4, false), "A€", "4010482B00");
        roundTrip(Asn1UniversalString::new, Constraints.UNCONSTRAINED, "A", "0100000041");
    }
}
