package io.github.schramp.gambasasn1.wire.spec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.github.schramp.gambasasn1.wire.types.Asn1BmpString;
import io.github.schramp.gambasasn1.wire.types.Asn1CharString;
import io.github.schramp.gambasasn1.wire.types.Asn1GraphicString;
import io.github.schramp.gambasasn1.wire.types.Asn1Ia5String;
import io.github.schramp.gambasasn1.wire.types.Asn1NumericString;
import io.github.schramp.gambasasn1.wire.types.Asn1PrintableString;
import io.github.schramp.gambasasn1.wire.types.Asn1UniversalString;
import io.github.schramp.gambasasn1.wire.types.Asn1Utf8String;
import io.github.schramp.gambasasn1.wire.types.Asn1VisibleString;
import org.junit.jupiter.api.Test;

/**
 * SIZE and FROM on character strings count characters, not contents octets
 * (X.680 §51.5, §51.7), for the kinds stored in more than one octet per
 * character: UTF8String, BMPString, UniversalString (X.690 §8.23). Without
 * a FROM, a kind with a fixed character set is checked against it (X.680
 * §41), with or without other constraints.
 */
class ConstraintCheckTest {
    private static Constraints sized(long lo, long hi) {
        return new Constraints(Constraints.SIZE_CONSTRAINED, 0, 0L, 0L, 0L, 0L, 0, lo, hi,
                null, 0, null, 0, null, 0.0, 0.0);
    }

    private static Constraints capitals() {
        char[] table = new char[256];
        java.util.Arrays.fill(table, (char) 0xFFFF);
        for (char ch = 'A'; ch <= 'Z'; ch++) {
            table[ch] = (char) (ch - 'A');
        }
        return new Constraints(0, 0, 0L, 0L, 0L, 0L, 0, 0L, 0L, table, 0, null, 0, null, 0.0, 0.0);
    }

    private static String check(Asn1CharString s, Constraints c) {
        return ConstraintCheck.violation(new MemberRef.Primitive(s, null), c);
    }

    @Test
    void utf8SizeCountsCharacters() {
        assertNull(check(new Asn1Utf8String("ÄÖÜß"), sized(1, 4)));
        assertNotNull(check(new Asn1Utf8String("€€€€€"), sized(1, 4)));
    }

    @Test
    void bmpSizeCountsCharacters() {
        assertNull(check(new Asn1BmpString("AB"), sized(1, 2)));
        assertNotNull(check(new Asn1BmpString("ABC"), sized(1, 2)));
    }

    @Test
    void universalSizeCountsCharacters() {
        assertNull(check(new Asn1UniversalString("AB"), sized(1, 2)));
        assertNotNull(check(new Asn1UniversalString("ABC"), sized(1, 2)));
    }

    @Test
    void withoutFromTheKindsOwnCharacterSetApplies() {
        for (Constraints c : new Constraints[] {null, Constraints.UNCONSTRAINED, sized(1, 20)}) {
            assertNull(check(new Asn1NumericString("0123 456789"), c));
            assertNotNull(check(new Asn1NumericString("12X"), c));
            assertNotNull(check(new Asn1NumericString("1#3"), c));
            assertNull(check(new Asn1PrintableString("Az09 '()+,-./:=?"), c));
            assertNotNull(check(new Asn1PrintableString("a#"), c));
            assertNotNull(check(new Asn1PrintableString("a@"), c));
            assertNull(check(new Asn1Ia5String("\u0000a~\u007F"), c));
            assertNotNull(check(new Asn1Ia5String("\u00E9"), c));
            assertNull(check(new Asn1VisibleString(" ~"), c));
            assertNotNull(check(new Asn1VisibleString("a\u0001"), c));
            assertNotNull(check(new Asn1VisibleString("\u007F"), c));
            assertNull(check(new Asn1Utf8String("\u20AC"), c));
            assertNull(check(new Asn1GraphicString("\u0001\u00FF"), c));
        }
    }

    @Test
    void bmpAlphabetChecksEachCharacter() {
        assertNull(check(new Asn1BmpString("AZ"), capitals()));
        assertNotNull(check(new Asn1BmpString("a"), capitals()));
        assertNotNull(check(new Asn1BmpString("Ł"), capitals()));
    }

    @Test
    void malformedUtf8OctetIsOneCharacter() {
        Asn1Utf8String s = new Asn1Utf8String();
        s.setOctets(new byte[] {(byte) 0xC3, 'A', (byte) 0xE2, (byte) 0x82});
        assertArrayEquals(new int[] {0xC3, 'A', 0xE2, 0x82}, s.codePoints());
    }
}
