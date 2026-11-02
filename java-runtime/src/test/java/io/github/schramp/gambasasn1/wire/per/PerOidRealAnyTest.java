package io.github.schramp.gambasasn1.wire.per;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.types.Asn1Any;
import io.github.schramp.gambasasn1.wire.types.Asn1ObjectIdentifier;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1RelativeOid;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * OBJECT IDENTIFIER, RELATIVE-OID, REAL and ANY in unaligned PER (X.691
 * §24, §25, §15, §11.2): BER contents octets after a general length. The
 * asn1c vectors are in the builtin_alias PER leg; these cover the edges.
 */
class PerOidRealAnyTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    @Test
    void contentsAfterALength() {
        assertArrayEquals(hex("03550403"), PerObject.encode(new Asn1ObjectIdentifier(new long[] {2, 5, 4, 3})));
        assertArrayEquals(hex("020102"), PerObject.encode(new Asn1RelativeOid(new long[] {1, 2})));
        assertArrayEquals(hex("0140"), PerObject.encode(new Asn1Real(Double.POSITIVE_INFINITY)));
        assertArrayEquals(hex("03020105"), PerObject.encode(new Asn1Any(hex("020105"))));
    }

    /** X.690 §8.5.2: REAL zero has no contents octets, so its PER field is the length 0. */
    @Test
    void realZeroIsAnEmptyField() {
        assertArrayEquals(hex("00"), PerObject.encode(new Asn1Real(0.0)));
        Asn1Real r = new Asn1Real(7.0);
        PerObject.decode(r, hex("00"));
        assertEquals(0.0, r.value());
    }

    @Test
    void malformedContentsFail() {
        // The last subidentifier octet still has bit 8 set (X.690 §8.19.2).
        assertThrows(DecodeException.class, () -> PerObject.decode(new Asn1ObjectIdentifier(), hex("025581")));
        assertThrows(DecodeException.class, () -> PerObject.decode(new Asn1RelativeOid(), hex("0181")));
        // The length says three octets, two follow.
        assertThrows(DecodeException.class, () -> PerObject.decode(new Asn1Any(), hex("030201")));
    }
}
