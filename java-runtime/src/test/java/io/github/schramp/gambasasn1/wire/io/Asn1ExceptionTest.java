package io.github.schramp.gambasasn1.wire.io;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.per.PerWhole;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import org.junit.jupiter.api.Test;

/** One catch of {@link Asn1Exception} handles every encode and decode failure. */
class Asn1ExceptionTest {
    private static final Constraints ZERO_TO_SEVEN = new Constraints(Constraints.CONSTRAINED,
            PerWhole.rangeBits(0, 7), 0, 7, 0, 0, 0, 0, 0, null, 0, null, 0, null, 0.0, 0.0);

    @Test
    void decodeFailureIsAnAsn1Exception() {
        // INTEGER whose length octet promises two content octets, one present.
        Asn1Exception e = assertThrows(Asn1Exception.class,
                () -> BerObject.decode(new Asn1Integer(), new byte[] {0x02, 0x02, 0x01}));
        assertInstanceOf(DecodeException.class, e);
    }

    @Test
    void encodeFailureIsAnAsn1Exception() {
        Asn1Exception e = assertThrows(Asn1Exception.class,
                () -> PerObject.encode(new Asn1Integer(8), ZERO_TO_SEVEN));
        assertInstanceOf(EncodeException.class, e);
    }

    @Test
    void bothAreUnchecked() {
        assertInstanceOf(RuntimeException.class, new EncodeException("x"));
        assertInstanceOf(RuntimeException.class, new DecodeException("x", 0));
    }
}
