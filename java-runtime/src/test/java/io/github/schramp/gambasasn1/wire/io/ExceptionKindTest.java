package io.github.schramp.gambasasn1.wire.io;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.per.PerWhole;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import org.junit.jupiter.api.Test;

/**
 * A decode failure is a checked exception, since the input comes from outside
 * the program; an encode failure is an unchecked one, since the value is the
 * caller's own.
 */
class ExceptionKindTest {
    private static final Constraints ZERO_TO_SEVEN = new Constraints(Constraints.CONSTRAINED,
            PerWhole.rangeBits(0, 7), 0, 7, 0, 0, 0, 0, 0, null, 0, null, 0, null, 0.0, 0.0);

    @Test
    void decodeExceptionIsChecked() {
        assertTrue(Exception.class.isAssignableFrom(DecodeException.class));
        assertFalse(RuntimeException.class.isAssignableFrom(DecodeException.class));
    }

    @Test
    void encodeExceptionIsUnchecked() {
        assertTrue(RuntimeException.class.isAssignableFrom(EncodeException.class));
    }

    @Test
    void truncatedInputThrowsDecodeException() {
        // INTEGER whose length octet promises two content octets, one present.
        assertThrows(DecodeException.class,
                () -> BerObject.decode(new Asn1Integer(), new byte[] {0x02, 0x02, 0x01}));
    }

    @Test
    void valueOutsideItsConstraintsThrowsEncodeException() {
        assertThrows(EncodeException.class, () -> PerObject.encode(new Asn1Integer(8), ZERO_TO_SEVEN));
    }
}
