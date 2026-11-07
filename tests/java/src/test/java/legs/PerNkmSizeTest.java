package legs;

import io.github.schramp.gambasasn1.wire.io.DecodeException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.per_nkm_size.Rec;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.types.Asn1GeneralString;
import io.github.schramp.gambasasn1.wire.types.Asn1Ia5String;
import io.github.schramp.gambasasn1.wire.types.Asn1Utf8String;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Unaligned PER of a SIZE on non-known-multiplier strings under
 * --per-nkm-size=strict, the default (X.691 §10.3.18, §30.6): the SIZE is
 * not PER-visible, so the length is unconstrained and no extension bit is
 * written, but it still restricts the values (§10.3 note). Expected bytes
 * are Erlang/OTP asn1's, as in tests/per/test_per_nkm_size.cpp.
 */
class PerNkmSizeTest {
    private static Rec value() {
        Rec r = new Rec();
        r.s(new Asn1Utf8String("ab"));
        r.ext(new Asn1Utf8String("abc"));
        r.named().value.set("xyz");
        r.g(new Asn1GeneralString("AB"));
        r.ia5(new Asn1Ia5String("hi"));
        return r;
    }

    @Test
    void strictEncodingMatchesErlang() throws DecodeException {
        byte[] want = HexFormat.of().parseHex("026162036162630378797a0241420b4690");
        assertArrayEquals(want, PerObject.encode(value()));
        Rec back = new Rec();
        PerObject.decode(back, want);
        assertEquals("ab", back.s().get());
        assertEquals("abc", back.ext().get());
        assertEquals("xyz", back.named().value.get());
        assertEquals("AB", back.g().get());
        assertEquals("hi", back.ia5().get());
    }

    @Test
    void lengthOutsideNonExtensibleSizeFails() {
        Rec r = value();
        r.s(new Asn1Utf8String("x".repeat(40)));
        assertThrows(EncodeException.class, () -> PerObject.encode(r));
    }

    @Test
    void sizeCountsCharactersNotOctets() throws DecodeException {
        Rec r = value();
        r.s(new Asn1Utf8String("\u00C4".repeat(32)));
        Rec back = new Rec();
        PerObject.decode(back, PerObject.encode(r));
        assertEquals("\u00C4".repeat(32), back.s().get());
        r.s(new Asn1Utf8String("\u00C4".repeat(33)));
        assertThrows(EncodeException.class, () -> PerObject.encode(r));
    }

    @Test
    void lengthOutsideExtensibleRootEncodes() throws DecodeException {
        Rec r = value();
        r.ext(new Asn1Utf8String("y".repeat(200)));
        Rec back = new Rec();
        PerObject.decode(back, PerObject.encode(r));
        assertEquals("y".repeat(200), back.ext().get());
    }
}
