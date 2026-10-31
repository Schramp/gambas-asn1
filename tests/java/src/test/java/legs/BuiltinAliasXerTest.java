package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.builtin_alias_ber.Bits;
import gen.builtin_alias_ber.Flag;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;

/**
 * Java XER leg of builtin_alias_ber_test.asn1: every builtin type assignment
 * writes asn1c's own BASIC-XER text for the value of each vector byte for
 * byte (X.693), and reads that text back to the same value.
 */
class BuiltinAliasXerTest {

    static Stream<Vectors.Vector> vectors() {
        return BuiltinAliasBerTest.vectors();
    }

    private static AsMemberRef fromDer(Vectors.Vector vec) {
        AsMemberRef v = BuiltinAliasBerTest.TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        return v;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoes(Vectors.Vector vec) {
        assertEquals(vec.asn1cXer(), new String(XerObject.encode(fromDer(vec)), StandardCharsets.UTF_8));
    }

    /**
     * asn1c's text reads back to the DER's value and writes the same text
     * again, except a REAL its 15 decimals cannot hold (such as -2.5E-300,
     * written {@code -0.0}): that text reads back to the number it says.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cXer(Vectors.Vector vec) {
        AsMemberRef v = BuiltinAliasBerTest.TYPES.get(vec.type()).get();
        byte[] text = vec.asn1cXer().getBytes(StandardCharsets.UTF_8);
        XerObject.decode(v, text);
        AsMemberRef expected = fromDer(vec);
        String number = vec.asn1cXer().replaceAll("<[^>]*>", "").strip();
        if (expected.asMemberRef() instanceof MemberRef.Primitive(Asn1Real r) && !number.isEmpty()
                && Double.compare(r.value(), Double.parseDouble(number)) != 0) {
            assertEquals(new MemberRef.Primitive(new Asn1Real(Double.parseDouble(number))), v.asMemberRef());
            return;
        }
        assertEquals(expected.asMemberRef(), v.asMemberRef());
        assertArrayEquals(vec.der(), BerObject.encode(v));
        assertArrayEquals(text, XerObject.encode(v));
    }

    /** asn1c also accepts the empty-element form for an empty value. */
    @Test
    void decodesEmptyElement() {
        Bits v = new Bits();
        XerObject.decode(v, "<Bits/>".getBytes(StandardCharsets.UTF_8));
        assertEquals(0, v.value.bitCount());
    }

    /** Text BOOLEAN is an asn1c extension: lenient only. */
    @Test
    void textBooleanIsLenientOnly() {
        byte[] text = "<Flag>true</Flag>".getBytes(StandardCharsets.UTF_8);
        assertThrows(DecodeException.class, () -> XerObject.decode(new Flag(), text));
        Flag v = new Flag();
        XerObject.decodeLenient(v, text);
        assertEquals(true, v.value.get());
    }

    @Test
    void wrongElementIsRejected() {
        assertThrows(DecodeException.class,
                () -> XerObject.decode(new Flag(), "<Other><true/></Other>".getBytes(StandardCharsets.UTF_8)));
    }
}
