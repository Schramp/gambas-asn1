package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.builtin_alias_ber.Color;
import gen.builtin_alias_ber.Flag;
import gen.builtin_alias_ber.Nothing;
import gen.builtin_alias_ber.Num;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.jer.JerObject;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java JER leg of builtin_alias_ber_test.asn1: every builtin type assignment
 * writes the JSON value asn1c writes for each vector (X.697, compared as
 * JSON: asn1c indents its JER), and reads asn1c's text back to the same
 * value and DER.
 */
class BuiltinAliasJerTest {

    static Stream<Vectors.Vector> vectors() {
        return BuiltinAliasBerTest.vectors();
    }

    /**
     * A generated type's own {@code CONSTRAINTS} table, which a JER root value
     * is written under; an ENUMERATED type has none.
     */
    static Constraints constraints(AsMemberRef v) {
        try {
            return (Constraints) v.getClass().getField("CONSTRAINTS").get(null);
        } catch (NoSuchFieldException e) {
            return Constraints.UNCONSTRAINED;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    private static AsMemberRef fromDer(Vectors.Vector vec) {
        AsMemberRef v = BuiltinAliasBerTest.TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        return v;
    }

    private static String jer(AsMemberRef v) {
        return new String(JerObject.encode(v, constraints(v)), StandardCharsets.UTF_8);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoes(Vectors.Vector vec) {
        assertEquals(Json.parse(vec.asn1cJer()), Json.parse(jer(fromDer(vec))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cJer(Vectors.Vector vec) {
        AsMemberRef v = BuiltinAliasBerTest.TYPES.get(vec.type()).get();
        JerObject.decode(v, vec.asn1cJer().getBytes(StandardCharsets.UTF_8), constraints(v));
        assertEquals(fromDer(vec).asMemberRef(), v.asMemberRef());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    /** Our own text reads back to the same value (JER round trip). */
    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void roundTrips(Vectors.Vector vec) {
        AsMemberRef v = fromDer(vec);
        AsMemberRef back = BuiltinAliasBerTest.TYPES.get(vec.type()).get();
        JerObject.decode(back, jer(v).getBytes(StandardCharsets.UTF_8), constraints(back));
        assertEquals(v.asMemberRef(), back.asMemberRef());
        assertArrayEquals(vec.der(), BerObject.encode(back));
    }

    /** The compact layout of the C++ and Rust runtimes: no whitespace between tokens. */
    @Test
    void writesCompactText() {
        Num n = new Num();
        n.value.set(-129);
        assertEquals("-129", jer(n));
        assertEquals("null", jer(new Nothing()));
        Color c = new Color();
        BerObject.decode(c, new byte[] {0x0A, 0x01, 0x05});
        assertEquals("\"blue\"", jer(c));
    }

    @Test
    void wrongTokensAreRejected() {
        assertThrows(DecodeException.class, () -> JerObject.decode(new Flag(), bytes("\"true\""), Constraints.UNCONSTRAINED));
        assertThrows(DecodeException.class, () -> JerObject.decode(new Nothing(), bytes("0"), Constraints.UNCONSTRAINED));
        assertThrows(DecodeException.class, () -> JerObject.decode(new Num(), bytes("1.5"), Constraints.UNCONSTRAINED));
        assertThrows(DecodeException.class, () -> JerObject.decode(new Color(), bytes("\"purple\""), Constraints.UNCONSTRAINED));
        assertThrows(DecodeException.class, () -> JerObject.decode(new Num(), bytes("1 2"), Constraints.UNCONSTRAINED));
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
