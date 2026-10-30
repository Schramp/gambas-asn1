package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.builtin_alias_ber.ExplicitFlag;
import gen.builtin_alias_ber.ExplicitNothing;
import gen.builtin_alias_ber.Flag;
import gen.builtin_alias_ber.Hyphen_Flag;
import gen.builtin_alias_ber.ImplicitFlag;
import gen.builtin_alias_ber.ImplicitNothing;
import gen.builtin_alias_ber.Nothing;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java leg of builtin_alias_ber_test.asn1: every generated type assignment
 * encodes asn1c's DER byte for byte and decodes it back, under its natural
 * tag, IMPLICIT and EXPLICIT (X.690 §8.14).
 */
class BuiltinAliasBerTest {
    private static final Map<String, Supplier<AsMemberRef>> TYPES = Map.of(
            "Flag", Flag::new,
            "ImplicitFlag", ImplicitFlag::new,
            "ExplicitFlag", ExplicitFlag::new,
            "Hyphen-Flag", Hyphen_Flag::new,
            "Nothing", Nothing::new,
            "ImplicitNothing", ImplicitNothing::new,
            "ExplicitNothing", ExplicitNothing::new);

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("builtin_alias_ber_test.vectors").stream();
    }

    /** The value a vector's XER names: BOOLEAN's {@code <true/>} or {@code <false/>}. */
    private static void setFromXer(AsMemberRef v, String xer) {
        if (v.asMemberRef() instanceof MemberRef.Primitive(Asn1Boolean b)) {
            b.set(xer.contains("<true/>"));
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoes(Vectors.Vector vec) {
        AsMemberRef v = TYPES.get(vec.type()).get();
        setFromXer(v, vec.xer());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDer(Vectors.Vector vec) {
        AsMemberRef v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        AsMemberRef expected = TYPES.get(vec.type()).get();
        setFromXer(expected, vec.xer());
        assertEquals(expected.asMemberRef(), v.asMemberRef());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @Test
    void everyTypeHasAVector() {
        List<String> covered = vectors().map(Vectors.Vector::type).distinct().sorted().toList();
        assertEquals(TYPES.keySet().stream().sorted().toList(), covered);
    }

    @Test
    void ownXerNameIsTheAsn1Name() {
        assertEquals("Hyphen-Flag", new Hyphen_Flag().ownElementXerName());
        assertEquals("ImplicitNothing", new ImplicitNothing().ownElementXerName());
    }

    @Test
    void anotherTypesTagIsRejected() {
        byte[] flag = BerObject.encode(new Flag());
        assertThrows(DecodeException.class, () -> BerObject.decode(new ImplicitFlag(), flag));
        assertThrows(DecodeException.class, () -> BerObject.decode(new ExplicitFlag(), flag));
        assertThrows(DecodeException.class, () -> BerObject.decode(new ImplicitNothing(), BerObject.encode(new Nothing())));
    }
}
