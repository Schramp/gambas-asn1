package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.default_ber.Color;
import gen.default_ber.Rec;
import gen.default_ber.Unordered;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * DEFAULT under BER, against asn1c's DER for tests/asn1/default_ber_test.asn1:
 * decode fills an absent member with its default (X.680 §25.6), and encode
 * leaves out a member equal to it (X.690 §11.5).
 */
class DefaultBerTest {
    private static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("Rec", Rec::new),
            Map.entry("Unordered", Unordered::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("default_ber_test.vectors").stream();
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @Test
    void newValueHoldsEveryDefault() {
        Rec r = new Rec();
        assertTrue(r.flag().get());
        assertEquals(5, r.num().get());
        assertEquals(300, r.big().get());
        assertEquals("anon", r.name().get());
        assertEquals(Color.Value.green, r.color().get());
        assertEquals(7, r.count().value.get());
        assertEquals(0.5, r.ratio().value());
    }

    @Test
    void absentMembersDecodeToTheirDefaults() {
        Rec r = new Rec();
        r.num().set(9);
        r.name().set("zz");
        BerObject.decode(r, hex("3003800101"));
        assertEquals(1, r.id().get());
        assertEquals(5, r.num().get());
        assertEquals("anon", r.name().get());
        assertEquals(new Rec().ratio().value(), r.ratio().value());
    }

    @Test
    void membersSetBackToTheirDefaultAreLeftOut() {
        Rec r = new Rec();
        r.id().set(1);
        r.ratio().set(2.0);
        assertFalse(r.isDefaultEqual(7));
        r.ratio().set(0.5);
        assertTrue(r.isDefaultEqual(7));
        assertArrayEquals(hex("3003800101"), BerObject.encode(r));
    }

    @Test
    void nullMeansTheDefault() {
        Unordered u = new Unordered();
        u.a().set(2);
        u.a(null);
        assertEquals(1, u.a().get());
        u.c().set("z");
        assertArrayEquals(hex("310382017A"), BerObject.encode(u));
    }

    @Test
    void equalityComparesDefaultsAsValues() {
        assertEquals(new Rec(), new Rec());
        Rec r = new Rec();
        r.num().set(6);
        assertFalse(new Rec().equals(r));
    }
}
