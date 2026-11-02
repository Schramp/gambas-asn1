package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.jer.JerObject;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java JER leg of the constructed-type codec tests: for each vector, the
 * value asn1c's DER decodes to is written as the JSON value asn1c writes
 * (X.697, compared as JSON), asn1c's text reads back to the same value and
 * DER, and our own text round-trips.
 *
 * <p>Two asn1c layouts the runtimes do not copy: asn1c leaves out some
 * absent DEFAULT members that the runtimes write with the DEFAULT value
 * decode filled in, as in its XER (for a default_ber_test value, asn1c's
 * members must be a subset of ours), and it nests the members of an
 * extension addition group in an {@code extN} object, where X.697 §27.3.1
 * has one member per component (asn1c's text is flattened first).
 */
class JerLegTest {

    private static final Set<String> DEFAULT_ROWS = DefaultBerTest.vectors().map(Vectors.Vector::xer)
            .collect(Collectors.toSet());

    static Stream<org.junit.jupiter.params.provider.Arguments> vectors() {
        return XerLegTest.vectors();
    }

    static String jer(AsMemberRef v) {
        byte[] text = v instanceof Asn1Pdu ? JerObject.encode(v) : JerObject.encode(v, BuiltinAliasJerTest.constraints(v));
        return new String(text, StandardCharsets.UTF_8);
    }

    static void unjer(AsMemberRef v, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (v instanceof Asn1Pdu) {
            JerObject.decode(v, bytes);
        } else {
            JerObject.decode(v, bytes, BuiltinAliasJerTest.constraints(v));
        }
    }

    /** Whether every member of {@code sub}, at every level, is in {@code full} with the same value. */
    private static boolean subset(Object sub, Object full) {
        if (sub instanceof Map<?, ?> s && full instanceof Map<?, ?> f) {
            return s.entrySet().stream().allMatch(e -> f.containsKey(e.getKey()) && subset(e.getValue(), f.get(e.getKey())));
        }
        if (sub instanceof List<?> s && full instanceof List<?> f) {
            if (s.size() != f.size()) {
                return false;
            }
            for (int i = 0; i < s.size(); i++) {
                if (!subset(s.get(i), f.get(i))) {
                    return false;
                }
            }
            return true;
        }
        return sub.equals(full);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoes(Vectors.Vector vec, Supplier<? extends AsMemberRef> type) {
        AsMemberRef v = type.get();
        BerObject.decode(v, vec.der());
        Object expected = Json.flattenGroups(Json.parse(vec.asn1cJer()));
        String text = jer(v);
        Object actual = Json.parse(text);
        if (DEFAULT_ROWS.contains(vec.xer()) && !expected.equals(actual)) {
            assertTrue(subset(expected, actual), () -> text);
            return;
        }
        assertEquals(expected, actual, text);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cJer(Vectors.Vector vec, Supplier<? extends AsMemberRef> type) {
        AsMemberRef v = type.get();
        unjer(v, Json.write(Json.flattenGroups(Json.parse(vec.asn1cJer()))));
        AsMemberRef expected = type.get();
        BerObject.decode(expected, vec.der());
        assertEquals(expected, v);
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void roundTrips(Vectors.Vector vec, Supplier<? extends AsMemberRef> type) {
        AsMemberRef v = type.get();
        BerObject.decode(v, vec.der());
        AsMemberRef back = type.get();
        unjer(back, jer(v));
        assertEquals(v, back);
        assertArrayEquals(vec.der(), BerObject.encode(back));
    }
}
