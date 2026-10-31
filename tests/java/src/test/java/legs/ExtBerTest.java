package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gen.ext_ber.Outer1;
import gen.ext_ber.Outer2;
import gen.ext_ber.S1;
import gen.ext_ber.S2;
import gen.ext_ber.V1;
import gen.ext_ber.V2;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Extensibility under BER, against asn1c's DER for
 * tests/asn1/ext_ber_test.asn1: the extension marker leaves the encoding
 * unchanged (X.690 §8.1.1.4), and a decoder of an earlier version skips
 * the extension additions it does not know (X.680 §7.1, §7.2), also inside
 * a nested type followed by a later member (X.680 §7.3).
 */
class ExtBerTest {
    static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("V1", V1::new),
            Map.entry("V2", V2::new),
            Map.entry("Outer1", Outer1::new),
            Map.entry("Outer2", Outer2::new),
            Map.entry("S1", S1::new),
            Map.entry("S2", S2::new));

    private static final List<Vectors.Vector> ROWS = Vectors.load("ext_ber_test.vectors");

    static Stream<Vectors.Vector> vectors() {
        return ROWS.stream();
    }

    private static Vectors.Vector row(String xer) {
        return ROWS.stream().filter(v -> v.xer().equals(xer)).findFirst().orElseThrow(() -> new AssertionError("no vector " + xer));
    }

    /** A later version's value, and the value an earlier version's decoder reads from it. */
    static Stream<Arguments> versions() {
        return Stream.of(
                Arguments.of("<V2><id>3</id><flag><false/></flag><level>9</level></V2>",
                        "<V1><id>3</id><flag><false/></flag></V1>"),
                Arguments.of("<V2><id>4</id><note>x</note><flag><true/></flag><level>1</level><name>ab</name><extra>0102</extra></V2>",
                        "<V1><id>4</id><note>x</note><flag><true/></flag></V1>"),
                Arguments.of("<V2><id>5</id><extra>FF</extra></V2>",
                        "<V1><id>5</id></V1>"),
                Arguments.of("<Outer2><inner><id>6</id><flag><true/></flag><level>2</level><extra>AA</extra></inner><tail>7</tail></Outer2>",
                        "<Outer1><inner><id>6</id><flag><true/></flag></inner><tail>7</tail></Outer1>"),
                Arguments.of("<S2><a>1</a><b><true/></b><c>z</c></S2>",
                        "<S1><a>1</a></S1>"),
                Arguments.of("<S2><a>2</a><c>q</c></S2>",
                        "<S1><a>2</a></S1>"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("versions")
    void earlierVersionSkipsUnknownAdditions(String later, String earlier) {
        Vectors.Vector from = row(later);
        Vectors.Vector to = row(earlier);
        Asn1Pdu v = TYPES.get(to.type()).get();
        BerObject.decode(v, from.der());
        assertArrayEquals(to.der(), BerObject.encode(v));
        Asn1Pdu expected = TYPES.get(to.type()).get();
        BerObject.decode(expected, to.der());
        assertEquals(expected, v);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("versions")
    void laterVersionKeepsEveryAddition(String later, String earlier) {
        Vectors.Vector from = row(later);
        Asn1Pdu v = TYPES.get(from.type()).get();
        BerObject.decode(v, from.der());
        assertArrayEquals(from.der(), BerObject.encode(v));
    }
}
