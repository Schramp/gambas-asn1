package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gen.tagging_ber.AutoChoice;
import gen.tagging_ber.AutoRec;
import gen.tagging_ber.AutoSet;
import gen.tagging_ber.ExpRec;
import gen.tagging_ber.ImpRec;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The tagging matrix under BER (X.680 §31.2, §25.3; X.690 §8.14), against
 * asn1c's DER for tests/asn1/tagging_ber_test.asn1: the same constructs
 * under EXPLICIT, IMPLICIT and AUTOMATIC module tagging decode and
 * re-encode byte for byte.
 */
class TaggingBerTest {
    private static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("ExpRec", ExpRec::new),
            Map.entry("ImpRec", ImpRec::new),
            Map.entry("AutoRec", AutoRec::new),
            Map.entry("AutoSet", AutoSet::new),
            Map.entry("AutoChoice", AutoChoice::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("tagging_ber_test.vectors").stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    /** A decoded value equals one decoded again from its own encoding. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void reencodingIsStable(Vectors.Vector vec) {
        Asn1Pdu a = TYPES.get(vec.type()).get();
        BerObject.decode(a, vec.der());
        Asn1Pdu b = TYPES.get(vec.type()).get();
        BerObject.decode(b, BerObject.encode(a));
        assertEquals(a, b);
    }

    @Test
    void everyTypeHasAVector() {
        List<String> covered = vectors().map(Vectors.Vector::type).distinct().sorted().toList();
        assertEquals(TYPES.keySet().stream().sorted().toList(), covered);
    }
}
