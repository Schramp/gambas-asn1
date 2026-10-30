package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gen.constraints_ber.Digits;
import gen.constraints_ber.Limits;
import gen.constraints_ber.Pick;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.spec.MemberMeta;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Inline member constraints (X.680 §51), against asn1c's DER for
 * tests/asn1/constraints_ber_test.asn1: each constrained member,
 * alternative and collection row references its own table, and BER is
 * unaffected by it.
 */
class ConstraintsBerTest {
    private static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("Limits", Limits::new),
            Map.entry("Pick", Pick::new),
            Map.entry("Digits", Digits::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("constraints_ber_test.vectors").stream();
    }

    private static Constraints row(List<MemberMeta> rows, String name) {
        return rows.stream().filter(r -> r.name().equals(name)).findFirst().orElseThrow().constraints();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @Test
    void everyTypeHasAVector() {
        List<String> covered = vectors().map(Vectors.Vector::type).distinct().sorted().toList();
        assertEquals(TYPES.keySet().stream().sorted().toList(), covered);
    }

    @Test
    void rowsCarryTheirOwnConstraints() {
        List<MemberMeta> rows = Limits.SPEC.members();
        Constraints b = row(rows, "byte");
        assertEquals(Constraints.CONSTRAINED, b.flags());
        assertEquals(0, b.lowerBound());
        assertEquals(255, b.upperBound());
        assertEquals(8, b.rangeBits());
        assertEquals(Constraints.CONSTRAINED | Constraints.EXTENSIBLE, row(rows, "neg").flags());
        assertEquals(Constraints.SEMI_CONSTRAINED, row(rows, "from").flags() & Constraints.SEMI_CONSTRAINED);
        assertEquals(-1L, row(rows, "big").upperU64());
        Constraints f = row(rows, "fixed");
        assertEquals(4, f.sizeLower());
        assertEquals(4, f.sizeUpper());
        Constraints sized = row(rows, "sized");
        assertEquals(1, sized.sizeLower());
        assertEquals(3, sized.sizeUpper());
        assertEquals(10, row(Pick.SPEC.alternatives().stream()
                .map(a -> new MemberMeta(a.name(), null, false, a.ber(), a.constraints(), null, null)).toList(), "num")
                .upperBound());
    }
}
