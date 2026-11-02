package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java XER leg of the constructed-type codec tests: for each vector, the
 * value asn1c's DER decodes to is written as asn1c's own BASIC-XER text
 * byte for byte (X.693), and that text reads back to the same value.
 *
 * <p>Two asn1c layouts the runtimes do not copy, both valid BASIC-XER:
 * asn1c puts an empty line between SET members (its SEQUENCE layout has
 * none), and it leaves out some absent DEFAULT members (a REAL one, an
 * INTEGER one in a SET) that the runtimes write with the DEFAULT value
 * decode filled in. The comparison drops empty lines, and for a
 * default_ber_test value accepts extra member lines.
 */
class XerLegTest {

    private static final Set<String> DEFAULT_ROWS = DefaultBerTest.vectors().map(Vectors.Vector::xer)
            .collect(Collectors.toSet());

    private static String withoutEmptyLines(String text) {
        return text.replaceAll("\n\n+", "\n");
    }

    /** Whether {@code lines} holds every line of {@code sub} in the same order. */
    private static boolean inOrderSubset(List<String> sub, List<String> lines) {
        int j = 0;
        for (String line : lines) {
            if (j < sub.size() && sub.get(j).equals(line)) {
                j++;
            }
        }
        return j == sub.size();
    }

    private static Stream<Arguments> rows(Map<String, ? extends Supplier<? extends AsMemberRef>> types,
            Stream<Vectors.Vector> vectors) {
        return vectors.filter(v -> types.containsKey(v.type())).map(v -> Arguments.of(v, types.get(v.type())));
    }

    static Stream<Arguments> vectors() {
        return Stream.of(
                rows(ChoiceBerTest.TYPES, ChoiceBerTest.vectors()),
                rows(ConstraintsBerTest.TYPES, ConstraintsBerTest.vectors()),
                rows(DefaultBerTest.TYPES, DefaultBerTest.vectors()),
                rows(ExtBerTest.TYPES, ExtBerTest.vectors()),
                rows(RecursionBerTest.TYPES, RecursionBerTest.vectors()),
                rows(TaggingBerTest.TYPES, TaggingBerTest.vectors()),
                rows(SeqOfBerTest.TYPES, SeqOfBerTest.vectors()),
                rows(SequenceBerTest.TYPES, SequenceBerTest.vectors()),
                rows(SetBerTest.TYPES, SetBerTest.vectors())).flatMap(s -> s);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoes(Vectors.Vector vec, Supplier<? extends AsMemberRef> type) {
        AsMemberRef v = type.get();
        BerObject.decode(v, vec.der());
        String expected = withoutEmptyLines(vec.asn1cXer());
        String actual = withoutEmptyLines(new String(XerObject.encode(v), StandardCharsets.UTF_8));
        if (DEFAULT_ROWS.contains(vec.xer()) && !expected.equals(actual)) {
            assertTrue(inOrderSubset(expected.lines().toList(), actual.lines().toList()), () -> actual);
            return;
        }
        assertEquals(expected, actual);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cXer(Vectors.Vector vec, Supplier<? extends AsMemberRef> type) {
        AsMemberRef v = type.get();
        XerObject.decode(v, vec.asn1cXer().getBytes(StandardCharsets.UTF_8));
        AsMemberRef expected = type.get();
        BerObject.decode(expected, vec.der());
        assertEquals(expected, v);
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }
}
