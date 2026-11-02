package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gen.xer_value_list.VlRec;
import gen.xer_value_list.VlTopBool;
import gen.xer_value_list.VlTopNull;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java XER leg of xer_value_list_test.asn1: SEQUENCE OF / SET OF a
 * BOOLEAN, ENUMERATED or NULL type is an XMLValueList (X.680 §25.5), its
 * values bare and laid out as asn1c writes them; decode also takes the
 * other forms asn1c reads (white-space between values, an open/close
 * pair for an empty element).
 */
class XerValueListTest {
    private static final Map<String, Supplier<AsMemberRef>> TYPES =
            Map.of("VlRec", VlRec::new, "VlTopBool", VlTopBool::new, "VlTopNull", VlTopNull::new);

    static Stream<Arguments> vectors() {
        return Vectors.load("xer_value_list_test.vectors").stream().map(v -> Arguments.of(v, TYPES.get(v.type())));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoes(Vectors.Vector vec, Supplier<AsMemberRef> type) {
        AsMemberRef v = type.get();
        BerObject.decode(v, vec.der());
        assertEquals(vec.asn1cXer().replaceAll("\n\n+", "\n"),
                new String(XerObject.encode(v), StandardCharsets.UTF_8).replaceAll("\n\n+", "\n"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cXer(Vectors.Vector vec, Supplier<AsMemberRef> type) {
        AsMemberRef v = type.get();
        XerObject.decode(v, vec.asn1cXer().getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    /** The vector's own single-line input form reads back to the same value. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesCompactInput(Vectors.Vector vec, Supplier<AsMemberRef> type) {
        AsMemberRef v = type.get();
        XerObject.decode(v, vec.xer().getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @Test
    void decodesSpacedValuesAndOpenClosePairs() {
        VlTopBool b = new VlTopBool();
        XerObject.decode(b, "<VlTopBool>\n  <false/>  <true/>\n</VlTopBool>".getBytes(StandardCharsets.UTF_8));
        assertEquals("<VlTopBool><false/><true/></VlTopBool>\n", new String(XerObject.encode(b), StandardCharsets.UTF_8));
        VlTopNull n = new VlTopNull();
        XerObject.decode(n, "<VlTopNull><NULL></NULL> <NULL/></VlTopNull>".getBytes(StandardCharsets.UTF_8));
        assertEquals(2, n.items().size());
    }
}
