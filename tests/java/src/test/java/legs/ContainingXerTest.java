package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gen.containing.Pick;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java XER leg of containing_test.asn1: a contained value (X.682 §11) is
 * written as its hex bytes, as asn1c does, unless its container config
 * asks for the inline form ({@code Pick.inner}, {@code "xer": "inline"}),
 * which is written in the C++ runtime's layout; both forms read back to
 * the same bytes.
 */
class ContainingXerTest {
    private static final byte[] PICK_INNER = HexFormat.of().parseHex("80053003800105");
    private static final String PICK_INNER_INLINE = """
            <Pick>
                <inner>
                    <Inner>
                        <id>5</id>
                    </Inner>
                </inner>
            </Pick>
            """;

    static Stream<Arguments> vectors() {
        return ContainingTest.vectors().map(v -> Arguments.of(v, ContainingTest.TYPES.get(v.type())));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoesUnlessInline(Vectors.Vector vec, Supplier<Asn1Pdu> type) {
        Asn1Pdu v = type.get();
        BerObject.decode(v, vec.der());
        String expected = java.util.Arrays.equals(vec.der(), PICK_INNER) ? PICK_INNER_INLINE : vec.asn1cXer();
        assertEquals(expected, new String(XerObject.encode(v), StandardCharsets.UTF_8));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cXer(Vectors.Vector vec, Supplier<Asn1Pdu> type) {
        Asn1Pdu v = type.get();
        XerObject.decode(v, vec.asn1cXer().getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    /** The inline form gives the inner value and the bytes its encoding stands for. */
    @Test
    void decodesInlineForm() {
        Pick p = new Pick();
        XerObject.decode(p, PICK_INNER_INLINE.getBytes(StandardCharsets.UTF_8));
        assertEquals(ContainedStatus.DECODED, p.inner().status());
        assertEquals(5, p.inner().value().id().get());
        assertArrayEquals(PICK_INNER, BerObject.encode(p));
    }

    /** A raw comment after the inline value gives the bytes as they were. */
    @Test
    void decodesInlineRawForm() {
        String text = PICK_INNER_INLINE.replace("</Inner>\n", "</Inner>\n        <!-- raw: 3003800105 -->\n");
        Pick p = new Pick();
        XerObject.decode(p, text.getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(PICK_INNER, BerObject.encode(p));
    }
}
