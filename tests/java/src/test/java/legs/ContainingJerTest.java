package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.containing.Pick;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.jer.JerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.spec.ContainedText;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java JER leg of containing_test.asn1: a contained value (X.682 §11) is
 * written as its hex bytes, as asn1c does, unless its container config
 * asks for another form ({@code Pick.inner}, {@code "jer": "inline_raw"}),
 * which is written in the C++ runtime's layout; every form reads back to
 * the same bytes.
 */
class ContainingJerTest {
    private static final byte[] PICK_INNER = HexFormat.of().parseHex("80053003800105");
    private static final String PICK_INNER_INLINE_RAW = "{\"inner\":{\"containing\":{\"id\":5},\"raw\":\"3003800105\"}}";

    static Stream<Arguments> vectors() {
        return ContainingXerTest.vectors();
    }

    private static String jer(Asn1Pdu v, ContainedOptions opts) {
        return new String(JerObject.encode(v, opts), StandardCharsets.UTF_8);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void encodesAsAsn1cDoesUnlessInline(Vectors.Vector vec, Supplier<Asn1Pdu> type) {
        Asn1Pdu v = type.get();
        BerObject.decode(v, vec.der());
        String text = jer(v, null);
        if (java.util.Arrays.equals(vec.der(), PICK_INNER)) {
            assertEquals(PICK_INNER_INLINE_RAW, text);
            return;
        }
        assertEquals(Json.parse(vec.asn1cJer()), Json.parse(text), text);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cJer(Vectors.Vector vec, Supplier<Asn1Pdu> type) {
        Asn1Pdu v = type.get();
        JerObject.decode(v, vec.asn1cJer().getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    /** The inline form gives the inner value and the bytes its encoding stands for. */
    @Test
    void decodesInlineForm() {
        Pick p = new Pick();
        JerObject.decode(p, "{\"inner\":{\"containing\":{\"id\":5}}}".getBytes(StandardCharsets.UTF_8));
        assertEquals(ContainedStatus.DECODED, p.inner().status());
        assertEquals(5, p.inner().value().id().get());
        assertArrayEquals(PICK_INNER, BerObject.encode(p));
    }

    /** {@code raw} gives the bytes as they were, even where they differ from the value's own encoding. */
    @Test
    void rawIsAuthoritative() {
        Pick p = new Pick();
        JerObject.decode(p, PICK_INNER_INLINE_RAW.replace("3003800105", "300380010500").getBytes(StandardCharsets.UTF_8));
        assertEquals(5, p.inner().value().id().get());
        assertArrayEquals(HexFormat.of().parseHex("8006300380010500"), BerObject.encode(p));
    }

    /**
     * A per-call JER form replaces every row's: a field whose row says hex
     * is written inline and reads back to the same values (the inline form
     * does not carry viaConfig's zero padding); a per-call hex
     * form gives asn1c's text.
     */
    @Test
    void optionsOverrideTheRowsJerForm() {
        Vectors.Vector vec = ContainingTest.vectors().filter(v -> v.type().equals("Holder")).findFirst().orElseThrow();
        Asn1Pdu h = ContainingTest.TYPES.get("Holder").get();
        BerObject.decode(h, vec.der());
        ContainedOptions inline = new ContainedOptions(null, false, null, ContainedText.INLINE);
        String text = jer(h, inline);
        assertTrue(text.contains("\"viaConstraint\":{\"containing\":{\"id\":5}}"), text);
        Asn1Pdu back = ContainingTest.TYPES.get("Holder").get();
        JerObject.decode(back, text.getBytes(StandardCharsets.UTF_8), inline);
        assertEquals(text, jer(back, inline));
        String hex = jer(h, new ContainedOptions(null, false, null, ContainedText.HEX));
        assertEquals(Json.parse(vec.asn1cJer()), Json.parse(hex), hex);
    }
}
