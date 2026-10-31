package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.jer_escape.JeRec;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.jer.JerObject;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/**
 * Java leg of jer_escape_test.asn1 (RFC 8259 §7, X.697 §23.4 NOTE); mirrors
 * tests/jer/test_jer_escape.cpp. Each document's {@code text} value carries
 * escapes and must decode to the given text, or fail when the escape is
 * malformed; member and alternative names may be escaped too.
 */
class JerEscapeTest {

    private static JeRec unjer(String json) {
        JeRec v = new JeRec();
        JerObject.decode(v, json.getBytes(StandardCharsets.UTF_8));
        return v;
    }

    private static String doc(String escaped) {
        return "{\"text\":\"" + escaped + "\",\"alt\":{\"n\":1}}";
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
        "\\u0041|A",
        "\\u00e9|é",
        "\\u20AC|€",
        "\\ud83d\\ude00|😀",
        "\\b\\f|`\b\f`",
        "\\\"\\\\\\/\\n\\r\\t|`\"\\/\n\r\t`",
    })
    void escapesDecode(String escaped, String text) {
        assertEquals(text, unjer(doc(escaped)).text().get());
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {"\\ud83dx", "\\ud83d\\u0041", "\\ude00", "\\u12", "\\u00g1", "\\x41"})
    void malformedEscapesFail(String escaped) {
        assertThrows(DecodeException.class, () -> unjer(doc(escaped)));
    }

    @Test
    void escapedMemberAndAlternativeNames() {
        JeRec r = unjer("{\"\\u0074ext\":\"hi\",\"al\\u0074\":{\"\\u006eame\":\"x\"}}");
        assertEquals("hi", r.text().get());
        assertEquals("x", r.alt().name().get());
    }

    @Test
    void controlCharactersSurviveARoundTrip() {
        JeRec c = new JeRec();
        c.text().setOctets("a\u0001\b\f\u001Fbé".getBytes(StandardCharsets.UTF_8));
        Asn1Integer n = new Asn1Integer();
        n.set(1);
        c.alt().n(n);
        assertEquals(c, unjer(new String(JerObject.encode(c), StandardCharsets.UTF_8)));
    }

    @Test
    void missingRequiredMemberFails() {
        assertThrows(DecodeException.class, () -> unjer("{\"text\":\"x\"}"));
    }

    @Test
    void unknownMembersAreSkipped() {
        assertEquals("x", unjer("{\"zz\":{\"a\":[1,\"]\"]},\"text\":\"x\",\"alt\":{\"n\":2}}").text().get());
    }
}
