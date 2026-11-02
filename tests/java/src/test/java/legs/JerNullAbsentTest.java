package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.jer_null_absent.JnRec;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.jer.JerObject;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Java leg of jer_null_absent_test.asn1 (X.697 §27.3.4); mirrors
 * tests/jer/test_jer_null_absent.cpp. {@code null} for an OPTIONAL or
 * DEFAULT member means the member is absent, except for a member whose type
 * is NULL, where {@code null} is the value.
 */
class JerNullAbsentTest {

    private static JnRec unjer(String json) {
        JnRec v = new JnRec();
        JerObject.decode(v, json.getBytes(StandardCharsets.UTF_8));
        return v;
    }

    private static String jer(JnRec v) {
        return new String(JerObject.encode(v), StandardCharsets.UTF_8);
    }

    @Test
    void nullMeansAbsent() {
        JnRec r = unjer("{\"a\":1,\"b\":null,\"c\":null,\"o\":null,\"s\":null}");
        assertEquals(1, r.a().get());
        assertNull(r.b());
        assertNull(r.o());
        assertNull(r.s());
        assertTrue(r.c() == null || r.c().get(), "DEFAULT member takes its default");
    }

    @Test
    void sameAsLeavingTheMembersOut() {
        JnRec withNull = unjer("{\"a\":1,\"b\":null,\"c\":null,\"o\":null,\"s\":null}");
        assertEquals(jer(unjer("{\"a\":1}")), jer(withNull));
        assertFalse(jer(withNull).contains("null"));
    }

    @Test
    void whitespaceAroundNull() {
        JnRec r = unjer("{ \"a\" : 2 , \"b\" : null , \"n\" : null }");
        assertNull(r.b());
        assertNotNull(r.n(), "null for a NULL member is its value");
    }

    @Test
    void nullForMandatoryMemberFails() {
        assertThrows(DecodeException.class, () -> unjer("{\"a\":null}"));
    }

    @Test
    void nullxIsNotNull() {
        assertThrows(DecodeException.class, () -> unjer("{\"a\":1,\"b\":nullx}"));
    }
}
