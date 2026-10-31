package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.real_jer_base.Bases;
import io.github.schramp.gambasasn1.wire.jer.JerObject;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Java leg of real_jer_base_test.asn1 (X.697 §23.1.3, §23.1.4); mirrors
 * tests/jer/test_real_jer_base.cpp. A base-10 value is a bare JSON number
 * where the JER-visible base constraint admits only 10, and a base10Value
 * object otherwise.
 */
class RealJerBaseTest {
    private static final Asn1Real D = Asn1Real.decimal(false, "1456", -2);

    private static String jer(Bases v) {
        return new String(JerObject.encode(v), StandardCharsets.UTF_8);
    }

    private static Bases unjer(String text) {
        Bases v = new Bases();
        JerObject.decode(v, text.getBytes(StandardCharsets.UTF_8));
        return v;
    }

    private static Bases allD() {
        Bases v = new Bases();
        v.b10().value.set(D);
        v.b2().value.set(D);
        v.inline().set(D);
        v.x697().set(D);
        v.both().set(D);
        v.plain().set(D);
        return v;
    }

    @Test
    void base10FormFollowsTheConstraint() {
        assertEquals("{\"b10\":1456E-2,\"b2\":{\"base10Value\":1456E-2},\"inline\":1456E-2,\"x697\":1456E-2,"
                + "\"both\":{\"base10Value\":1456E-2},\"plain\":{\"base10Value\":1456E-2}}", jer(allD()));
    }

    @Test
    void everyMemberDecodesBackToTheSameDecimal() {
        assertEquals(allD(), unjer(jer(allD())));
    }

    @Test
    void aJsonNumberIsBase10OnlyWhereTheBaseIsConstrainedTo10() {
        Bases n = unjer("{\"b10\":14.56,\"b2\":14.56,\"inline\":14.56,\"x697\":14.56,\"both\":14.56,\"plain\":14.56}");
        assertEquals(D, n.b10().value);
        assertEquals(D, n.inline());
        assertEquals(D, n.x697());
        assertEquals(Asn1Real.Storage.DOUBLE, n.b2().value.storage());
        assertEquals(Asn1Real.Storage.DOUBLE, n.both().storage());
        assertEquals(Asn1Real.Storage.DOUBLE, n.plain().storage());
    }

    /** §23.1.2: a base-2 value is a JSON number under base (10) too. */
    @Test
    void aBase2ValueIsANumberUnderBase10() {
        Bases b = new Bases();
        b.b10().value.set(0.5);
        assertTrue(jer(b).startsWith("{\"b10\":0.5,"), jer(b));
    }
}
