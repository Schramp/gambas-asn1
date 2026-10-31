package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.containing.Envelope;
import gen.containing.Holder;
import gen.containing.Inner;
import gen.containing.Kind;
import gen.containing.Pick;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.spec.Containing;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Contained values (X.682 §11) under BER, against asn1c's DER for
 * tests/asn1/containing_test.asn1 with containing_test.container.json:
 * the inner value is decoded with the outer one, the raw bytes stay
 * authoritative, and a changed inner value re-encodes.
 */
class ContainingTest {
    private static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("Inner", Inner::new),
            Map.entry("Holder", Holder::new),
            Map.entry("Pick", Pick::new),
            Map.entry("Envelope", Envelope::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("containing_test.vectors").stream();
    }

    private static Vectors.Vector row(String type, String xerPart) {
        return vectors().filter(v -> v.type().equals(type) && v.xer().contains(xerPart)).findFirst().orElseThrow();
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @Test
    void decodesEachContainedMember() {
        Holder h = new Holder();
        BerObject.decode(h, row("Holder", "<plain/>").der());
        assertEquals(ContainedStatus.DECODED, h.viaConstraint().status());
        assertEquals(5, h.viaConstraint().value().id().get());
        assertEquals(-300, h.viaAlias().value().id().get());
        assertEquals("abc", h.viaAlias().value().name().get());
        assertEquals(ContainedStatus.DECODED, h.viaConfig().status());
        assertEquals(5, h.viaConfig().value().id().get());
        assertEquals(5, h.viaSized().value().id().get());
    }

    @Test
    void keepsRawBytesOfAnUndecodedOrFailedMember() {
        Holder h = new Holder();
        byte[] der = row("Holder", "<scrambled/>").der();
        BerObject.decode(h, der);
        assertEquals(ContainedStatus.SKIPPED, h.viaConfig().status());
        assertNull(h.viaConfig().value());
        assertArrayEquals(hex("010203"), h.viaConfig().bytes());
        assertEquals(ContainedStatus.FAILED, h.viaConstraint().status());
        assertArrayEquals(hex("FF"), h.viaConstraint().bytes());
        assertEquals(-300, h.viaSized().value().id().get());
        assertArrayEquals(der, BerObject.encode(h));
    }

    @Test
    void decodesNothingWhenContainedDecodingIsOff() {
        Holder h = new Holder();
        byte[] der = row("Holder", "<plain/>").der();
        BerObject.decode(h, der, new ContainedOptions(null, true));
        assertEquals(ContainedStatus.SKIPPED, h.viaConstraint().status());
        assertNull(h.viaAlias().value());
        assertArrayEquals(der, BerObject.encode(h));
    }

    @Test
    void reencodesAnEditedInnerValue() {
        Holder h = new Holder();
        BerObject.decode(h, row("Holder", "<plain/>").der());
        h.viaAlias().edit().id().set(5);
        h.viaAlias().edit().name(null);

        Holder back = new Holder();
        BerObject.decode(back, BerObject.encode(h));
        assertArrayEquals(row("Inner", "<id>5</id></Inner>").der(), back.viaAlias().bytes());
        assertEquals(5, back.viaAlias().value().id().get());
    }

    @Test
    void encodesAContainedChoiceAlternative() {
        Pick p = new Pick();
        p.select(0);
        Inner in = new Inner();
        in.id().set(5);
        p.inner().set(in);
        assertArrayEquals(row("Pick", "<inner>").der(), BerObject.encode(p));

        Pick back = new Pick();
        BerObject.decode(back, row("Pick", "<inner>").der());
        assertEquals(5, back.inner().value().id().get());
    }

    @Test
    void containsItsOwnType() {
        Envelope inner = new Envelope();
        inner.depth().set(1);
        Envelope e = new Envelope();
        e.depth().set(0);
        Containing<Envelope> nested = new Containing<>(Envelope::new, Envelope.SPEC.members().get(1).contained());
        nested.set(inner);
        e.nested(nested);
        byte[] der = row("Envelope", "<nested>").der();
        assertArrayEquals(der, BerObject.encode(e));

        Envelope back = new Envelope();
        BerObject.decode(back, der);
        assertTrue(back.nested() != null);
        assertEquals(1, back.nested().value().depth().get());
        assertNull(back.nested().value().nested());
    }
}
