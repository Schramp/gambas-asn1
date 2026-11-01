package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import gen.containing.Holder;
import gen.containing.Inner;
import gen.containing.Pick;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Contained values under unaligned PER (X.682 §11): the field is an OCTET
 * STRING under its SIZE (X.691 §17) holding the inner value, whose rules
 * follow the outer encoding when the constraint names none (X.682 §11.4).
 * asn1c has no contents constraints and writes a field's bytes as they are,
 * so its UPER is ground truth where those bytes are PER already.
 */
class ContainingPerTest {
    private static Vectors.Vector row(String type, String xerPart) {
        return ContainingTest.vectors().filter(v -> v.type().equals(type) && v.xer().contains(xerPart)).findFirst()
                .orElseThrow();
    }

    static Stream<Vectors.Vector> uper() {
        return PerLeg.withUper(ContainingTest.vectors(), ContainingTest.TYPES.keySet());
    }

    /** Every asn1c UPER decodes and re-encodes byte for byte; undecodable contents stay raw. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("uper")
    void decodesAsn1cUperAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = ContainingTest.TYPES.get(vec.type()).get();
        PerObject.decode(v, vec.asn1cUper());
        assertArrayEquals(vec.asn1cUper(), PerObject.encode(v));
    }

    /**
     * A value whose contents are PER already: written as PER it matches
     * asn1c. (Written back as BER, its contents become BER: X.682 §11.4.)
     */
    @Test
    void perContentsMatchAsn1c() {
        Vectors.Vector vec = row("Holder", "<viaConstraint>008280");
        Holder h = new Holder();
        BerObject.decode(h, vec.der());
        assertArrayEquals(vec.asn1cUper(), PerObject.encode(h));
    }

    /**
     * X.682 §11.4: contents decoded from BER are written again as PER when
     * the outer value is; the sidecar fields, configured BER, keep their bytes.
     */
    @Test
    void berContentsAreWrittenAsPer() {
        Holder b = new Holder();
        BerObject.decode(b, row("Holder", "<viaConstraint>3003800105").der());
        Holder back = new Holder();
        PerObject.decode(back, PerObject.encode(b));
        assertEquals(ContainedStatus.DECODED, back.viaConstraint().status());
        assertEquals(5, back.viaConstraint().value().id().get());
        assertEquals(-300, back.viaAlias().value().id().get());
        assertEquals(5, back.viaConfig().value().id().get());
        assertEquals(5, back.viaSized().value().id().get());
        assertArrayEquals(row("Holder", "<viaConstraint>008280").asn1cUper(), PerObject.encode(b));
        assertArrayEquals(row("Inner", "<id>5</id></Inner>").asn1cUper(), back.viaConstraint().bytes());
    }

    @Test
    void encodesAContainedChoiceAlternative() {
        Pick p = new Pick();
        p.select(0);
        Inner in = new Inner();
        in.id().set(5);
        p.inner().set(in);
        Pick back = new Pick();
        PerObject.decode(back, PerObject.encode(p));
        assertEquals(ContainedStatus.DECODED, back.inner().status());
        assertEquals(5, back.inner().value().id().get());
        assertArrayEquals(row("Inner", "<id>5</id></Inner>").asn1cUper(), back.inner().bytes());
    }
}
