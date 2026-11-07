package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.choice_ber.Plain;
import gen.constraints_ber.Limits;
import gen.seqof_ber.Ints;
import gen.sequence_ber.Outer;
import io.github.schramp.gambasasn1.wire.DecodeOptions;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Decoder settings: constraint checks and rich errors, for BER and PER.
 * Constraint-violating encodings come from the Java BER encoder, which
 * does not check constraints, applied to a changed asn1c vector.
 */
class DecodeOptionsTest {
    static final DecodeOptions CHECKED = DecodeOptions.DEFAULT.withConstraintChecks(true);
    static final DecodeOptions RICH = CHECKED.withRichErrors(true);

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    /** asn1c's first Limits vector with {@code change} applied, BER-encoded again. */
    private static byte[] limitsWith(Consumer<Limits> change) throws DecodeException {
        Limits v = new Limits();
        BerObject.decode(v, Vectors.load("constraints_ber_test.vectors").get(0).der());
        change.accept(v);
        return BerObject.encode(v);
    }

    static Stream<Vectors.Vector> validVectors() {
        return Stream.of("constraints_ber_test.vectors", "sequence_ber_test.vectors", "set_ber_test.vectors",
                        "seqof_ber_test.vectors", "choice_ber_test.vectors", "ext_ber_test.vectors")
                .flatMap(f -> Vectors.load(f).stream());
    }

    static final Map<String, Map<String, Supplier<Asn1Pdu>>> TYPES = Map.of(
            "constraints", Map.of("Limits", Limits::new, "Pick", gen.constraints_ber.Pick::new,
                    "Digits", gen.constraints_ber.Digits::new));

    /** asn1c's encodings of valid values decode with checks on, and with rich errors. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("validVectors")
    void validValuesPassTheChecks(Vectors.Vector vec) throws DecodeException {
        Asn1Pdu plain = make(vec.type(), vec.der());
        if (plain == null) {
            return;
        }
        Asn1Pdu checked = make(vec.type(), vec.der());
        BerObject.decode(checked, vec.der(), RICH);
        assertEquals(plain, checked);
        if (vec.asn1cUper() != null) {
            Asn1Pdu p = make(vec.type(), vec.der());
            PerObject.decode(p, vec.asn1cUper(), RICH);
            assertEquals(plain, p);
        }
    }

    /** A fresh value of {@code type} from whichever leg's vectors hold {@code der}, decoded plainly; null if none fits. */
    private static Asn1Pdu make(String type, byte[] der) {
        for (String pkg : new String[] {"constraints_ber", "sequence_ber", "set_ber", "seqof_ber", "choice_ber",
                "ext_ber"}) {
            try {
                Asn1Pdu v = (Asn1Pdu) Class.forName("gen." + pkg + "." + type).getConstructor().newInstance();
                BerObject.decode(v, der);
                return v;
            } catch (ReflectiveOperationException | ClassCastException | DecodeException e) {
                // not this leg's type, or not its encoding
            }
        }
        return null;
    }

    @Test
    void etsiSampleDecodesWithChecksOn() throws IOException, DecodeException {
        byte[] file = Files.readAllBytes(Path.of(System.getProperty("etsi.sample")));
        BerReader r = new BerReader(file).withOptions(RICH);
        int n = 0;
        while (!r.atEnd()) {
            BerObject.decode(new gen.etsi.LI_PS_PDU.PS_PDU(), r);
            n++;
        }
        assertTrue(n > 1);
    }

    @Test
    void outOfRangeIntegerDecodesWithoutChecksAndFailsWithThem() throws DecodeException {
        byte[] der = limitsWith(v -> v.byte_().set(300));
        Limits v = new Limits();
        BerObject.decode(v, der);
        assertEquals(300, v.byte_().get());
        DecodeException e = assertThrows(DecodeException.class, () -> BerObject.decode(new Limits(), der, CHECKED));
        assertEquals("constraint violated: INTEGER 300 outside 0..255", e.reason());
        assertEquals("", e.path());
        assertEquals(2, e.position());
        DecodeException rich = assertThrows(DecodeException.class, () -> BerObject.decode(new Limits(), der, RICH));
        assertEquals("Limits.byte", rich.path());
        assertTrue(rich.getMessage().startsWith(
                "constraint violated: INTEGER 300 outside 0..255 in Limits.byte at byte 2 (input there: 02 02 01 2c"),
                rich.getMessage());
    }

    @Test
    void sizeAndAlphabetAndElementViolations() {
        DecodeException name = assertThrows(DecodeException.class,
                () -> BerObject.decode(new Limits(), limitsWith(v -> v.name().set("abcdefghi")), RICH));
        assertEquals("constraint violated: IA5String size 9 outside SIZE(1..8)", name.reason());
        assertEquals("Limits.name", name.path());
        DecodeException fixed = assertThrows(DecodeException.class,
                () -> BerObject.decode(new Limits(), limitsWith(v -> v.fixed().set(new byte[3])), RICH));
        assertEquals("Limits.fixed", fixed.path());
        DecodeException elem = assertThrows(DecodeException.class,
                () -> BerObject.decode(new Limits(), limitsWith(v -> v.small().items().get(0).value.set(10)), RICH));
        assertEquals("constraint violated: INTEGER 10 outside 0..9", elem.reason());
        assertEquals("Limits.small", elem.path());
        DecodeException count = assertThrows(DecodeException.class, () -> BerObject.decode(new Limits(),
                limitsWith(v -> {
                    for (int i = 0; i < 3; i++) {
                        v.sized().add(new io.github.schramp.gambasasn1.wire.types.Asn1Boolean());
                    }
                }), RICH));
        assertEquals("constraint violated: SEQUENCE OF size 4 outside SIZE(1..3)", count.reason());
        assertEquals("Limits.sized", count.path());
    }

    @Test
    void anExtensibleRangeAdmitsOtherValues() throws DecodeException {
        byte[] der = limitsWith(v -> v.neg().set(7));
        Limits v = new Limits();
        BerObject.decode(v, der, RICH);
        assertEquals(7, v.neg().get());
    }

    @Test
    void richErrorsNameTheFailingMemberAndShowTheInput() {
        byte[] der = hex("3011300C0201010101000C0004000500020102");
        byte[] cut = Arrays.copyOf(der, 9);
        cut[1] = 7;
        cut[3] = 5;
        DecodeException plain = assertThrows(DecodeException.class, () -> BerObject.decode(new Outer(), cut));
        assertEquals("", plain.path());
        DecodeException rich = assertThrows(DecodeException.class,
                () -> BerObject.decode(new Outer(), cut, DecodeOptions.DEFAULT.withRichErrors(true)));
        assertEquals(plain.reason(), rich.reason());
        assertEquals(plain.position(), rich.position());
        assertTrue(rich.path().startsWith("Outer.inner."), rich.path());
        assertTrue(rich.getMessage().contains("(input there: ") || rich.getMessage().contains("(end of input)"),
                rich.getMessage());
    }

    @Test
    void perRichErrorsNameTheFailingMember() {
        byte[] uper = Vectors.load("sequence_ber_test.vectors").stream()
                .filter(v -> v.type().equals("Outer")).findFirst().orElseThrow().asn1cUper();
        byte[] cut = Arrays.copyOf(uper, 4);
        DecodeException plain = assertThrows(DecodeException.class, () -> PerObject.decode(new Outer(), cut));
        DecodeException rich = assertThrows(DecodeException.class,
                () -> PerObject.decode(new Outer(), cut, DecodeOptions.DEFAULT.withRichErrors(true)));
        assertEquals(plain.reason(), rich.reason());
        assertTrue(rich.path().startsWith("Outer."), rich.path());
    }

    private static Ints ints(int n) {
        Ints v = new Ints();
        for (int i = 0; i < n; i++) {
            v.add(new Asn1Integer(i % 100));
        }
        return v;
    }

    @Test
    void richErrorsNameTheFailingElementAndAlternative() {
        // Ints: 30 09 | 02 01 00 | 02 01 01 | 02 01 02, element 2 claiming 2 octets.
        byte[] der = BerObject.encode(ints(3));
        der[der.length - 2] = 2;
        assertEquals("Ints[2]", assertThrows(DecodeException.class,
                () -> BerObject.decode(new Ints(), der, RICH)).path());
        byte[] uper = PerObject.encode(ints(3));
        byte[] cutUper = Arrays.copyOf(uper, uper.length - 1);
        assertEquals("Ints[2]", assertThrows(DecodeException.class,
                () -> PerObject.decode(new Ints(), cutUper, RICH)).path());

        // Plain ::= CHOICE { num, flag, text UTF8String }: text of length 5 holding 1 octet.
        byte[] text = hex("0C0561");
        assertEquals("Plain.text", assertThrows(DecodeException.class,
                () -> BerObject.decode(new Plain(), text, RICH)).path());
    }

    @Test
    void perElementIndexCountsOnAcrossLengthFragments() {
        // 16385 elements: a 16K fragment, then a length of 1 (X.691 §11.9.3.8).
        byte[] uper = PerObject.encode(ints(16385));
        byte[] cut = Arrays.copyOf(uper, uper.length - 1);
        assertEquals("Ints[16384]", assertThrows(DecodeException.class,
                () -> PerObject.decode(new Ints(), cut, RICH)).path());
    }

    @Test
    void traceNamesEachElement() throws DecodeException {
        for (boolean per : new boolean[] {false, true}) {
            java.util.List<String> lines = new java.util.ArrayList<>();
            DecodeOptions o = DecodeOptions.DEFAULT.withTrace(lines::add);
            if (per) {
                PerObject.decode(new Ints(), PerObject.encode(ints(3)), o);
            } else {
                BerObject.decode(new Ints(), BerObject.encode(ints(3)), o);
            }
            assertEquals(4, lines.size(), lines.toString());
            for (int i = 0; i < 3; i++) {
                assertTrue(lines.get(i + 1).contains(" [" + i + "] "), lines.toString());
            }
        }
    }

    @Test
    void positionsDecodeTakesTheSettingsToo() throws DecodeException {
        byte[] der = limitsWith(v -> v.byte_().set(300));
        assertThrows(DecodeException.class, () -> BerObject.decodeWithPositions(new Limits(), der, CHECKED));
        assertEquals(der.length, BerObject.decodeWithPositions(new Limits(), der, DecodeOptions.DEFAULT).bytesConsumed());
    }
}
