package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Java XER leg of the X.693 §21 ENCODING-CONTROL schemas: a BASE64 or UTF8
 * instruction on a SEQUENCE member, a CHOICE alternative, a SEQUENCE OF
 * element or a type of its own, declared inline, on a named type or in an
 * ENCODING-CONTROL block. Each value is written as asn1c's text and read
 * back from it.
 */
class XerInstructionTest {
    private static final Map<String, Supplier<AsMemberRef>> INSTR = Map.of(
            "InlineTest", gen.xer_encoding_instr.InlineTest::new,
            "Base64Payload", gen.xer_encoding_instr.Base64Payload::new,
            "PayloadWrapper", gen.xer_encoding_instr.PayloadWrapper::new,
            "LegacyBase64", gen.xer_encoding_instr.LegacyBase64::new,
            "StandardBase64", gen.xer_encoding_instr.StandardBase64::new,
            "NoInstruction", gen.xer_encoding_instr.NoInstruction::new,
            "Utf8Field", gen.xer_encoding_instr.Utf8Field::new);

    static Stream<Arguments> vectors() {
        return Stream.of(
                rows("xer_encoding_instr_test.vectors", INSTR),
                rows("xer_alt_instruction_test.vectors", Map.of("Holder", gen.xer_alt_instruction.Holder::new)),
                rows("rust_seqof_base64_elem_test.vectors", Map.of("Entries", gen.rust_seqof_base64_elem.Entries::new)))
                .flatMap(s -> s);
    }

    private static Stream<Arguments> rows(String file, Map<String, Supplier<AsMemberRef>> types) {
        return Vectors.load(file).stream().map(v -> Arguments.of(v, types.get(v.type())));
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
}
