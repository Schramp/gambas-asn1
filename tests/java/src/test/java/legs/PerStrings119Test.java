package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.per_strings_119.PDU;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Unaligned PER leg of asn1c's data-119 suite (119-per-strings-OK.asn1):
 * the character string types, plain and with FROM, SIZE and extensible
 * constraints (X.691 §30). tests/vectors/per_strings_119.vectors holds
 * asn1c's encodings of every input without -P; the -P inputs break a PER
 * constraint, so encoding them must fail.
 */
class PerStrings119Test {
    static final Map<String, java.util.function.Supplier<PDU>> TYPES = Map.of("PDU", PDU::new);

    private static final List<Vectors.Vector> ROWS = Vectors.load("per_strings_119.vectors");

    static Stream<Vectors.Vector> vectors() {
        return ROWS.stream();
    }

    private static List<Path> inputs(boolean p) throws IOException {
        try (Stream<Path> files = Files.list(Path.of(System.getProperty("asn1c.suite.dir"), "data-119"))) {
            return files.filter(f -> f.getFileName().toString().endsWith(".in"))
                    .filter(f -> f.getFileName().toString().endsWith("-P.in") == p)
                    .sorted()
                    .toList();
        }
    }

    static Stream<Path> refused() throws IOException {
        return inputs(true).stream();
    }

    /** asn1c's DER encodes to asn1c's UPER, and asn1c's UPER decodes back to the DER. */
    @ParameterizedTest(name = "{index}")
    @MethodSource("vectors")
    void matchesAsn1cUper(Vectors.Vector vec) throws DecodeException {
        PerLeg.check(vec, TYPES);
    }

    /** The XER input encodes to asn1c's UPER, as in the C++ and Rust legs. */
    @ParameterizedTest(name = "{index}")
    @MethodSource("vectors")
    void xerInputEncodesToAsn1cUper(Vectors.Vector vec) throws DecodeException {
        PDU v = new PDU();
        XerObject.decode(v, vec.xer().getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(vec.asn1cUper(), PerObject.encode(v));
    }

    /** X.691 §30: a value outside its PER-visible alphabet or SIZE cannot be encoded. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("refused")
    void constraintViolationIsNotEncoded(Path input) throws IOException, DecodeException {
        PDU v = new PDU();
        XerObject.decode(v, Files.readAllBytes(input));
        assertThrows(EncodeException.class, () -> PerObject.encode(v));
    }

    @Test
    void oneVectorPerInputWithoutP() throws IOException {
        assertEquals(inputs(false).size(), ROWS.size());
        assertEquals(List.of(), ROWS.stream().filter(r -> r.asn1cUper() == null).toList());
        assertEquals(14, inputs(true).size());
    }
}
