package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.constructed_strings.Bits;
import gen.constructed_strings.CtxChoice;
import gen.constructed_strings.Holder;
import gen.constructed_strings.MixChoice;
import gen.constructed_strings.Name;
import gen.constructed_strings.NestChoice;
import gen.constructed_strings.Num;
import gen.constructed_strings.Opt;
import gen.constructed_strings.OptSet;
import gen.constructed_strings.Plain;
import gen.constructed_strings.Tagged;
import gen.constructed_strings.When;
import gen.constructed_strings.Wrapped;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Constructed-form strings in BER (X.690 §8.6.4, §8.7.3, §8.23.3; CER §9.2):
 * the Java leg of tests/seq/test_constructed_strings.cpp and
 * tests/rust/constructed_strings. tests/vectors/constructed_strings_test.vectors
 * holds, per row, a BER encoding with constructed strings (asn1c's CER, or an
 * X.690 example) and asn1c's DER of the same value.
 */
class ConstructedStringsTest {
    private static final HexFormat HEX = HexFormat.of().withUpperCase();

    static final Map<String, Supplier<AsMemberRef>> TYPES = Map.ofEntries(
            Map.entry("Tagged", Tagged::new),
            Map.entry("Plain", Plain::new),
            Map.entry("Bits", Bits::new),
            Map.entry("Name", Name::new),
            Map.entry("Wrapped", Wrapped::new),
            Map.entry("Opt", Opt::new),
            Map.entry("OptSet", OptSet::new),
            Map.entry("CtxChoice", CtxChoice::new),
            Map.entry("NestChoice", NestChoice::new),
            Map.entry("MixChoice", MixChoice::new),
            Map.entry("Num", Num::new),
            Map.entry("When", When::new),
            Map.entry("Holder", Holder::new));

    /** Decodes {@code ber} as the whole input, then re-encodes the value. */
    private static byte[] roundtrip(String type, byte[] ber) throws DecodeException {
        AsMemberRef v = TYPES.get(type).get();
        BerReader r = new BerReader(ber);
        BerObject.decode(v, r);
        assertTrue(r.atEnd(), "trailing octets");
        return BerObject.encode(v);
    }

    static Stream<Arguments> vectors() throws IOException {
        List<String> lines = Files.readAllLines(Path.of(System.getProperty("vectors.dir"), "constructed_strings_test.vectors"));
        return lines.stream()
                .filter(l -> !l.isEmpty() && !l.startsWith("#"))
                .map(l -> l.split("\t"))
                .map(c -> Arguments.of(c[0], c[1], c[2], c[3]));
    }

    @Test
    void sixVectorRows() throws IOException {
        assertEquals(6, vectors().count());
    }

    /** The BER decodes to the value of asn1c's DER and re-encodes to that DER. */
    @ParameterizedTest(name = "{0} ({1})")
    @MethodSource("vectors")
    void berDecodesToTheDerValue(String type, String source, String ber, String der) throws DecodeException {
        assertEquals(der, HEX.formatHex(roundtrip(type, HEX.parseHex(ber))));
        assertEquals(der, HEX.formatHex(roundtrip(type, HEX.parseHex(der))));
    }

    static Stream<Arguments> accepted() {
        return Stream.of(
                Arguments.of("empty constructed VisibleString", "Name", "3A00", "1A00"),
                Arguments.of("empty constructed indefinite VisibleString", "Name", "3A800000", "1A00"),
                Arguments.of("empty constructed BIT STRING", "Bits", "2300", "030100"),
                Arguments.of("nested constructed segment", "Name", "3A0B240504034A6F6E04026573", "1A054A6F6E6573"),
                Arguments.of("nested indefinite segment", "Name", "3A80248004034A6F6E0000040265730000", "1A054A6F6E6573"),
                Arguments.of("segments at several nesting levels", "Name",
                        "3A80248004014124800401420000040143000024060401440401450401460000", "1A06414243444546"),
                Arguments.of("CONTAINING value split across segments", "Wrapped",
                        "300DA00B04021A0504054A6F6E6573", "300980071A054A6F6E6573"),
                Arguments.of("BIT STRING, unused bits in the last segment", "Bits", "230803020080030205E0", "03030580E0"),
                Arguments.of("constructed OPTIONAL and extension members", "Opt",
                        "3080A08004024A6F04016E0000A2070402ABCD0401EF0000", "300A80034A6F6E8203ABCDEF"),
                Arguments.of("constructed OPTIONAL character string", "Opt", "3080A10504034A6F6E0000", "300581034A6F6E"),
                Arguments.of("SET members out of order, one constructed", "OptSet",
                        "310AA1050403414243800141", "31088001418103414243"),
                Arguments.of("CHOICE context-tag index, segmented alternative", "CtxChoice", "A006040141040142", "80024142"),
                Arguments.of("CHOICE context-tag index, segmented character string", "CtxChoice", "A106040141040142", "81024142"),
                Arguments.of("CHOICE dispatch table, segmented alternative", "NestChoice", "A206040141040142", "82024142"),
                Arguments.of("CHOICE dispatch table, via the untagged CHOICE", "NestChoice", "A106040141040142", "81024142"),
                Arguments.of("CHOICE linear scan, segmented IMPLICIT alternative", "MixChoice", "A006040141040142", "80024142"),
                Arguments.of("CHOICE linear scan, segmented untagged string", "MixChoice", "3606040141040142", "16024142"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("accepted")
    void accepted(String label, String type, String ber, String der) throws DecodeException {
        assertEquals(der, HEX.formatHex(roundtrip(type, HEX.parseHex(ber))));
    }

    /** {@code 3A 80}, {@code n} nested {@code 24 80}, {@code 04 01 41}, the end-of-contents octets. */
    static byte[] nested(int n) {
        byte[] b = new byte[2 + 2 * n + 3 + 2 * (n + 1)];
        b[0] = 0x3A;
        b[1] = (byte) 0x80;
        for (int i = 0; i < n; i++) {
            b[2 + 2 * i] = 0x24;
            b[3 + 2 * i] = (byte) 0x80;
        }
        b[2 + 2 * n] = 0x04;
        b[3 + 2 * n] = 0x01;
        b[4 + 2 * n] = 0x41;
        return b;
    }

    /** asn1c's limit: 29 nested segments inside the string decode. */
    @Test
    void segmentsNested29Deep() throws DecodeException {
        assertEquals("1A0141", HEX.formatHex(roundtrip("Name", nested(29))));
    }

    static Stream<Arguments> refused() {
        return Stream.of(
                Arguments.of("character string segment with its own tag", "Name", HEX.parseHex("3A051A034A6F6E"),
                        "segment of a constructed string is not an OCTET STRING"),
                Arguments.of("BIT STRING segment with an OCTET STRING tag", "Bits", HEX.parseHex("2304040200FF"),
                        "segment of a constructed BIT STRING is not a BIT STRING"),
                Arguments.of("end-of-contents in a definite constructed string", "Name", HEX.parseHex("3A0404000000"),
                        "segment of a constructed string is not an OCTET STRING"),
                Arguments.of("unused bits before the last BIT STRING segment", "Bits", HEX.parseHex("230803020180030200FF"),
                        "BIT STRING segment other than the last has unused bits"),
                Arguments.of("BIT STRING segment without its unused-bits octet", "Bits", HEX.parseHex("23020300"),
                        "BIT STRING segment is empty (need at least unused-bits byte)"),
                Arguments.of("BIT STRING segment with unused bits and no octets", "Bits", HEX.parseHex("2303030103"),
                        "BIT STRING segment has 3 unused bits in 0 octets"),
                Arguments.of("IMPLICIT member segment with the member's tag", "Tagged",
                        HEX.parseHex("300DA00680044A6F6E658101008200"),
                        "segment of a constructed string is not an OCTET STRING"),
                Arguments.of("segments nested 30 deep", "Name", nested(30),
                        "constructed string segments nest deeper than 30 levels"),
                Arguments.of("segments nested 300 deep", "Name", nested(300),
                        "constructed string segments nest deeper than 30 levels"),
                Arguments.of("constructed IMPLICIT INTEGER", "Num", HEX.parseHex("3005A103020105"), "expected tag"),
                Arguments.of("UTCTime member with an OCTET STRING tag", "When", HEX.parseHex("300724050403313233"), "expected tag"),
                Arguments.of("OPTIONAL SEQUENCE in primitive form", "Holder", HEX.parseHex("30051003020105"), "mandatory member 'n' missing"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("refused")
    void refused(String label, String type, byte[] ber, String error) {
        DecodeException e = assertThrows(DecodeException.class, () -> roundtrip(type, ber));
        assertTrue(e.getMessage().contains(error), e.getMessage());
    }

    /** The contained value is decoded from the joined segments, not from the segment TLVs. */
    @Test
    void containedValueDecodedFromJoinedSegments() throws DecodeException {
        Wrapped w = new Wrapped();
        BerObject.decode(w, HEX.parseHex("300DA00B04021A0504054A6F6E6573"));
        assertEquals(ContainedStatus.DECODED, w.c().status());
        assertEquals("Jones", w.c().value().value.get());
    }

    /** A primitive string decodes and re-encodes to itself. */
    @Test
    void primitiveFormRoundTrips() throws DecodeException {
        assertArrayEquals(HEX.parseHex("1A054A6F6E6573"), roundtrip("Name", HEX.parseHex("1A054A6F6E6573")));
    }
}
