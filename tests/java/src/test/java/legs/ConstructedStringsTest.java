package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.constructed_strings.Bits;
import gen.constructed_strings.Name;
import gen.constructed_strings.Opt;
import gen.constructed_strings.OptSet;
import gen.constructed_strings.Plain;
import gen.constructed_strings.Tagged;
import gen.constructed_strings.Wrapped;
import io.github.schramp.gambasasn1.wire.DecodeOptions;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.spec.ContainedStatus;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Positions;
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

    static final Map<String, Supplier<AsMemberRef>> TYPES = Map.of(
            "Tagged", Tagged::new,
            "Plain", Plain::new,
            "Bits", Bits::new,
            "Name", Name::new,
            "Wrapped", Wrapped::new,
            "Opt", Opt::new,
            "OptSet", OptSet::new);

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
                        "310AA1050403414243800141", "31088001418103414243"));
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
                        "constructed string segments nest deeper than 30 levels"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("refused")
    void refused(String label, String type, byte[] ber, String error) {
        DecodeException e = assertThrows(DecodeException.class, () -> roundtrip(type, ber));
        assertTrue(e.getMessage().contains(error), e.getMessage());
    }

    /**
     * A joined value's octets are spread over its segments: it keeps its
     * encoding span but has no contents or value span, and a CONTAINING
     * value decoded from it is not placed in the input.
     */
    @Test
    void joinedValuesHaveNoContentsOrValueSpan() throws DecodeException {
        Plain pl = new Plain();
        Positions p = BerObject.decodeWithPositions(pl, HEX.parseHex("30102407040201020401030301001A000C00"), null)
                .positions();
        assertArrayEquals(new byte[] {1, 2, 3}, pl.o().get());
        assertEquals(16, p.bitOffset(pl.o()));
        assertEquals(72, p.sizeBits(pl.o()));
        assertEquals(-1, p.contentsBitOffset(pl.o()));
        assertEquals(-1, p.valueSizeBits(pl.o()));

        Wrapped joined = new Wrapped();
        p = BerObject.decodeWithPositions(joined, HEX.parseHex("300DA00B04021A0504054A6F6E6573"), null).positions();
        assertEquals("Jones", joined.c().value().value.get());
        assertEquals(-1, p.contentsBitOffset(joined.c()));
        assertEquals(-1, p.bitOffset(joined.c().value()));

        Wrapped primitive = new Wrapped();
        p = BerObject.decodeWithPositions(primitive, HEX.parseHex("300980071A054A6F6E6573"), null).positions();
        assertEquals(32, p.contentsBitOffset(primitive.c()));
        assertEquals(32, p.bitOffset(primitive.c().value()));
    }

    /** Relaxed decoding takes a BIT STRING segment with unused bits and no octets as empty, as it does a primitive one. */
    @Test
    void relaxedReachesTheSegments() throws DecodeException {
        for (String ber : List.of("030103", "2303030103")) {
            Bits v = new Bits();
            BerReader r = new BerReader(HEX.parseHex(ber)).withOptions(DecodeOptions.DEFAULT.withRelaxed(true));
            BerObject.decode(v, r);
            assertEquals("030100", HEX.formatHex(BerObject.encode(v)), ber);
        }
    }

    /** The contained value is decoded from the joined segments, not from the segment TLVs. */
    @Test
    void containedValueDecodedFromJoinedSegments() throws DecodeException {
        Wrapped w = new Wrapped();
        BerObject.decode(w, HEX.parseHex("300DA00B04021A0504054A6F6E6573"));
        assertEquals(ContainedStatus.DECODED, w.c().status());
        assertEquals("Jones", w.c().value().value.get());
    }

    /** The primitive form still decodes as before. */
    @Test
    void primitiveFormUnchanged() throws DecodeException {
        assertArrayEquals(HEX.parseHex("1A054A6F6E6573"), roundtrip("Name", HEX.parseHex("1A054A6F6E6573")));
    }
}
