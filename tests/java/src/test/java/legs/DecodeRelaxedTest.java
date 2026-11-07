package legs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.constraints_ber.Limits;
import gen.sequence_ber.Outer;
import gen.sequence_ber.Plain;
import io.github.schramp.gambasasn1.wire.DecodeOptions;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.jer.JerObject;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.xer.XerObject;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Decoder settings, second part: relaxed decoding per codec, constraint
 * checks and rich errors under XER and JER, and tracing. Off-standard
 * inputs are asn1c's encodings changed in one place.
 */
class DecodeRelaxedTest {
    static final DecodeOptions RELAXED = DecodeOptions.DEFAULT.withRelaxed(true);

    private static Vectors.Vector plain() {
        return Vectors.load("sequence_ber_test.vectors").stream().filter(v -> v.type().equals("Plain"))
                .findFirst().orElseThrow();
    }

    /** A definite-length TLV with one-octet tag and short-form length. */
    private static byte[] tlv(int tag, byte[] contents) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        out.write(contents.length);
        out.writeBytes(contents);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    @Test
    void berRelaxedSkipsTrailingMembersOfANonExtensibleSequence() throws DecodeException {
        byte[] der = plain().der();
        byte[] contents = Arrays.copyOfRange(der, 2, der.length);
        // Plain's own first member repeated after its last one.
        byte[] longer = tlv(0x30, concat(contents, Arrays.copyOfRange(contents, 0, 3)));
        DecodeException e = assertThrows(DecodeException.class, () -> BerObject.decode(new Plain(), longer));
        assertTrue(e.reason().contains("unexpected octets after its last member"), e.reason());
        Plain want = new Plain();
        BerObject.decode(want, der);
        Plain got = new Plain();
        BerObject.decode(got, longer, RELAXED);
        assertEquals(want, got);
    }

    @Test
    void berRelaxedStillRejectsAnUnknownAlternativeOfANonExtensibleChoice() {
        // [5] 01 00: a tag no alternative of choice_ber's Plain has.
        byte[] unknown = tlv(0x85, new byte[] {0});
        for (DecodeOptions o : List.of(DecodeOptions.DEFAULT, RELAXED)) {
            DecodeException e = assertThrows(DecodeException.class,
                    () -> BerObject.decode(new gen.choice_ber.Plain(), unknown, o));
            assertTrue(e.reason().contains("no alternative has tag"), e.reason());
        }
    }

    @Test
    void aNullDecoderSettingMeansTheDefaults() throws DecodeException {
        byte[] der = plain().der();
        Plain want = new Plain();
        BerObject.decode(want, der);
        Plain ber = new Plain();
        BerObject.decode(ber, der, null);
        assertEquals(want, ber);
        Plain xer = new Plain();
        XerObject.decode(xer, XerObject.encode(want), null);
        assertEquals(want, xer);
    }

    @Test
    void berRelaxedTakesALongBoolean() throws DecodeException {
        byte[] der = plain().der();
        // 01 01 FF (flag) becomes 01 02 00 FF.
        int at = 5;
        assertEquals(0x01, der[at]);
        byte[] contents = concat(Arrays.copyOfRange(der, 2, at), new byte[] {1, 2, 0, (byte) 0xFF},
                Arrays.copyOfRange(der, at + 3, der.length));
        byte[] odd = tlv(0x30, contents);
        assertThrows(DecodeException.class, () -> BerObject.decode(new Plain(), odd));
        Plain got = new Plain();
        BerObject.decode(got, odd, RELAXED);
        assertTrue(got.flag().get());
    }

    @Test
    void perRelaxedIgnoresTrailingOctets() throws DecodeException {
        byte[] uper = plain().asn1cUper();
        byte[] longer = concat(uper, new byte[] {0, 1});
        assertThrows(DecodeException.class, () -> PerObject.decode(new Plain(), longer));
        Plain want = new Plain();
        PerObject.decode(want, uper);
        Plain got = new Plain();
        PerObject.decode(got, longer, RELAXED);
        assertEquals(want, got);
    }

    @Test
    void xerRelaxedTakesAsn1cTextBooleans() throws DecodeException {
        byte[] xer = plain().asn1cXer().replace("<flag><true/></flag>", "<flag>true</flag>")
                .getBytes(StandardCharsets.UTF_8);
        assertThrows(DecodeException.class, () -> XerObject.decode(new Plain(), xer));
        Plain got = new Plain();
        XerObject.decode(got, xer, RELAXED);
        assertTrue(got.flag().get());
    }

    @Test
    void xerAndJerCheckConstraintsWhenAsked() throws DecodeException {
        Limits bad = new Limits();
        BerObject.decode(bad, Vectors.load("constraints_ber_test.vectors").get(0).der());
        bad.name().set("abcdefghi");
        DecodeOptions rich = DecodeOptions.DEFAULT.withConstraintChecks(true).withRichErrors(true);
        byte[] xer = XerObject.encode(bad);
        XerObject.decode(new Limits(), xer, DecodeOptions.DEFAULT);
        DecodeException x = assertThrows(DecodeException.class, () -> XerObject.decode(new Limits(), xer, rich));
        assertEquals("constraint violated: IA5String size 9 outside SIZE(1..8)", x.reason());
        assertEquals("Limits.name", x.path());
        byte[] jer = JerObject.encode(bad);
        JerObject.decode(new Limits(), jer, DecodeOptions.DEFAULT);
        DecodeException j = assertThrows(DecodeException.class, () -> JerObject.decode(new Limits(), jer, rich));
        assertEquals(x.reason(), j.reason());
        assertEquals("Limits.name", j.path());
    }

    @Test
    void richXerErrorShowsTheInput() {
        byte[] xer = plain().asn1cXer().replace("<num>5</num>", "<num>x</num>").getBytes(StandardCharsets.UTF_8);
        DecodeException e = assertThrows(DecodeException.class,
                () -> XerObject.decode(new Plain(), xer, DecodeOptions.DEFAULT.withRichErrors(true)));
        assertEquals("Plain", e.path());
        assertTrue(e.getMessage().contains("(input there: "), e.getMessage());
    }

    @Test
    void traceListsEachMemberWithItsOffset() throws DecodeException {
        List<String> lines = new ArrayList<>();
        byte[] der = Vectors.load("sequence_ber_test.vectors").stream().filter(v -> v.type().equals("Outer"))
                .findFirst().orElseThrow().der();
        BerObject.decode(new Outer(), der, DecodeOptions.DEFAULT.withTrace(lines::add));
        assertEquals(List.of("BER byte 0 Outer Outer", "BER byte 2 .inner Plain", "BER byte 4 .num INTEGER",
                "BER byte 7 .flag BOOLEAN", "BER byte 10 .text UTF8String", "BER byte 12 .data OCTET_STRING",
                "BER byte 14 .nul NULL", "BER byte 16 .tail INTEGER"), lines);
        List<String> per = new ArrayList<>();
        PerObject.decode(new Outer(), Vectors.load("sequence_ber_test.vectors").stream()
                .filter(v -> v.type().equals("Outer")).findFirst().orElseThrow().asn1cUper(),
                DecodeOptions.DEFAULT.withTrace(per::add));
        assertEquals(8, per.size());
        assertEquals("PER bit 16 .flag BOOLEAN", per.get(3));
    }
}
