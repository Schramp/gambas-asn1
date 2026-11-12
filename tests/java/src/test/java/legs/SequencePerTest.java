package legs;

import io.github.schramp.gambasasn1.wire.io.DecodeException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.ber.BerObject;
import gen.ext_ber.V1;
import gen.ext_ber.V2;
import io.github.schramp.gambasasn1.wire.per.PerLength;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.per.PerWriter;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Unaligned PER leg of the SEQUENCE and SET schemas (X.691 §19, §21):
 * presence bitmaps, DEFAULT members, extension additions and SETs in
 * canonical order, against asn1c's UPER.
 */
class SequencePerTest {
    static Stream<Vectors.Vector> sequence() {
        return PerLeg.withUper(SequenceBerTest.vectors(), Set.of("Point", "Plain", "Opt", "Tagged", "Outer"));
    }

    static Stream<Vectors.Vector> ext() {
        return PerLeg.withUper(ExtBerTest.vectors(), ExtBerTest.TYPES.keySet());
    }

    static Stream<Vectors.Vector> defaults() {
        return PerLeg.withUper(DefaultBerTest.vectors(), DefaultBerTest.TYPES.keySet());
    }

    static Stream<Vectors.Vector> set() {
        return PerLeg.withUper(SetBerTest.vectors(), Set.of("Rec"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("sequence")
    void sequenceSchema(Vectors.Vector vec) throws DecodeException {
        PerLeg.check(vec, SequenceBerTest.TYPES);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("ext")
    void extensionAdditions(Vectors.Vector vec) throws DecodeException {
        PerLeg.check(vec, ExtBerTest.TYPES);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("defaults")
    void defaultMembers(Vectors.Vector vec) throws DecodeException {
        PerLeg.check(vec, DefaultBerTest.TYPES);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("set")
    void setInCanonicalOrder(Vectors.Vector vec) throws DecodeException {
        PerLeg.check(vec, SetBerTest.TYPES);
    }

    private static Vectors.Vector row(String xer) {
        return ExtBerTest.vectors().filter(v -> v.xer().equals(xer)).findFirst().orElseThrow();
    }

    /**
     * X.691 §19.9: an earlier version's decoder skips the additions it does
     * not know by their length and keeps everything else.
     */
    @ParameterizedTest(name = "{1}")
    @MethodSource("legs.ExtBerTest#versions")
    void earlierVersionSkipsUnknownAdditions(String later, String earlier) throws DecodeException {
        Vectors.Vector from = row(later);
        Vectors.Vector to = row(earlier);
        Asn1Pdu sent = ExtBerTest.TYPES.get(from.type()).get();
        BerObject.decode(sent, from.der());
        Asn1Pdu v = ExtBerTest.TYPES.get(to.type()).get();
        PerObject.decode(v, PerObject.encode(sent));
        assertArrayEquals(to.der(), BerObject.encode(v));
    }

    /**
     * X.691 §19.7: a sender with 200 additions, of which the first (flag) and
     * the 71st are present: the presence bitmap is as wide as the count on
     * the wire, and the unknown addition is skipped by its length.
     */
    @Test
    void extensionBitmapWiderThan64() throws DecodeException {
        PerWriter w = new PerWriter().putBits(1, 1).putBits(0, 1);
        PerLength.putUnconstrained(w, 5);
        PerLength.putNormallySmallLength(w, 200);
        for (int i = 0; i < 200; i++) {
            w.putBits(i == 0 || i == 70 ? 1 : 0, 1);
        }
        PerLength.putOctets(w, new byte[] {(byte) 0x80});
        PerLength.putOctets(w, new byte[] {0});
        V1 v = new V1();
        PerObject.decode(v, w.toByteArray());
        // id 5 and flag TRUE: the DER of the id 3 / FALSE vector with both values changed.
        assertArrayEquals(java.util.HexFormat.of().parseHex("30068001058201FF"), BerObject.encode(v));
    }

    /**
     * X.691 §11.2: an extension addition's open type holds one complete
     * encoding. V2 {@code id 3, flag TRUE}, flag's open type 2 octets longer
     * ({@code 80 FF FF}), is an error unless relaxed.
     */
    @Test
    void trailingOctetsInAnAdditionsOpenTypeFail() throws DecodeException {
        byte[] longer = java.util.HexFormat.of().parseHex("80414140380FFFF0");
        DecodeException e = assertThrows(DecodeException.class, () -> PerObject.decode(new V2(), longer));
        assertTrue(e.getMessage().contains("PER: trailing data in an open type"), e.getMessage());
        V2 got = new V2();
        PerObject.decode(got, longer, DecodeRelaxedTest.RELAXED);
        assertTrue(got.flag().get());
    }
}
