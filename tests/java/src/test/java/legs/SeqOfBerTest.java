package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.seqof_ber.Colors;
import gen.seqof_ber.Holder;
import gen.seqof_ber.IntSet;
import gen.seqof_ber.Ints;
import gen.seqof_ber.Names;
import gen.seqof_ber.Point;
import gen.seqof_ber.Points;
import gen.seqof_ber.TaggedInts;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.SeqOf;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * SEQUENCE OF / SET OF under BER (X.690 §8.10, §8.12), against asn1c's DER
 * for tests/asn1/seqof_ber_test.asn1: every vector decodes and re-encodes
 * byte for byte, a SET OF in DER order (X.690 §11.6).
 */
class SeqOfBerTest {
    private static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("Ints", Ints::new),
            Map.entry("IntSet", IntSet::new),
            Map.entry("Points", Points::new),
            Map.entry("Colors", Colors::new),
            Map.entry("Names", Names::new),
            Map.entry("TaggedInts", TaggedInts::new),
            Map.entry("Holder", Holder::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("seqof_ber_test.vectors").stream();
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static Asn1Integer i(long v) {
        return new Asn1Integer(v);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @Test
    void everyTypeHasAVector() {
        List<String> covered = vectors().map(Vectors.Vector::type).distinct().sorted().toList();
        assertEquals(TYPES.keySet().stream().sorted().toList(), covered);
    }

    @Test
    void elementsDecodeInOrder() {
        Ints v = new Ints();
        BerObject.decode(v, hex("300A0201010201FE0202012C"));
        assertEquals(List.of(i(1), i(-2), i(300)), v.items());
    }

    /** SET OF elements are written in DER order whatever order they were added in. */
    @Test
    void setOfEncodesInDerOrder() {
        IntSet s = new IntSet();
        s.add(i(5));
        s.add(i(-1));
        s.add(i(300));
        s.add(i(2));
        assertArrayEquals(hex("310D0201020201050201FF0202012C"), BerObject.encode(s));
        // Decoding keeps the order of the input.
        IntSet d = new IntSet();
        BerObject.decode(d, hex("310D0201020201050201FF0202012C"));
        assertEquals(List.of(i(2), i(5), i(-1), i(300)), d.items());
    }

    @Test
    void membersSetByAccessorEncodeAsAsn1cDoes() {
        Holder h = new Holder();
        h.opt(new SeqOf<>(Asn1Boolean::new));
        h.opt().add(new Asn1Boolean(true));
        h.opt().add(new Asn1Boolean(false));
        h.named().add(i(4));
        assertArrayEquals(hex("301930003100A000A10830060101FF010100300302010463003000"), BerObject.encode(h));

        Points p = new Points();
        Point a = new Point();
        a.x(i(1));
        a.y(i(2));
        p.add(a);
        assertArrayEquals(hex("30083006020101020102"), BerObject.encode(p));
    }

    @Test
    void decodeReplacesWhatTheCollectionHeld() {
        Ints v = new Ints();
        v.add(i(9));
        BerObject.decode(v, hex("3000"));
        assertEquals(0, v.size());
        Holder h = new Holder();
        BerObject.decode(h, hex("302E3003020101310A0401010401FF04020100A008300602010002010030006306020109020108300730030201013000"));
        assertNull(h.opt());
        assertEquals(2, h.nested().size());
        assertEquals(List.of(i(1)), h.nested().items().get(0).items());
        assertEquals(new Asn1OctetString(hex("01")), h.set().items().get(0));
    }

    @Test
    void collectionsCompareByElements() {
        Ints a = new Ints();
        a.add(i(1));
        Ints b = new Ints();
        b.add(i(1));
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        b.add(i(2));
        assertNotEquals(a, b);
    }

    @Test
    void malformedInputIsADecodeError() {
        // A SET where a SEQUENCE OF belongs.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Ints(), hex("3103020101")));
        // An element of the wrong type.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Ints(), hex("30030101FF")));
        // The type's own IMPLICIT tag missing.
        assertThrows(DecodeException.class, () -> BerObject.decode(new TaggedInts(), hex("3003020107")));
        assertThrows(DecodeException.class, () -> BerObject.decode(new Colors(), new byte[0]));
    }
}
