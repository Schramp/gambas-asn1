package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.sequence_ber.Opt;
import gen.sequence_ber.Outer;
import gen.sequence_ber.Pick;
import gen.sequence_ber.Plain;
import gen.sequence_ber.Point;
import gen.sequence_ber.Refs;
import gen.sequence_ber.Tagged;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.MemberMeta;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Ia5String;
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
 * SEQUENCE under BER (X.690 §8.9), against asn1c's DER for
 * tests/asn1/sequence_ber_test.asn1: every vector decodes with exactly the
 * OPTIONAL members its XER holds and re-encodes byte for byte.
 */
class SequenceBerTest {
    static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("Point", Point::new),
            Map.entry("Plain", Plain::new),
            Map.entry("Opt", Opt::new),
            Map.entry("Tagged", Tagged::new),
            Map.entry("Refs", Refs::new),
            Map.entry("Outer", Outer::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("sequence_ber_test.vectors").stream();
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static boolean xerHas(String xer, String member) {
        return xer.contains("<" + member + ">") || xer.contains("<" + member + "/>");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        Asn1Seq s = (Asn1Seq) v;
        List<MemberMeta> rows = s.spec().members();
        for (int i = 0; i < rows.size(); i++) {
            boolean present = !(s.getMember(i) instanceof MemberRef.Absent);
            assertEquals(xerHas(vec.xer(), rows.get(i).name()), present, rows.get(i).name());
        }
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    @Test
    void everyTypeHasAVector() {
        List<String> covered = vectors().map(Vectors.Vector::type).distinct().sorted().toList();
        assertEquals(TYPES.keySet().stream().sorted().toList(), covered);
    }

    @Test
    void membersSetByAccessorEncodeAsAsn1cDoes() {
        Opt o = new Opt();
        o.b(new Asn1Boolean(false));
        assertArrayEquals(hex("3003010100"), BerObject.encode(o));
        o.a(new Asn1Integer(7));
        o.b(new Asn1Boolean(true));
        assertArrayEquals(hex("30060201070101FF"), BerObject.encode(o));
        o.a(null);
        o.c(new Asn1OctetString(hex("FF")));
        assertArrayEquals(hex("30060101FF0401FF"), BerObject.encode(o));

        Tagged t = new Tagged();
        t.imp(new Asn1Integer(0));
        t.exp(new Asn1Boolean(true));
        t.optx(new Asn1Integer(9));
        assertArrayEquals(hex("300D800100A1030101FFA303020109"), BerObject.encode(t));
    }

    @Test
    void decodedValuesEqualConstructedOnes() {
        Point p = new Point();
        BerObject.decode(p, hex("30060201010201FE"));
        Point q = new Point();
        q.x(new Asn1Integer(1));
        q.y(new Asn1Integer(-2));
        assertEquals(q, p);
        assertEquals(q.hashCode(), p.hashCode());
        q.y(new Asn1Integer(2));
        assertNotEquals(q, p);
    }

    /** An OPTIONAL untagged CHOICE member is present when the next tag is one of its alternatives'. */
    @Test
    void optionalUntaggedChoiceIsDetectedByItsAlternativeTags() {
        Refs r = new Refs();
        BerObject.decode(r, hex("30320A010202010061030101006D030201FB300602010302010416017AA5030101FFA403020109160171A6083006020105020106"));
        Pick want = new Pick();
        want.s(new Asn1Ia5String("q"));
        assertEquals(want, r.opick());
        assertEquals(new Asn1Integer(5), r.opoint().x());
    }

    @Test
    void decodeResetsOptionalMembersTheInputLeavesOut() {
        Opt o = new Opt();
        o.a(new Asn1Integer(1));
        o.c(new Asn1OctetString(hex("01")));
        BerObject.decode(o, hex("3003010100"));
        assertNull(o.a());
        assertNull(o.c());
    }

    @Test
    void malformedInputIsADecodeError() {
        // A mandatory member missing.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Point(), hex("3003020101")));
        // A member with the wrong tag.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Point(), hex("30060101FF0201FE")));
        // Octets after the last member.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Point(), hex("30090201010201FE020100")));
        // Not a SEQUENCE.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Point(), hex("31060201010201FE")));
        assertThrows(DecodeException.class, () -> BerObject.decode(new Point(), new byte[0]));
    }
}
