package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import gen.set_ber.Mixed;
import gen.set_ber.Rec;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.ber.BerWriter;
import io.github.schramp.gambasasn1.wire.ber.Tag;
import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.ByteSource;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * SET under BER, against asn1c's DER for tests/asn1/set_ber_test.asn1:
 * decode accepts the components in any order (X.690 §8.11.2) and encode
 * writes them in canonical tag order (X.680 §8.6, X.690 §10.3).
 */
class SetBerTest {
    static final Map<String, Supplier<Asn1Pdu>> TYPES = Map.ofEntries(
            Map.entry("Rec", Rec::new),
            Map.entry("Mixed", Mixed::new));

    static Stream<Vectors.Vector> vectors() {
        return Vectors.load("set_ber_test.vectors").stream();
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    /** The component TLVs of an encoded SET, as they appear. */
    private static List<byte[]> components(byte[] der) {
        BerReader outer = new BerReader(der);
        BerReader r = new BerReader(outer.readTlv().value());
        ByteSource src = r.source();
        List<byte[]> parts = new ArrayList<>();
        while (!r.atEnd()) {
            int start = src.position();
            r.readTlv();
            parts.add(src.bytesSince(start));
        }
        return parts;
    }

    /** A SET of the given component TLVs, in the given order. */
    private static byte[] set(List<byte[]> parts) {
        ByteSink out = new ByteSink();
        BerWriter.writeTagged(out, Tag.universal(17, true), inner -> parts.forEach(inner::write));
        return out.toByteArray();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesAsn1cDerAndReencodesIt(Vectors.Vector vec) {
        Asn1Pdu v = TYPES.get(vec.type()).get();
        BerObject.decode(v, vec.der());
        assertArrayEquals(vec.der(), BerObject.encode(v));
    }

    /** asn1c's components in reverse order decode to the same value, which re-encodes canonically. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void decodesComponentsInAnyOrder(Vectors.Vector vec) {
        List<byte[]> parts = components(vec.der());
        Collections.reverse(parts);
        Asn1Pdu canonical = TYPES.get(vec.type()).get();
        BerObject.decode(canonical, vec.der());
        Asn1Pdu reversed = TYPES.get(vec.type()).get();
        BerObject.decode(reversed, set(parts));
        assertEquals(canonical, reversed);
        assertArrayEquals(vec.der(), BerObject.encode(reversed));
    }

    @Test
    void everyTypeHasAVector() {
        List<String> covered = vectors().map(Vectors.Vector::type).distinct().sorted().toList();
        assertEquals(TYPES.keySet().stream().sorted().toList(), covered);
    }

    @Test
    void membersSetByAccessorEncodeInCanonicalOrder() {
        Rec r = new Rec();
        r.third(new Asn1Integer(2));
        r.first(new Asn1Boolean(false));
        r.zeroth(new Asn1Integer(199));
        assertArrayEquals(hex("310A800200C7810100830102"), BerObject.encode(r));
    }

    @Test
    void malformedInputIsADecodeError() {
        List<byte[]> parts = components(hex("310A800200C7810100830102"));
        // A mandatory component missing.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Rec(), set(parts.subList(0, 2))));
        // A component twice.
        List<byte[]> twice = new ArrayList<>(parts);
        twice.add(parts.get(0));
        assertThrows(DecodeException.class, () -> BerObject.decode(new Rec(), set(twice)));
        // A SEQUENCE where a SET belongs.
        assertThrows(DecodeException.class, () -> BerObject.decode(new Rec(), hex("300A800200C7810100830102")));
    }
}
