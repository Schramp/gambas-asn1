package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.containing.Holder;
import gen.containing.Inner;
import gen.sequence_ber.Outer;
import gen.sequence_ber.Plain;
import gen.set_ber.Rec;
import gen.seqof_ber.Point;
import gen.seqof_ber.Points;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.spec.Decoded;
import io.github.schramp.gambasasn1.wire.spec.Positions;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * Per-node source positions: where in the input each decoded value starts,
 * for BER (its first tag octet) and unaligned PER (its first bit), over
 * asn1c's encodings of the codec-test schemas.
 */
class PositionsTest {
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static Vectors.Vector row(String file, String type, String xerPart) {
        return Vectors.load(file).stream()
                .filter(v -> v.type().equals(type) && v.xer().contains(xerPart))
                .findFirst().orElseThrow();
    }

    /** The {@code octets} octets of {@code data} that start at bit {@code at}. */
    private static byte[] bitsAt(byte[] data, long at, int octets) {
        byte[] out = new byte[octets];
        for (int i = 0; i < 8 * octets; i++) {
            long b = at + i;
            int bit = (data[(int) (b / 8)] >> (7 - (int) (b % 8))) & 1;
            out[i / 8] |= (byte) (bit << (7 - i % 8));
        }
        return out;
    }

    @Test
    void berNestedSequenceMembersStartAtTheirTagOctet() {
        // 30 11 | 30 0C | 02 01 01 | 01 01 00 | 0C 00 | 04 00 | 05 00 | 02 01 02
        byte[] der = hex("3011300C0201010101000C0004000500020102");
        Outer v = new Outer();
        Decoded d = BerObject.decodeWithPositions(v, der, null);
        Positions p = d.positions();
        assertEquals(der.length, d.bytesConsumed());
        assertEquals(0, p.byteOffset(v));
        Plain in = v.inner();
        assertEquals(2, p.byteOffset(in));
        assertEquals(4, p.byteOffset(in.num()));
        assertEquals(7, p.byteOffset(in.flag()));
        assertEquals(10, p.byteOffset(in.text()));
        assertEquals(12, p.byteOffset(in.data()));
        assertEquals(14, p.byteOffset(in.nul()));
        assertEquals(16, p.byteOffset(v.tail()));
        assertEquals(8 * 16, p.bitOffset(v.tail()));
    }

    @Test
    void berSequenceOfElementsEachHaveTheirOwnPosition() {
        // 30 10 | 30 06 02 01 01 02 01 02 | 30 06 02 01 03 02 01 04
        byte[] der = hex("301030060201010201023006020103020104");
        Points v = new Points();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        Point second = v.items().get(1);
        assertEquals(2, p.byteOffset(v.items().get(0)));
        assertEquals(10, p.byteOffset(second));
        assertEquals(15, p.byteOffset(second.y()));
    }

    @Test
    void berSetComponentsKeepTheirWirePositionsAfterReordering() {
        // 31 0A | 80 02 00 C7 (zeroth) | 81 01 00 (first) | 83 01 02 (third): table order is third, first, zeroth
        byte[] der = hex("310A800200C7810100830102");
        Rec v = new Rec();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        assertEquals(0, p.byteOffset(v));
        assertEquals(2, p.byteOffset(v.zeroth()));
        assertEquals(6, p.byteOffset(v.first()));
        assertEquals(9, p.byteOffset(v.third()));
        assertTrue(!p.contains(v.second()));
    }

    @Test
    void berContainedValueIsPlacedAtItsContentsOctets() {
        byte[] der = row("containing_test.vectors", "Holder", "<plain/>").der();
        Holder v = new Holder();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        // 30 2D | 80 01 01 | 81 05 [30 03 80 01 05] ...
        assertEquals(5, p.byteOffset(v.viaConstraint()));
        assertEquals(7 * 8, p.contentsBit(v.viaConstraint()));
        Inner inner = v.viaConstraint().value();
        assertEquals(7, p.byteOffset(inner));
        assertEquals(9, p.byteOffset(inner.id()));
        for (var c : java.util.List.of(v.viaConstraint(), v.viaAlias(), v.viaConfig(), v.viaSized())) {
            long at = p.byteOffset(c.value());
            byte[] bytes = c.bytes();
            assertArrayEquals(bytes, java.util.Arrays.copyOfRange(der, (int) at, (int) at + bytes.length));
        }
    }

    @Test
    void berRecordsReadBackToBackAreEachRelativeToTheirOwnStart() {
        byte[] one = hex("3011300C0201010101000C0004000500020102");
        byte[] two = hex("301030060201010201023006020103020104");
        byte[] both = new byte[one.length + two.length];
        System.arraycopy(one, 0, both, 0, one.length);
        System.arraycopy(two, 0, both, one.length, two.length);
        BerReader r = new BerReader(both);
        Outer a = new Outer();
        Decoded da = BerObject.decodeWithPositions(a, r);
        Points b = new Points();
        Decoded db = BerObject.decodeWithPositions(b, r);
        assertEquals(one.length, da.bytesConsumed());
        assertEquals(two.length, db.bytesConsumed());
        assertEquals(0, db.positions().byteOffset(b));
        assertEquals(10, db.positions().byteOffset(b.items().get(1)));
        assertEquals(one.length + 10, db.positions().withBase(8L * one.length).byteOffset(b.items().get(1)));
    }

    @Test
    void perMembersStartAtTheirFirstBit() {
        byte[] uper = row("sequence_ber_test.vectors", "Outer", "<tail>2</tail>").asn1cUper();
        Outer v = new Outer();
        Decoded d = PerObject.decodeWithPositions(v, uper, null);
        Positions p = d.positions();
        assertEquals(uper.length, d.bytesConsumed());
        assertEquals(0, p.bitOffset(v));
        assertEquals(0, p.bitOffset(v.inner()));
        assertEquals(0, p.bitOffset(v.inner().num()));
        // num: an 8-bit length and one octet; flag is one bit after it.
        assertEquals(16, p.bitOffset(v.inner().flag()));
        assertEquals(17, p.bitOffset(v.inner().text()));
        // NULL takes no bits (X.691 §24), so it starts where tail does.
        assertEquals(p.bitOffset(v.inner().nul()), p.bitOffset(v.tail()));
    }

    @Test
    void perContainedValueIsPlacedAtItsContentsBits() {
        byte[] uper = row("containing_test.vectors", "Holder", "<viaConstraint>008280").asn1cUper();
        Holder v = new Holder();
        Positions p = PerObject.decodeWithPositions(v, uper, null).positions();
        for (var c : java.util.List.of(v.viaConstraint(), v.viaAlias(), v.viaConfig(), v.viaSized())) {
            byte[] bytes = c.bytes();
            long at = p.contentsBit(c);
            assertTrue(at > p.bitOffset(c), c.toString());
            assertArrayEquals(bytes, bitsAt(uper, at, bytes.length));
            if (c.value() != null) {
                assertEquals(at, p.bitOffset(c.value()));
            }
        }
    }

    @Test
    void plainDecodeRecordsNothing() {
        Outer v = new Outer();
        BerObject.decode(v, hex("3011300C0201010101000C0004000500020102"));
        Positions p = BerObject.decodeWithPositions(new Outer(), hex("3011300C0201010101000C0004000500020102"), null)
                .positions();
        assertTrue(!p.contains(v));
        assertEquals(-1, p.bitOffset(v.tail()));
    }
}
