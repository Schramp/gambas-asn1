package legs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gen.containing.Holder;
import gen.containing.Inner;
import gen.sequence_ber.Outer;
import gen.sequence_ber.Plain;
import gen.sequence_ber.Refs;
import gen.set_ber.Rec;
import gen.seqof_ber.Point;
import gen.seqof_ber.Points;
import io.github.schramp.gambasasn1.wire.ber.BerObject;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.containing.ContainedDecoders;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.per.PerObject;
import io.github.schramp.gambasasn1.wire.DecodeOptions;
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

    private static byte[] xor(byte[] b) {
        byte[] out = b.clone();
        for (int i = 0; i < out.length; i++) {
            out[i] ^= 0x5A;
        }
        return out;
    }

    @Test
    void berContainedValueDecodedFromTransformedBytesIsNotPlaced() {
        Holder src = new Holder();
        BerObject.decode(src, row("containing_test.vectors", "Holder", "<plain/>").der());
        for (var c : java.util.List.of(src.viaConstraint(), src.viaAlias(), src.viaSized())) {
            c.setBytes(xor(c.bytes()));
        }
        byte[] der = BerObject.encode(src);

        // A "plain" that deciphers first: the bytes it decodes are not on the wire.
        ContainedDecoders reg = new ContainedDecoders();
        reg.add("plain", a -> ContainedDecoders.decodeValueFrom(a, xor(a.raw()), null), null);
        Holder v = new Holder();
        Positions p = BerObject.decodeWithPositions(v, der,
                new DecodeOptions(new ContainedOptions(reg, false, null, null), false, false, false, null)).positions();

        Inner inner = v.viaConstraint().value();
        assertEquals(5, inner.id().get());
        assertEquals(7 * 8, p.contentsBit(v.viaConstraint()));
        assertTrue(!p.contains(inner));
        assertTrue(!p.contains(inner.id()));
        assertEquals(-1, p.bitOffset(v.viaSized().value()));
        // zero_padding decodes a prefix of the raw contents, which is on the wire.
        long at = p.byteOffset(v.viaConfig().value());
        byte[] bytes = v.viaConfig().bytes();
        assertArrayEquals(bytes, java.util.Arrays.copyOfRange(der, (int) at, (int) at + bytes.length));
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
    void berNodesSpanTheirWholeEncodingAndPrimitivesTheirContents() {
        // 30 11 | 30 0C | 02 01 01 | 01 01 00 | 0C 00 | 04 00 | 05 00 | 02 01 02
        byte[] der = hex("3011300C0201010101000C0004000500020102");
        Outer v = new Outer();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        assertEquals(8 * der.length, p.sizeBits(v));
        assertEquals(der.length, p.endByteOffset(v));
        assertEquals(8 * 14, p.sizeBits(v.inner()));
        assertEquals(16, p.endByteOffset(v.inner()));
        assertEquals(8 * 3, p.sizeBits(v.inner().num()));
        assertEquals(8 * 6, p.contentsBitOffset(v.inner().num()));
        assertEquals(8, p.contentsSizeBits(v.inner().num()));
        assertEquals(8 * 7, p.contentsEndBitOffset(v.inner().num()));
        // An empty value has empty contents right after its header.
        assertEquals(8 * 12, p.contentsBitOffset(v.inner().text()));
        assertEquals(0, p.contentsSizeBits(v.inner().text()));
        assertEquals(16, p.sizeBits(v.inner().nul()));
        // A constructed value has no contents span of its own.
        assertEquals(-1, p.contentsBitOffset(v.inner()));
    }

    @Test
    void berExplicitTagSpansTheOuterTlvAndItsContentsTheInnerOnes() {
        // 30 32 | 0A 01 02 | 02 01 00 | 61 03 [01 01 00] | 6D 03 [02 01 FB] | ...
        byte[] der = hex("30320A010202010061030101006D030201FB300602010302010416017AA5030101FFA403020109"
                + "160171A6083006020105020106");
        Refs v = new Refs();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        assertEquals(8, p.byteOffset(v.tbool().value));
        assertEquals(8 * 5, p.sizeBits(v.tbool().value));
        assertEquals(8 * 12, p.contentsBitOffset(v.tbool().value));
        assertEquals(8, p.contentsSizeBits(v.tbool().value));
        assertEquals(13, p.byteOffset(v.texp().value));
        assertEquals(18, p.endByteOffset(v.texp().value));
        assertEquals(8 * 17, p.contentsBitOffset(v.texp().value));
        assertEquals(8, p.contentsSizeBits(v.texp().value));
    }

    @Test
    void berSetComponentEndsFollowTheirWirePlace() {
        // 31 0A | 80 02 00 C7 (zeroth) | 81 01 00 (first) | 83 01 02 (third): table order is third, first, zeroth
        byte[] der = hex("310A800200C7810100830102");
        Rec v = new Rec();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        assertEquals(6, p.endByteOffset(v.zeroth()));
        assertEquals(8 * 4, p.sizeBits(v.zeroth()));
        assertEquals(8 * 4, p.contentsBitOffset(v.zeroth()));
        assertEquals(16, p.contentsSizeBits(v.zeroth()));
        assertEquals(9, p.endByteOffset(v.first()));
        assertEquals(12, p.endByteOffset(v.third()));
        assertEquals(8 * 11, p.contentsBitOffset(v.third()));
        assertEquals(12, p.endByteOffset(v));
    }

    @Test
    void berContainedInnerValueSpansItsOwnEncodingInsideTheFieldContents() {
        byte[] der = row("containing_test.vectors", "Holder", "<plain/>").der();
        Holder v = new Holder();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        // 30 2D | 80 01 01 | 81 05 [30 03 80 01 05] ...
        assertEquals(8 * 7, p.contentsBitOffset(v.viaConstraint()));
        assertEquals(8 * 5, p.contentsSizeBits(v.viaConstraint()));
        assertEquals(8 * 7, p.sizeBits(v.viaConstraint()));
        Inner inner = v.viaConstraint().value();
        assertEquals(8 * 5, p.sizeBits(inner));
        assertEquals(p.contentsEndBitOffset(v.viaConstraint()), p.endBitOffset(inner));
        assertEquals(8 * 7, p.bitOffset(inner));
        assertEquals(-1, p.contentsBitOffset(inner));
    }

    @Test
    void berEndsMoveWithTheBase() {
        byte[] one = hex("3011300C0201010101000C0004000500020102");
        byte[] two = hex("301030060201010201023006020103020104");
        byte[] both = new byte[one.length + two.length];
        System.arraycopy(one, 0, both, 0, one.length);
        System.arraycopy(two, 0, both, one.length, two.length);
        BerReader r = new BerReader(both);
        BerObject.decodeWithPositions(new Outer(), r);
        Points b = new Points();
        Positions p = BerObject.decodeWithPositions(b, r).positions();
        assertEquals(two.length, p.endByteOffset(b));
        assertEquals(18, p.endByteOffset(b.items().get(1)));
        Positions moved = p.withBase(8L * one.length);
        assertEquals(both.length, moved.endByteOffset(b));
        assertEquals(one.length + 17, moved.contentsBitOffset(b.items().get(1).y()) / 8);
        assertEquals(p.sizeBits(b), moved.sizeBits(b));
    }

    @Test
    void perNodesSpanTheirBits() {
        byte[] uper = row("sequence_ber_test.vectors", "Outer", "<tail>2</tail>").asn1cUper();
        Outer v = new Outer();
        Decoded d = PerObject.decodeWithPositions(v, uper, null);
        Positions p = d.positions();
        assertEquals(16, p.sizeBits(v.inner().num()));
        assertEquals(1, p.sizeBits(v.inner().flag()));
        assertEquals(0, p.sizeBits(v.inner().nul()));
        assertEquals(p.endBitOffset(v.tail()), p.endBitOffset(v));
        assertEquals(p.bitOffset(v.tail()), p.endBitOffset(v.inner()));
        assertEquals(uper.length, p.endByteOffset(v));
        assertEquals(-1, p.contentsBitOffset(v.inner().num()));
    }

    @Test
    void perContainedFieldContentsEndWithTheField() {
        byte[] uper = row("containing_test.vectors", "Holder", "<viaConstraint>008280").asn1cUper();
        Holder v = new Holder();
        Positions p = PerObject.decodeWithPositions(v, uper, null).positions();
        for (var c : java.util.List.of(v.viaConstraint(), v.viaAlias(), v.viaConfig(), v.viaSized())) {
            assertEquals(8L * c.bytes().length, p.contentsSizeBits(c), c.toString());
            assertEquals(p.endBitOffset(c), p.contentsEndBitOffset(c), c.toString());
        }
    }

    @Test
    void aBuiltinAliasObjectIsTheSameNodeAsItsValue() {
        byte[] der = hex("30320A010202010061030101006D030201FB300602010302010416017AA5030101FFA403020109"
                + "160171A6083006020105020106");
        Refs v = new Refs();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        assertTrue(p.contains(v.tbool()));
        assertEquals(p.bitOffset(v.tbool().value), p.bitOffset(v.tbool()));
        assertEquals(8 * 5, p.sizeBits(v.tbool()));
        assertEquals(8 * 17, p.valueBitOffset(v.texp()));
    }

    @Test
    void berValueSpans() {
        // 30 11 | 30 0C | 02 01 01 | 01 01 00 | 0C 00 | 04 00 | 05 00 | 02 01 02
        byte[] der = hex("3011300C0201010101000C0004000500020102");
        Outer v = new Outer();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        assertEquals(8 * 2, p.valueBitOffset(v));
        assertEquals(8 * 17, p.valueSizeBits(v));
        assertEquals(8 * 4, p.valueBitOffset(v.inner()));
        assertEquals(8 * 16, p.valueEndBitOffset(v.inner()));
        assertEquals(p.contentsBitOffset(v.inner().num()), p.valueBitOffset(v.inner().num()));
        assertEquals(8, p.valueSizeBits(v.inner().num()));
        assertEquals(0, p.valueSizeBits(v.inner().data()));
    }

    @Test
    void berChoiceValueIsItsAlternativesAndEnumeratedItsContents() {
        // 30 32 | 0A 01 02 (color) | ... | 16 01 7A (pick s "z") at 29
        byte[] der = hex("30320A010202010061030101006D030201FB300602010302010416017AA5030101FFA403020109"
                + "160171A6083006020105020106");
        Refs v = new Refs();
        Positions p = BerObject.decodeWithPositions(v, der, null).positions();
        assertEquals(8 * 4, p.valueBitOffset(v.color()));
        assertEquals(8, p.valueSizeBits(v.color()));
        assertEquals(-1, p.contentsBitOffset(v.pick()));
        assertEquals(8 * 28, p.valueBitOffset(v.pick()));
        assertEquals(8, p.valueSizeBits(v.pick()));
    }

    @Test
    void bitStringValueLeavesOutTheUnusedBitsOctetAndTheUnusedBits() {
        io.github.schramp.gambasasn1.wire.types.Asn1BitString b = new io.github.schramp.gambasasn1.wire.types.Asn1BitString();
        // 03 03 04 A5 B0: unused-bits octet 4, value 1010 0101 1011 (12 bits).
        byte[] der = hex("030304A5B0");
        Positions p = BerObject.decodeWithPositions(b, der, null).positions();
        assertEquals(8 * 2, p.contentsBitOffset(b));
        assertEquals(8 * 3, p.contentsSizeBits(b));
        assertEquals(8 * 3, p.valueBitOffset(b));
        assertEquals(12, p.valueSizeBits(b));
        PerObject.decodeWithPositions(new io.github.schramp.gambasasn1.wire.types.Asn1BitString(), PerObject.encode(b), null);
        io.github.schramp.gambasasn1.wire.types.Asn1BitString c = new io.github.schramp.gambasasn1.wire.types.Asn1BitString();
        Positions q = PerObject.decodeWithPositions(c, PerObject.encode(b), null).positions();
        // An unconstrained BIT STRING: an 8-bit length, then the bits (X.691 §16.11).
        assertEquals(8, q.valueBitOffset(c));
        assertEquals(12, q.valueSizeBits(c));
    }

    @Test
    void perContainedAndOctetStringValues() {
        byte[] uper = row("containing_test.vectors", "Holder", "<viaConstraint>008280").asn1cUper();
        Holder v = new Holder();
        Positions p = PerObject.decodeWithPositions(v, uper, null).positions();
        for (var c : java.util.List.of(v.viaConstraint(), v.viaAlias(), v.viaConfig(), v.viaSized())) {
            assertEquals(p.contentsBitOffset(c), p.valueBitOffset(c), c.toString());
            assertEquals(8L * c.bytes().length, p.valueSizeBits(c), c.toString());
        }
        io.github.schramp.gambasasn1.wire.types.Asn1OctetString o = new io.github.schramp.gambasasn1.wire.types.Asn1OctetString();
        o.set(hex("010203"));
        io.github.schramp.gambasasn1.wire.types.Asn1OctetString back = new io.github.schramp.gambasasn1.wire.types.Asn1OctetString();
        Positions q = PerObject.decodeWithPositions(back, PerObject.encode(o), null).positions();
        assertEquals(8, q.valueBitOffset(back));
        assertEquals(24, q.valueSizeBits(back));
    }

    /**
     * Over every record of the ETSI sample: each node's contents lie inside
     * its encoding, which lies inside the record, and an OCTET STRING's
     * contents span holds exactly its value.
     */
    @Test
    void etsiSampleSpansNestAndOctetStringContentsAreTheirValue() throws java.io.IOException {
        byte[] all = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(System.getProperty("etsi.sample")));
        BerReader r = new BerReader(all);
        int strings = 0;
        while (!r.atEnd()) {
            long base = 8L * r.position();
            gen.etsi.LI_PS_PDU.PS_PDU pdu = new gen.etsi.LI_PS_PDU.PS_PDU();
            Decoded d = BerObject.decodeWithPositions(pdu, r);
            Positions p = d.positions().withBase(base);
            assertEquals(base + 8L * d.bytesConsumed(), p.endBitOffset(pdu));
            for (Object n : p.nodes()) {
                long start = p.bitOffset(n);
                long end = p.endBitOffset(n);
                assertTrue(start >= base && start <= end && end <= p.endBitOffset(pdu),
                        start + ".." + end + " in " + base + ".." + p.endBitOffset(pdu) + ": " + n.getClass());
                long cs = p.contentsBitOffset(n);
                if (cs >= 0) {
                    assertTrue(start <= cs && cs <= p.contentsEndBitOffset(n) && p.contentsEndBitOffset(n) <= end,
                            start + ".." + end + " contents " + cs + ".." + p.contentsEndBitOffset(n) + ": " + n.getClass());
                }
                if (n instanceof io.github.schramp.gambasasn1.wire.types.Asn1OctetString o) {
                    assertEquals(cs, p.valueBitOffset(n));
                    assertEquals(8L * o.get().length, p.valueSizeBits(n));
                    assertArrayEquals(o.get(), java.util.Arrays.copyOfRange(all, (int) (cs / 8),
                            (int) (p.contentsEndBitOffset(n) / 8)));
                    strings++;
                }
            }
        }
        assertTrue(strings > 0);
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
