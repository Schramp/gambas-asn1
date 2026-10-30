package io.github.schramp.gambasasn1.wire.ber;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class BerWriterTest {

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) {
            b[i] = (byte) v[i];
        }
        return b;
    }

    @Test
    void writeTaggedLengthForms() {
        Object[][] cases = {
            {0, bytes(0x00)}, {127, bytes(0x7F)}, {128, bytes(0x81, 0x80)}, {255, bytes(0x81, 0xFF)},
            {256, bytes(0x82, 0x01, 0x00)}, {65535, bytes(0x82, 0xFF, 0xFF)}, {65536, bytes(0x83, 0x01, 0x00, 0x00)},
            {(1 << 24) - 1, bytes(0x83, 0xFF, 0xFF, 0xFF)}, {1 << 24, bytes(0x84, 0x01, 0x00, 0x00, 0x00)},
        };
        for (Object[] c : cases) {
            int n = (Integer) c[0];
            byte[] lenOctets = (byte[]) c[1];
            ByteSink out = new ByteSink();
            out.write(0xAA);
            BerWriter.writeTagged(out, Tag.universal(UniversalTag.OCTET_STRING, false), s -> s.pad(n));
            byte[] got = out.toByteArray();
            assertEquals(2 + lenOctets.length + n, got.length, "size for " + n);
            assertEquals((byte) 0xAA, got[0]);
            assertEquals(0x04, got[1]);
            assertArrayEquals(lenOctets, Arrays.copyOfRange(got, 2, 2 + lenOctets.length), "length octets for " + n);
        }
    }

    @Test
    void writeTaggedKeepsContentWhenShifting() {
        ByteSink out = new ByteSink();
        BerWriter.writeTagged(out, Tag.universal(UniversalTag.SEQUENCE, true), s -> {
            BerWriter.writePrimitive(s, Tag.universal(UniversalTag.BOOLEAN, false), bytes(0xFF));
            BerWriter.writeTagged(s, Tag.context(0, true), t ->
                    BerWriter.writePrimitive(t, Tag.universal(UniversalTag.INTEGER, false), bytes(0x2A)));
        });
        assertArrayEquals(bytes(0x30, 0x08, 0x01, 0x01, 0xFF, 0xA0, 0x03, 0x02, 0x01, 0x2A), out.toByteArray());
    }

    @Test
    void highTagNumbers() {
        int[][] cases = {{30, 0x1E}, {31, 0x1F, 0x1F}, {127, 0x1F, 0x7F}, {128, 0x1F, 0x81, 0x00},
            {16383, 0x1F, 0xFF, 0x7F}, {Integer.MAX_VALUE, 0x1F, 0x87, 0xFF, 0xFF, 0xFF, 0x7F}};
        for (int[] c : cases) {
            ByteSink out = new ByteSink();
            BerWriter.writeTag(out, new Tag(TagClass.UNIVERSAL, c[0], false));
            assertArrayEquals(bytes(Arrays.copyOfRange(c, 1, c.length)), out.toByteArray(), "tag " + c[0]);
        }
        ByteSink out = new ByteSink();
        BerWriter.writeTag(out, new Tag(TagClass.PRIVATE, 5, true));
        BerWriter.writeTag(out, new Tag(TagClass.APPLICATION, 1, false));
        assertArrayEquals(bytes(0xE5, 0x41), out.toByteArray());
    }
}
