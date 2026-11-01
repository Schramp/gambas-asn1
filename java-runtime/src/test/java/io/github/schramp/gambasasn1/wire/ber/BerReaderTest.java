package io.github.schramp.gambasasn1.wire.ber;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import org.junit.jupiter.api.Test;

class BerReaderTest {

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) {
            b[i] = (byte) v[i];
        }
        return b;
    }

    @Test
    void tagRoundTrip() {
        for (TagClass cls : TagClass.values()) {
            for (int n : new int[] {0, 1, 30, 31, 127, 128, 16383, 16384, Integer.MAX_VALUE}) {
                for (boolean constructed : new boolean[] {false, true}) {
                    Tag t = new Tag(cls, n, constructed);
                    ByteSink out = new ByteSink();
                    BerWriter.writeTag(out, t);
                    BerReader r = new BerReader(out.toByteArray());
                    assertEquals(t, r.peekTag());
                    assertEquals(t, r.readTag());
                    assertTrue(r.atEnd());
                }
            }
        }
    }

    @Test
    void definiteLengthNested() {
        BerReader r = new BerReader(bytes(0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x2A, 0x05, 0x00));
        Tlv seq = r.readTlv();
        assertEquals(Tag.universal(UniversalTag.SEQUENCE, true), seq.tag());
        BerReader inner = new BerReader(seq.value());
        assertArrayEquals(bytes(0xFF), inner.readTlv().value().remainingBytes());
        assertArrayEquals(bytes(0x2A), inner.readTlv().value().remainingBytes());
        assertTrue(inner.atEnd());
        assertEquals(0, r.readTlv().value().remaining());
        assertTrue(r.atEnd());
    }

    @Test
    void indefiniteLengthNested() {
        // [0] { SEQUENCE (indefinite) { INTEGER 5 } } with end-of-contents octets
        BerReader r = new BerReader(bytes(0xA0, 0x80, 0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00));
        Tlv outer = r.readTlv();
        assertArrayEquals(bytes(0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00), outer.value().remainingBytes());
        Tlv inner = new BerReader(outer.value()).readTlv();
        assertArrayEquals(bytes(0x02, 0x01, 0x05), inner.value().remainingBytes());
        assertEquals(Tag.universal(UniversalTag.BOOLEAN, false), r.readTlv().tag());
    }

    @Test
    void longLength() {
        byte[] data = new byte[4 + 300];
        data[0] = 0x04;
        data[1] = (byte) 0x82;
        data[2] = 0x01;
        data[3] = 0x2C;
        assertEquals(300, new BerReader(data).readTlv().value().remaining());
    }

    @Test
    void malformedInputIsADecodeException() {
        int[][] cases = {
            {},                             // no tag
            {0x1F},                         // high tag number cut off
            {0x1F, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F}, // tag number above 2^31-1
            {0x04},                         // no length
            {0x04, 0x05, 0x01},             // contents cut off
            {0x04, 0x82, 0x01},             // length octets cut off
            {0x04, 0x85, 0, 0, 0, 0, 1},    // 5 length octets
            {0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF}, // length above 2 GiB
            {0x04, 0x80, 0x00, 0x00},       // indefinite length on a primitive
            {0x30, 0x80, 0x02, 0x01, 0x05}, // no end-of-contents
            {0x30, 0x80, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00}, // nested indefinite primitive
        };
        for (int[] c : cases) {
            BerReader r = new BerReader(bytes(c));
            assertThrows(DecodeException.class, r::readTlv, () -> java.util.Arrays.toString(c));
        }
    }
}
