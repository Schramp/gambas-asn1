package io.github.schramp.gambasasn1.wire.ber;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * BER record framing (book.md "Reading Records from Files and Streams"):
 * every vector of {@code tests/framing/framing.vectors}, shared with the C++
 * and Rust framers, through a stream read in bulk and one that delivers one
 * octet per read. Both must report exactly the frames and the result given
 * there, and leave the stream at the end of each frame.
 */
class BerFramesTest {

    private record Expect(String file, int maxFrame, List<long[]> frames, String result) {
    }

    private static Path dir() {
        return Path.of(System.getProperty("framing.vectors", "../tests/framing"));
    }

    private static List<Expect> load() throws IOException {
        List<Expect> out = new ArrayList<>();
        for (String line : Files.readAllLines(dir().resolve("framing.vectors"))) {
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] c = line.split("\t");
            List<long[]> frames = new ArrayList<>();
            if (!c[2].equals("-")) {
                for (String f : c[2].split(",")) {
                    String[] p = f.split("\\+");
                    frames.add(new long[] {Long.parseLong(p[0]), Long.parseLong(p[1])});
                }
            }
            int max = c[1].equals("-") ? FrameLimits.DEFAULT.maxFrame() : Integer.parseInt(c[1]);
            out.add(new Expect(c[0], max, frames, c[3]));
        }
        return out;
    }

    /** Counts the octets read through it; with {@code oneOctet} at most one per read. */
    private static final class Counting extends FilterInputStream {
        long count;
        final boolean oneOctet;

        Counting(InputStream in, boolean oneOctet) {
            super(in);
            this.oneOctet = oneOctet;
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b >= 0) {
                count++;
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int got = super.read(b, off, oneOctet ? Math.min(len, 1) : len);
            if (got > 0) {
                count += got;
            }
            return got;
        }
    }

    private static String key(DecodeException e) {
        String m = e.reason();
        return "error " + m.substring(0, m.indexOf(':')) + " " + e.position();
    }

    private static void check(Expect v, byte[] data, boolean oneOctet) throws IOException {
        Counting in = new Counting(new ByteArrayInputStream(data), oneOctet);
        BerFrames frames = new BerFrames(in, new FrameLimits(v.maxFrame()));
        List<long[]> got = new ArrayList<>();
        String result;
        String how = v.file() + (oneOctet ? " (one octet per read)" : "");
        for (;;) {
            Frame f;
            try {
                f = frames.next();
            } catch (DecodeException e) {
                DecodeException again = assertThrows(DecodeException.class, frames::next, how + ": error not sticky");
                assertSame(e, again);
                result = key(e);
                break;
            }
            if (f == null) {
                result = "end";
                break;
            }
            int off = (int) f.offset();
            assertArrayEquals(Arrays.copyOfRange(data, off, off + f.bytes().length), f.bytes(), how);
            got.add(new long[] {f.offset(), f.bytes().length});
            assertEquals(f.offset() + f.bytes().length, in.count, how + ": stream not left at the end of the frame");
        }
        assertEquals(render(v.frames()), render(got), how + ": frames");
        assertEquals(v.result(), result, how + ": result");
    }

    private static String render(List<long[]> frames) {
        return String.join(",", frames.stream().map(f -> f[0] + "+" + f[1]).toList());
    }

    @Test
    void sharedFramingVectors() throws IOException {
        List<Expect> vectors = load();
        assertTrue(vectors.size() > 20);
        for (Expect v : vectors) {
            byte[] data = Files.readAllBytes(dir().resolve(v.file()));
            check(v, data, false);
            check(v, data, true);
        }
    }

    @Test
    void readOneLeavesTheStreamAtTheNextRecord() throws IOException, DecodeException {
        byte[] data = {0x02, 0x01, 0x05, 0x30, (byte) 0x80, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00};
        InputStream in = new ByteArrayInputStream(data);
        assertArrayEquals(new byte[] {0x02, 0x01, 0x05}, BerFrames.readOne(in));
        assertArrayEquals(new byte[] {0x30, (byte) 0x80, 0x05, 0x00, 0x00, 0x00}, BerFrames.readOne(in));
        assertEquals(0x04, in.read());
        assertEquals(0x00, in.read());
        assertNull(BerFrames.readOne(in));
    }

    @Test
    void decodeRebasesErrorsAndPositionsAndTheStreamGoesOn() throws IOException, DecodeException {
        // Three INTEGER records; the second has no contents octets, which
        // X.690 §8.3.1 forbids. The frames are moved 100 octets into a
        // larger input to check the rebasing.
        byte[] data = {0x02, 0x01, 0x05, 0x02, 0x00, 0x02, 0x01, 0x07};
        BerFrames frames = new BerFrames(new ByteArrayInputStream(data));
        Frame a = frames.next();
        Asn1Integer i = new Asn1Integer();
        var d = BerFrames.decodeWithPositions(i, new Frame(a.offset() + 100, a.bytes()), null);
        assertEquals(5, i.get());
        assertEquals(3, d.bytesConsumed());
        assertEquals(8 * 100, d.positions().base());
        Frame b = frames.next();
        assertEquals(3, b.offset());
        DecodeException e = assertThrows(DecodeException.class,
                () -> BerFrames.decode(new Asn1Integer(), new Frame(b.offset() + 100, b.bytes()), null));
        assertTrue(e.position() >= 103, e.getMessage());
        Asn1Integer k = new Asn1Integer();
        BerFrames.decode(k, frames.next(), null);
        assertEquals(7, k.get());
        assertNull(frames.next());
    }

    @Test
    void offsetsPastTwoGibAreLongs() {
        DecodeException e = new DecodeException("truncated: input ends inside a record", 5L << 30);
        assertEquals(5L << 30, e.position());
        assertTrue(e.getMessage().endsWith("at byte 5368709120"), e.getMessage());
        assertEquals((5L << 30) + 7, e.withBase(7).position());
    }

    @Test
    void readFailureIsAnIoExceptionAndSticks() {
        IOException boom = new IOException("disk on fire");
        BerFrames frames = new BerFrames(new InputStream() {
            @Override
            public int read() throws IOException {
                throw boom;
            }
        });
        assertSame(boom, assertThrows(IOException.class, frames::next));
        assertSame(boom, assertThrows(IOException.class, frames::next));
    }

    @Test
    void limitsMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> new FrameLimits(0));
    }
}
