package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.DecodeOptions;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.Nesting;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Decoded;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Reads BER records one at a time from an {@link InputStream}, such as an
 * ETSI LI file of PS-PDUs back to back (book.md, "Reading Records from Files
 * and Streams").
 *
 * <p>Each {@link #next()} returns one complete top-level TLV with its
 * absolute 64-bit offset, so a file of any size is read in the memory of
 * its largest record. The framer reads exactly up to the end of each record
 * and does no buffering of its own: wrap a file in a
 * {@link java.io.BufferedInputStream}. It follows the contract of the C++
 * {@code BerFrameReader} and the Rust {@code ReadFrames}; {@code tests/framing}
 * holds the vectors all three pass.
 *
 * <pre>{@code
 * try (InputStream in = new BufferedInputStream(Files.newInputStream(path))) {
 *     BerFrames frames = new BerFrames(in);
 *     for (Frame f; (f = frames.next()) != null; ) {   // DecodeException here: no next record
 *         PS_PDU pdu = new PS_PDU();
 *         try {
 *             BerFrames.decode(pdu, f, opts);
 *         } catch (DecodeException e) {                // the next record is still read
 *             System.err.println("skipped: " + e.getMessage());
 *             continue;
 *         }
 *         handle(pdu);
 *     }
 * }
 * }</pre>
 *
 * <p>After a framing error, or a read error, every later {@link #next()}
 * throws that same exception again: the framer cannot know where the next
 * record starts.
 */
public final class BerFrames {
    private final InputStream in;
    private final FrameLimits limits;
    private byte[] buf = new byte[256];
    private int len;
    private long offset;
    private Exception failed;

    /** Frames the records of {@code in} with {@link FrameLimits#DEFAULT}. */
    public BerFrames(InputStream in) {
        this(in, FrameLimits.DEFAULT);
    }

    /** Frames the records of {@code in} with {@code limits} per record. */
    public BerFrames(InputStream in, FrameLimits limits) {
        this.in = in;
        this.limits = limits;
    }

    /**
     * Reads one record from {@code in}, leaving the stream at the start of
     * the next one.
     *
     * @return the record's tag, length and contents octets, or {@code null}
     *         when the stream ends before its first octet
     * @throws DecodeException if the input is not a well-formed record (see {@link #next()})
     * @throws IOException if reading {@code in} fails
     */
    public static byte[] readOne(InputStream in) throws IOException, DecodeException {
        Frame f = new BerFrames(in).next();
        return f == null ? null : f.bytes();
    }

    /**
     * Reads the next record.
     *
     * @return the frame, or {@code null} at the end of the input
     * @throws DecodeException if the input is not a well-formed record. The
     *         message starts with a reason key ({@code truncated},
     *         {@code tag-too-long}, {@code length-field-too-long},
     *         {@code indefinite-primitive}, {@code frame-too-large},
     *         {@code too-deep}) and {@link DecodeException#position()} is
     *         absolute in the input
     * @throws IOException if reading the input fails
     */
    public Frame next() throws IOException, DecodeException {
        if (failed instanceof IOException e) {
            throw e;
        }
        if (failed instanceof DecodeException e) {
            throw e;
        }
        len = 0;
        int n;
        try {
            n = frameLength();
        } catch (IOException | DecodeException e) {
            failed = e;
            throw e;
        }
        if (n < 0) {
            return null;
        }
        Frame f = new Frame(offset, Arrays.copyOf(buf, n));
        offset += n;
        return f;
    }

    /** Offset of the next record: the octets consumed so far. */
    public long offset() {
        return offset;
    }

    /**
     * BER-decodes one frame into {@code v}. {@code opts} may be null.
     *
     * @throws DecodeException if the frame is not a valid BER encoding of the type of
     *         {@code v}; {@link DecodeException#position()} is absolute in the input
     */
    public static void decode(AsMemberRef v, Frame f, DecodeOptions opts) throws DecodeException {
        try {
            BerObject.decode(v, f.bytes(), opts);
        } catch (DecodeException e) {
            throw e.withBase(f.offset());
        }
    }

    /**
     * {@link #decode} that also records where every decoded node starts, in
     * bits from the start of the input (the frame's offset included).
     *
     * @throws DecodeException if the frame is not a valid BER encoding of the type of
     *         {@code v}; {@link DecodeException#position()} is absolute in the input
     */
    public static Decoded decodeWithPositions(AsMemberRef v, Frame f, DecodeOptions opts) throws DecodeException {
        Decoded d;
        try {
            d = BerObject.decodeWithPositions(v, f.bytes(), opts);
        } catch (DecodeException e) {
            throw e.withBase(f.offset());
        }
        return new Decoded(d.bytesConsumed(), d.positions().withBase(8 * f.offset()));
    }

    // --- the walk -------------------------------------------------------------
    //
    // Finds the length of the record at the stream position, reading exactly
    // its octets into buf: definite contents are skipped without being
    // parsed, an indefinite-length record is closed by walking its nested
    // headers to the matching end-of-contents octets (X.690 §8.1.2, §8.1.3,
    // §8.1.5). The same walk as the C++ and Rust framers.

    /** @return the frame length, or -1 when the input ends before its first octet */
    private int frameLength() throws IOException, DecodeException {
        if (!fill(1)) {
            return -1;
        }
        Header h = new Header();
        header(0, h);
        if (!h.indefinite) {
            return skip(h);
        }
        int depth = 1;
        int pos = h.end;
        for (;;) {
            header(pos, h);
            if (h.eoc) {
                pos = h.end;
                if (--depth == 0) {
                    return pos;
                }
            } else if (h.indefinite) {
                if (depth == Nesting.MAX_DECODE_DEPTH) {
                    throw new DecodeException("too-deep: more than " + Nesting.MAX_DECODE_DEPTH
                            + " nested indefinite-length levels", offset + pos);
                }
                ++depth;
                pos = h.end;
            } else {
                pos = skip(h);
            }
        }
    }

    /** The identifier and length octets of one TLV inside the frame. */
    private static final class Header {
        /** Frame offset just past the length octets. */
        int end;
        /** Definite length; negative when eight length octets exceed a signed long. */
        long length;
        /** Length octet 0x80 (X.690 §8.1.3.6). */
        boolean indefinite;
        /** The end-of-contents octets 00 00 (X.690 §8.1.5). */
        boolean eoc;
    }

    /** Parses the identifier and length octets at frame offset {@code pos} into {@code h}. */
    private void header(int pos, Header h) throws IOException, DecodeException {
        need(pos + 1L);
        int first = buf[pos] & 0xFF;
        boolean constructed = (first & 0x20) != 0;
        int p = pos + 1;
        if ((first & 0x1F) == 0x1F) {
            long number = 0;
            for (int k = 1;; ++k) {
                need(p + 1L);
                int b = buf[p++] & 0xFF;
                number = (number << 7) | (b & 0x7F);
                if ((b & 0x80) == 0) {
                    break;
                }
                if (k == 5) {
                    throw tagTooLong(pos);
                }
            }
            if (number > 0x7FFF_FFFFL) {
                throw tagTooLong(pos);
            }
        }
        need(p + 1L);
        int l = buf[p] & 0xFF;
        h.eoc = first == 0 && l == 0;
        if (l == 0x80) {
            if (!constructed) {
                throw new DecodeException("indefinite-primitive: indefinite length on a primitive encoding",
                        offset + p);
            }
            h.end = p + 1;
            h.length = 0;
            h.indefinite = true;
            return;
        }
        h.indefinite = false;
        if ((l & 0x80) != 0) {
            int n = l & 0x7F;
            if (n > 8) {
                throw new DecodeException("length-field-too-long: length field of " + n + " octets (at most 8)",
                        offset + p);
            }
            need(p + 1L + n);
            long length = 0;
            for (int i = 0; i < n; ++i) {
                length = (length << 8) | (buf[p + 1 + i] & 0xFF);
            }
            h.length = length;
            h.end = p + 1 + n;
            return;
        }
        h.length = l;
        h.end = p + 1;
    }

    /** Reads definite contents: the whole TLV must fit the limit. */
    private int skip(Header h) throws IOException, DecodeException {
        long end = h.end + h.length;
        if (h.length < 0 || end > limits.maxFrame()) {
            throw tooLarge();
        }
        need(end);
        return (int) end;
    }

    /**
     * Makes the first {@code n} frame octets available: frame-too-large past
     * the limit (checked before reading), truncated when the input ends first.
     */
    private void need(long n) throws IOException, DecodeException {
        if (n > limits.maxFrame()) {
            throw tooLarge();
        }
        if (!fill((int) n)) {
            throw new DecodeException("truncated: input ends inside a record", offset + len);
        }
    }

    /** Reads up to {@code n} frame octets in all; false when the input ends first. */
    private boolean fill(int n) throws IOException {
        if (n > buf.length) {
            buf = Arrays.copyOf(buf, Math.max(n, (int) Math.min(Integer.MAX_VALUE - 8, 2L * buf.length)));
        }
        while (len < n) {
            int got = in.read(buf, len, n - len);
            if (got < 0) {
                return false;
            }
            len += got;
        }
        return true;
    }

    private DecodeException tagTooLong(int pos) {
        return new DecodeException("tag-too-long: tag number longer than 5 octets or above 2^31-1", offset + pos);
    }

    private DecodeException tooLarge() {
        return new DecodeException("frame-too-large: record longer than " + limits.maxFrame() + " octets", offset);
    }
}
