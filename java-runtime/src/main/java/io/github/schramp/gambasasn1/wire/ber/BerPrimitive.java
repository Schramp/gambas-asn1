package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.ByteSource;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.types.Asn1Any;
import io.github.schramp.gambasasn1.wire.types.Asn1Arcs;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1CharString;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1ObjectIdentifier;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import io.github.schramp.gambasasn1.wire.types.Asn1Real;
import io.github.schramp.gambasasn1.wire.types.Asn1RelativeOid;
import io.github.schramp.gambasasn1.wire.types.Asn1UInteger;
import java.util.Arrays;

/**
 * BER for builtin leaf values: one switch over the builtin wrappers for the
 * natural tag and the contents octets, and the member's own framing
 * (X.690 §8.14) applied around them.
 */
public final class BerPrimitive {
    private static final Tag BOOLEAN_TAG = Tag.universal(UniversalTag.BOOLEAN, false);
    private static final Tag NULL_TAG = Tag.universal(UniversalTag.NULL, false);
    private static final Tag INTEGER_TAG = Tag.universal(UniversalTag.INTEGER, false);
    private static final Tag OCTET_STRING_TAG = Tag.universal(UniversalTag.OCTET_STRING, false);
    private static final Tag BIT_STRING_TAG = Tag.universal(UniversalTag.BIT_STRING, false);
    private static final Tag OBJECT_IDENTIFIER_TAG = Tag.universal(UniversalTag.OBJECT_IDENTIFIER, false);
    private static final Tag RELATIVE_OID_TAG = Tag.universal(UniversalTag.RELATIVE_OID, false);
    private static final Tag REAL_TAG = Tag.universal(UniversalTag.REAL, false);

    /** X.690 §11.1: DER encodes TRUE as all ones. */
    private static final int DER_TRUE = 0xFF;

    private BerPrimitive() {
    }

    /**
     * Encodes {@code p} under {@code framing}: IMPLICIT replaces the
     * natural tag, EXPLICIT wraps the natural encoding (X.690 §8.14), and
     * every other framing writes the natural encoding.
     */
    public static void encode(Asn1Primitive p, BerTagging framing, ByteSink out) {
        if (p instanceof Asn1Any any) {
            encodeAny(any, framing, out);
            return;
        }
        switch (framing.resolve()) {
            case BerTagging.Implicit(Tag tag) -> encodeTagged(p, tag, out);
            case BerTagging.Explicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> encodeTagged(p, naturalTag(p), inner));
            case BerTagging.Unsupported(String reason) -> throw new EncodeException("primitive not supported: " + reason);
            default -> encodeTagged(p, naturalTag(p), out);
        }
    }

    /** Decode counterpart of {@link #encode}: reads one TLV into {@code p}. */
    public static void decode(Asn1Primitive p, BerTagging framing, BerReader r) {
        if (p instanceof Asn1Any any) {
            decodeAny(any, framing, r);
            return;
        }
        switch (framing.resolve()) {
            case BerTagging.Implicit(Tag tag) -> decodeTagged(p, tag, r);
            case BerTagging.Explicit(Tag tag) -> {
                int start = r.position();
                Tlv outer = r.readTlv();
                if (!outer.tag().equals(tag)) {
                    throw new DecodeException("expected EXPLICIT tag " + tag + ", got " + outer.tag(), start);
                }
                decodeTagged(p, naturalTag(p), r.nested(outer.value()));
            }
            case BerTagging.Unsupported(String reason) -> throw new DecodeException("primitive not supported: " + reason, r.position());
            default -> decodeTagged(p, naturalTag(p), r);
        }
    }

    /** The builtin's own universal tag (X.680 §8, Table 1). */
    public static Tag naturalTag(Asn1Primitive p) {
        return switch (p) {
            case Asn1Boolean b -> BOOLEAN_TAG;
            case Asn1Null n -> NULL_TAG;
            case Asn1Integer i -> INTEGER_TAG;
            case Asn1UInteger u -> INTEGER_TAG;
            case Asn1OctetString o -> OCTET_STRING_TAG;
            case Asn1BitString b -> BIT_STRING_TAG;
            case Asn1CharString c -> Tag.universal(c.universalTagNumber(), false);
            case Asn1ObjectIdentifier o -> OBJECT_IDENTIFIER_TAG;
            case Asn1RelativeOid r -> RELATIVE_OID_TAG;
            case Asn1Real r -> REAL_TAG;
            default -> throw new EncodeException("no BER form for " + p.xerElementName());
        };
    }

    private static void encodeTagged(Asn1Primitive p, Tag tag, ByteSink out) {
        switch (p) {
            case Asn1Boolean b -> BerWriter.writePrimitive(out, tag, new byte[] {(byte) (b.get() ? DER_TRUE : 0)});
            case Asn1Null n -> BerWriter.writePrimitive(out, tag, new byte[0]);
            case Asn1Integer i -> BerWriter.writePrimitive(out, tag, encodeInteger(i.get()));
            case Asn1UInteger u -> BerWriter.writePrimitive(out, tag, encodeUnsigned(u.get()));
            case Asn1OctetString o -> BerWriter.writePrimitive(out, tag, o.get());
            case Asn1CharString c -> BerWriter.writePrimitive(out, tag, c.octets());
            case Asn1ObjectIdentifier o -> BerWriter.writePrimitive(out, tag, encodeObjectIdentifier(o.get()));
            case Asn1RelativeOid r -> BerWriter.writePrimitive(out, tag, encodeSubidentifiers(r.get(), 0, new byte[r.get().length * 10], 0));
            case Asn1Real r -> BerWriter.writePrimitive(out, tag, BerReal.encode(r));
            // X.690 §8.6.2: the initial octet counts the unused bits of the last octet.
            case Asn1BitString b -> BerWriter.writeTagged(out, tag, c -> {
                c.write(b.unusedBits());
                c.write(b.bytes());
            });
            default -> throw new EncodeException("no BER form for " + p.xerElementName());
        }
    }

    private static void decodeTagged(Asn1Primitive p, Tag tag, BerReader r) {
        int start = r.position();
        Tlv tlv = r.readTlv();
        if (!tlv.tag().equals(tag)) {
            throw new DecodeException("expected tag " + tag + ", got " + tlv.tag(), start);
        }
        ByteSource v = tlv.value();
        switch (p) {
            // X.690 §8.2.2: any non-zero contents octet is TRUE.
            case Asn1Boolean b -> {
                if (v.remaining() != 1) {
                    throw new DecodeException("BOOLEAN: contents must be one octet, got " + v.remaining(), start);
                }
                b.set(v.read("BOOLEAN") != 0);
            }
            // X.690 §8.8.2: no contents octets.
            case Asn1Null n -> {
                if (!v.atEnd()) {
                    throw new DecodeException("NULL: contents must be empty, got " + v.remaining() + " octets", start);
                }
            }
            case Asn1Integer i -> i.set(decodeInteger(v, start));
            case Asn1UInteger u -> u.set(decodeUnsigned(v, start));
            case Asn1OctetString o -> o.set(v.remainingBytes());
            case Asn1CharString c -> c.setOctets(v.remainingBytes());
            case Asn1ObjectIdentifier o -> o.set(decodeObjectIdentifier(v.remainingBytes(), start));
            case Asn1RelativeOid rel -> rel.set(decodeSubidentifiers(v.remainingBytes(), 0, new long[0], start));
            case Asn1Real real -> real.set(BerReal.decode(v.remainingBytes(), start));
            case Asn1BitString b -> {
                if (v.atEnd()) {
                    throw new DecodeException("BIT STRING: contents need the unused-bits octet", start);
                }
                int unused = v.read("BIT STRING");
                if (unused > 7 || (unused != 0 && v.atEnd())) {
                    throw new DecodeException("BIT STRING: " + unused + " unused bits with " + v.remaining() + " octets", start);
                }
                b.set(v.remainingBytes(), unused);
            }
            default -> throw new DecodeException("no BER form for " + p.xerElementName(), start);
        }
    }

    /**
     * INTEGER contents (X.690 §8.3): two's complement, big-endian, in the
     * fewest octets (§8.3.2). Also the contents of ENUMERATED (§8.4).
     */
    public static byte[] encodeInteger(long n) {
        int len = 8;
        while (len > 1) {
            long top9 = n >> (8 * len - 9);
            if (top9 != 0 && top9 != -1) {
                break;
            }
            len--;
        }
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (n >> (8 * (len - 1 - i)));
        }
        return out;
    }

    /**
     * Decode counterpart of {@link #encodeInteger}: one to eight contents
     * octets, sign-extended.
     *
     * @param pos the TLV's position, for the error
     */
    public static long decodeInteger(ByteSource v, int pos) {
        int len = v.remaining();
        if (len == 0) {
            throw new DecodeException("INTEGER: empty contents", pos);
        }
        if (len > 8) {
            throw new DecodeException("INTEGER: " + len + " octets do not fit 64-bit storage", pos);
        }
        long n = (byte) v.read("INTEGER");
        for (int i = 1; i < len; i++) {
            n = (n << 8) | v.read("INTEGER");
        }
        return n;
    }

    /**
     * OBJECT IDENTIFIER contents (X.690 §8.19): the first two arcs share one
     * subidentifier, {@code X*40+Y} (§8.19.4), the rest are one each.
     */
    public static byte[] encodeObjectIdentifier(long[] arcs) {
        if (arcs.length == 0) {
            return new byte[0];
        }
        byte[] out = new byte[arcs.length * 10];
        int n = writeSubidentifier(out, 0, arcs[0] * 40 + (arcs.length > 1 ? arcs[1] : 0));
        return encodeSubidentifiers(arcs, Math.min(2, arcs.length), out, n);
    }

    /**
     * Decode counterpart of {@link #encodeObjectIdentifier}. A first
     * subidentifier below 80 gives X = 0 or 1; from 80 up X is 2 and Y is
     * the remainder (X.690 §8.19.4).
     *
     * @param pos the TLV's position, for the error
     */
    public static long[] decodeObjectIdentifier(byte[] v, int pos) {
        if (v.length == 0) {
            return new long[0];
        }
        long[] firstOut = new long[1];
        int i = readSubidentifier(v, 0, Asn1Arcs.MAX_ARC + 80, firstOut, pos);
        long first = firstOut[0];
        long x = first < 80 ? first / 40 : 2;
        return decodeSubidentifiers(v, i, new long[] {x, first - x * 40}, pos);
    }

    /**
     * Writes {@code arcs[from..]} one subidentifier each (X.690 §8.19.2,
     * §8.20.2) into {@code out} after {@code n} octets already written.
     */
    private static byte[] encodeSubidentifiers(long[] arcs, int from, byte[] out, int n) {
        for (int i = from; i < arcs.length; i++) {
            n = writeSubidentifier(out, n, arcs[i]);
        }
        return Arrays.copyOf(out, n);
    }

    /**
     * Reads subidentifiers from {@code v[i..]}, one arc each, after the
     * arcs in {@code head}.
     */
    private static long[] decodeSubidentifiers(byte[] v, int i, long[] head, int pos) {
        long[] arcs = Arrays.copyOf(head, head.length + v.length);
        int n = head.length;
        long[] arc = new long[1];
        while (i < v.length) {
            i = readSubidentifier(v, i, Asn1Arcs.MAX_ARC, arc, pos);
            arcs[n++] = arc[0];
        }
        return Arrays.copyOf(arcs, n);
    }

    /** Base 128, most significant group first, bit 8 set on all but the last octet (X.690 §8.19.2). */
    private static int writeSubidentifier(byte[] out, int n, long value) {
        int groups = 1;
        while (groups < 10 && (value >>> (7 * groups)) != 0) {
            groups++;
        }
        for (int g = groups - 1; g >= 0; g--) {
            out[n++] = (byte) (((value >>> (7 * g)) & 0x7F) | (g > 0 ? 0x80 : 0));
        }
        return n;
    }

    /**
     * Reads one subidentifier at {@code v[i]} into {@code out[0]}.
     *
     * @return the index after it
     * @throws DecodeException if it is truncated or exceeds {@code max}
     */
    private static int readSubidentifier(byte[] v, int i, long max, long[] out, int pos) {
        long value = 0;
        while (true) {
            if (i >= v.length) {
                throw new DecodeException("truncated subidentifier", pos);
            }
            int b = v[i++] & 0xFF;
            if (value > (max >>> 7)) {
                throw new DecodeException("subidentifier exceeds arc limit " + Asn1Arcs.MAX_ARC, pos);
            }
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                if (value > max) {
                    throw new DecodeException("subidentifier exceeds arc limit " + Asn1Arcs.MAX_ARC, pos);
                }
                out[0] = value;
                return i;
            }
        }
    }

    /**
     * ANY replays its captured encoding: as is, or inside an EXPLICIT tag.
     * An IMPLICIT tag is not allowed on an untagged open type (X.680
     * tagged types, §30.8 of the 2002 edition), so it is
     * an error.
     */
    private static void encodeAny(Asn1Any any, BerTagging framing, ByteSink out) {
        switch (framing.resolve()) {
            case BerTagging.Explicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> inner.write(any.get()));
            case BerTagging.Implicit(Tag tag) -> throw new EncodeException("ANY cannot be IMPLICIT tagged");
            case BerTagging.Unsupported(String reason) -> throw new EncodeException("ANY not supported: " + reason);
            default -> out.write(any.get());
        }
    }

    /**
     * Decode counterpart of {@link #encodeAny}: captures every remaining
     * octet of the reader, or of the EXPLICIT tag's contents, verbatim.
     */
    private static void decodeAny(Asn1Any any, BerTagging framing, BerReader r) {
        switch (framing.resolve()) {
            case BerTagging.Explicit(Tag tag) -> {
                int start = r.position();
                Tlv outer = r.readTlv();
                if (!outer.tag().equals(tag)) {
                    throw new DecodeException("expected EXPLICIT tag " + tag + ", got " + outer.tag(), start);
                }
                any.set(outer.value().remainingBytes());
            }
            case BerTagging.Implicit(Tag tag) -> throw new DecodeException("ANY cannot be IMPLICIT tagged", r.position());
            case BerTagging.Unsupported(String reason) -> throw new DecodeException("ANY not supported: " + reason, r.position());
            default -> {
                ByteSource src = r.source();
                any.set(src.remainingBytes());
                src.skip(src.remaining(), "ANY");
            }
        }
    }

    /**
     * INTEGER contents (X.690 §8.3) of a value read as unsigned: the fewest
     * octets, with a leading 00 when the top bit is set.
     */
    public static byte[] encodeUnsigned(long n) {
        if (n >= 0) {
            return encodeInteger(n);
        }
        byte[] out = new byte[9];
        for (int i = 0; i < 8; i++) {
            out[1 + i] = (byte) (n >>> (8 * (7 - i)));
        }
        return out;
    }

    /**
     * Decode counterpart of {@link #encodeUnsigned}: up to eight octets of a
     * non-negative value, or nine whose first is 00. A negative value is an
     * error.
     *
     * @param pos the TLV's position, for the error
     */
    public static long decodeUnsigned(ByteSource v, int pos) {
        int len = v.remaining();
        if (len == 0) {
            throw new DecodeException("INTEGER: empty contents", pos);
        }
        boolean padded = len == 9 && v.peek() == 0;
        if (padded) {
            v.read("INTEGER");
            len--;
        }
        if (len > 8) {
            throw new DecodeException("INTEGER: " + len + " octets do not fit unsigned 64-bit storage", pos);
        }
        if (!padded && (v.peek() & 0x80) != 0) {
            throw new DecodeException("INTEGER: negative value in unsigned storage", pos);
        }
        long n = 0;
        for (int i = 0; i < len; i++) {
            n = (n << 8) | v.read("INTEGER");
        }
        return n;
    }
}
