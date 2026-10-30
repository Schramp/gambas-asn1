package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.ByteSource;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1CharString;
import io.github.schramp.gambasasn1.wire.types.Asn1Integer;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;

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
        switch (framing.resolve()) {
            case BerTagging.Implicit(Tag tag) -> encodeTagged(p, tag, out);
            case BerTagging.Explicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> encodeTagged(p, naturalTag(p), inner));
            case BerTagging.Unsupported(String reason) -> throw new EncodeException("primitive not supported: " + reason);
            default -> encodeTagged(p, naturalTag(p), out);
        }
    }

    /** Decode counterpart of {@link #encode}: reads one TLV into {@code p}. */
    public static void decode(Asn1Primitive p, BerTagging framing, BerReader r) {
        switch (framing.resolve()) {
            case BerTagging.Implicit(Tag tag) -> decodeTagged(p, tag, r);
            case BerTagging.Explicit(Tag tag) -> {
                int start = r.position();
                Tlv outer = r.readTlv();
                if (!outer.tag().equals(tag)) {
                    throw new DecodeException("expected EXPLICIT tag " + tag + ", got " + outer.tag(), start);
                }
                decodeTagged(p, naturalTag(p), new BerReader(outer.value()));
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
            case Asn1OctetString o -> OCTET_STRING_TAG;
            case Asn1BitString b -> BIT_STRING_TAG;
            case Asn1CharString c -> Tag.universal(c.universalTagNumber(), false);
            default -> throw new EncodeException("no BER form for " + p.xerElementName());
        };
    }

    private static void encodeTagged(Asn1Primitive p, Tag tag, ByteSink out) {
        switch (p) {
            case Asn1Boolean b -> BerWriter.writePrimitive(out, tag, new byte[] {(byte) (b.get() ? DER_TRUE : 0)});
            case Asn1Null n -> BerWriter.writePrimitive(out, tag, new byte[0]);
            case Asn1Integer i -> BerWriter.writePrimitive(out, tag, encodeInteger(i.get()));
            case Asn1OctetString o -> BerWriter.writePrimitive(out, tag, o.get());
            case Asn1CharString c -> BerWriter.writePrimitive(out, tag, c.octets());
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
            case Asn1OctetString o -> o.set(v.remainingBytes());
            case Asn1CharString c -> c.setOctets(v.remainingBytes());
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
}
