package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.ByteSource;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;

/**
 * BER for builtin leaf values: one switch over the builtin wrappers for the
 * natural tag and the contents octets, and the member's own framing
 * (X.690 §8.14) applied around them.
 */
public final class BerPrimitive {
    private static final Tag BOOLEAN_TAG = Tag.universal(UniversalTag.BOOLEAN, false);
    private static final Tag NULL_TAG = Tag.universal(UniversalTag.NULL, false);

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
            default -> throw new EncodeException("no BER form for " + p.xerElementName());
        };
    }

    private static void encodeTagged(Asn1Primitive p, Tag tag, ByteSink out) {
        switch (p) {
            case Asn1Boolean b -> BerWriter.writePrimitive(out, tag, new byte[] {(byte) (b.get() ? DER_TRUE : 0)});
            case Asn1Null n -> BerWriter.writePrimitive(out, tag, new byte[0]);
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
            default -> throw new DecodeException("no BER form for " + p.xerElementName(), start);
        }
    }
}
