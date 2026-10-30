package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;

/**
 * The BER walker: one switch over {@link MemberRef}, driven by the
 * generated tables. Generated types carry no codec code; this class encodes
 * and decodes every one of them.
 */
public final class BerObject {
    private BerObject() {
    }

    /** Encodes {@code v} with its type's own framing. */
    public static byte[] encode(AsMemberRef v) {
        ByteSink out = new ByteSink();
        encodeMemberRef(v.asMemberRef(), v.berFraming(), out);
        return out.toByteArray();
    }

    /**
     * Decodes the first value in {@code data} into {@code v}, with its
     * type's own framing.
     */
    public static void decode(AsMemberRef v, byte[] data) {
        decode(v, new BerReader(data));
    }

    /**
     * Decodes one value from {@code r} into {@code v}; the reader is left
     * after it, so records can be read back to back.
     */
    public static void decode(AsMemberRef v, BerReader r) {
        decodeMemberRef(v.asMemberRef(), v.berFraming(), r);
    }

    /** Encodes one member, alternative or element under its row's framing (X.690 §8.14). */
    public static void encodeMemberRef(MemberRef m, BerTagging framing, ByteSink out) {
        switch (m) {
            case MemberRef.Absent a -> {
            }
            case MemberRef.Unsupported(String reason) -> throw new EncodeException(reason);
            case MemberRef.Primitive(var p) -> BerPrimitive.encode(p, framing, out);
            default -> throw new EncodeException("BER encode of " + m.getClass().getSimpleName() + " is not supported yet");
        }
    }

    /** Decode counterpart of {@link #encodeMemberRef}. */
    public static void decodeMemberRef(MemberRef m, BerTagging framing, BerReader r) {
        switch (m) {
            case MemberRef.Absent a -> {
            }
            case MemberRef.Unsupported(String reason) -> throw new DecodeException(reason, r.position());
            case MemberRef.Primitive(var p) -> BerPrimitive.decode(p, framing, r);
            default -> throw new DecodeException("BER decode of " + m.getClass().getSimpleName() + " is not supported yet", r.position());
        }
    }
}
