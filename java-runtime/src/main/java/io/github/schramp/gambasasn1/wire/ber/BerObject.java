package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;

/**
 * The BER walker: one switch over {@link MemberRef}, driven by the
 * generated tables. Generated types carry no codec code; this class encodes
 * and decodes every one of them.
 */
public final class BerObject {
    private static final Tag ENUMERATED_TAG = Tag.universal(UniversalTag.ENUMERATED, false);

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
            case MemberRef.Enumerated(EnumSlot slot, var spec) -> {
                byte[] content = BerPrimitive.encodeInteger(slot.enumGet());
                switch (framing.resolve()) {
                    case BerTagging.Implicit(Tag tag) -> BerWriter.writePrimitive(out, tag, content);
                    case BerTagging.Explicit(Tag tag) ->
                        BerWriter.writeTagged(out, tag, inner -> BerWriter.writePrimitive(inner, ENUMERATED_TAG, content));
                    case BerTagging.Unsupported(String reason) -> throw new EncodeException(reason);
                    default -> BerWriter.writePrimitive(out, ENUMERATED_TAG, content);
                }
            }
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
            case MemberRef.Enumerated(EnumSlot slot, var spec) -> {
                switch (framing.resolve()) {
                    case BerTagging.Implicit(Tag tag) -> decodeEnumerated(slot, tag, r);
                    case BerTagging.Explicit(Tag tag) -> {
                        int start = r.position();
                        Tlv outer = r.readTlv();
                        if (!outer.tag().equals(tag)) {
                            throw new DecodeException("expected EXPLICIT tag " + tag + ", got " + outer.tag(), start);
                        }
                        decodeEnumerated(slot, ENUMERATED_TAG, new BerReader(outer.value()));
                    }
                    case BerTagging.Unsupported(String reason) -> throw new DecodeException(reason, r.position());
                    default -> decodeEnumerated(slot, ENUMERATED_TAG, r);
                }
            }
            default -> throw new DecodeException("BER decode of " + m.getClass().getSimpleName() + " is not supported yet", r.position());
        }
    }

    /**
     * One ENUMERATED TLV under {@code tag} into {@code slot} (X.690 §8.4);
     * a value that is not one of the type's items is an error.
     */
    private static void decodeEnumerated(EnumSlot slot, Tag tag, BerReader r) {
        int start = r.position();
        Tlv tlv = r.readTlv();
        if (!tlv.tag().equals(tag)) {
            throw new DecodeException("expected tag " + tag + ", got " + tlv.tag(), start);
        }
        long v = BerPrimitive.decodeInteger(tlv.value(), start);
        if (!slot.enumSet(v)) {
            throw new DecodeException("invalid ENUMERATED value: " + v, start);
        }
    }
}
