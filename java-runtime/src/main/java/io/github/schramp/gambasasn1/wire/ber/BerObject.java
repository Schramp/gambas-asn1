package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AltMeta;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.BerDispatch;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.spec.ChoiceSpec;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import java.util.List;

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
            case MemberRef.Choice(Asn1Choice c) -> {
                switch (framing.resolve()) {
                    case BerTagging.Explicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> encodeChoice(c, inner));
                    case BerTagging.Implicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> encodeChoiceAlternative(c, inner));
                    case BerTagging.Unsupported(String reason) -> throw new EncodeException(reason);
                    default -> encodeChoice(c, out);
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
            case MemberRef.Choice(Asn1Choice c) -> {
                switch (framing.resolve()) {
                    case BerTagging.Explicit(Tag tag) -> {
                        BerReader inner = enter(r, tag);
                        decodeChoice(c, inner);
                        expectEnd(inner, tag);
                    }
                    case BerTagging.Implicit(Tag tag) -> {
                        BerReader inner = enter(r, tag);
                        decodeChoiceAlternative(c, inner);
                        expectEnd(inner, tag);
                    }
                    case BerTagging.Unsupported(String reason) -> throw new DecodeException(reason, r.position());
                    default -> decodeChoice(c, r);
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

    /**
     * A CHOICE value: its own tag, when the type has one, wraps the selected
     * alternative (X.680 §31.2.7: a tagged CHOICE is always EXPLICIT).
     */
    private static void encodeChoice(Asn1Choice c, ByteSink out) {
        Tag own = c.spec().ownTag();
        if (own != null) {
            BerWriter.writeTagged(out, own, inner -> encodeChoiceAlternative(c, inner));
        } else {
            encodeChoiceAlternative(c, out);
        }
    }

    /**
     * The selected alternative under its row's framing (X.690 §8.13), or an
     * unknown extension alternative replayed as it was read (X.680 §6).
     */
    private static void encodeChoiceAlternative(Asn1Choice c, ByteSink out) {
        int i = c.activeIndex();
        if (i >= 0) {
            encodeMemberRef(c.getActive(), c.spec().alternatives().get(i).ber(), out);
            return;
        }
        Asn1Choice.UnknownExtension ext = c.unknownExtension();
        if (ext == null) {
            throw new EncodeException("CHOICE " + c.spec().name() + ": no alternative selected");
        }
        BerWriter.writePrimitive(out, ext.tag(), ext.bytes());
    }

    /** Decode counterpart of {@link #encodeChoice}. */
    private static void decodeChoice(Asn1Choice c, BerReader r) {
        Tag own = c.spec().ownTag();
        if (own == null) {
            decodeChoiceAlternative(c, r);
            return;
        }
        BerReader inner = enter(r, own);
        decodeChoiceAlternative(c, inner);
        expectEnd(inner, own);
    }

    /**
     * Selects the alternative whose tag the next TLV carries, through the
     * table's sorted {@code berTags}, and decodes it in place. An extensible
     * CHOICE keeps a TLV no alternative matches as an unknown extension;
     * otherwise that TLV is an error.
     */
    private static void decodeChoiceAlternative(Asn1Choice c, BerReader r) {
        ChoiceSpec spec = c.spec();
        int start = r.position();
        Tag tag = r.peekTag();
        if (tag == null) {
            throw new DecodeException("CHOICE " + spec.name() + ": no alternative present", start);
        }
        int alt = dispatch(spec.berTags(), tag);
        if (alt >= 0) {
            AltMeta row = spec.alternatives().get(alt);
            decodeMemberRef(c.select(alt), row.ber(), r);
            return;
        }
        if (spec.extAt() < 0) {
            throw new DecodeException("CHOICE " + spec.name() + ": no alternative has tag " + tag, start);
        }
        Tlv tlv = r.readTlv();
        c.setUnknownExtension(new Asn1Choice.UnknownExtension(tlv.tag(), tlv.value().remainingBytes()));
    }

    /** The alternative whose dispatch entry has {@code tag}'s class and number, or -1. */
    private static int dispatch(List<BerDispatch> tags, Tag tag) {
        int lo = 0;
        int hi = tags.size() - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            int cmp = Tag.IDENTIFIER_ORDER.compare(tags.get(mid).tag(), tag);
            if (cmp == 0) {
                return tags.get(mid).alt();
            }
            if (cmp < 0) {
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return -1;
    }

    /** Reads one TLV that must carry {@code tag} and returns a reader over its contents. */
    private static BerReader enter(BerReader r, Tag tag) {
        int start = r.position();
        Tlv tlv = r.readTlv();
        if (!tlv.tag().matchesIdentifier(tag)) {
            throw new DecodeException("expected tag " + tag + ", got " + tlv.tag(), start);
        }
        return new BerReader(tlv.value());
    }

    /** A tag's contents hold exactly one encoding (X.690 §8.14.2). */
    private static void expectEnd(BerReader inner, Tag tag) {
        if (!inner.atEnd()) {
            throw new DecodeException("trailing octets inside tag " + tag, inner.position());
        }
    }
}
