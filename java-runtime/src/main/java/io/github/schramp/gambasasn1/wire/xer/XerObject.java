package io.github.schramp.gambasasn1.wire.xer;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.EnumEntry;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.EnumSpec;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;

/**
 * The XER walker (X.693, BASIC-XER): one switch over {@link MemberRef},
 * driven by the generated tables. A document is the value's own element
 * followed by a newline, as asn1c writes it.
 */
public final class XerObject {
    private XerObject() {
    }

    /** Encodes {@code v} as a BASIC-XER document. */
    public static byte[] encode(AsMemberRef v) {
        return encode(v, null);
    }

    /** {@link #encode(AsMemberRef)} with contained-value settings; null for the defaults. */
    public static byte[] encode(AsMemberRef v, ContainedOptions opts) {
        XerWriter w = new XerWriter();
        encodeElement(v.ownElementXerName(), v.asMemberRef(), w, 0);
        w.ascii("\n");
        return w.toByteArray();
    }

    /** Decodes a BASIC-XER document into {@code v}. */
    public static void decode(AsMemberRef v, byte[] data) {
        decode(v, new XerReader(data));
    }

    /**
     * {@link #decode(AsMemberRef, byte[])} that also accepts the asn1c
     * extensions (text BOOLEAN, hex BIT STRING).
     */
    public static void decodeLenient(AsMemberRef v, byte[] data) {
        decode(v, new XerReader(data, true));
    }

    /** Decodes one document from {@code r} into {@code v}. */
    public static void decode(AsMemberRef v, XerReader r) {
        r.skipWhitespace();
        decodeElement(v.ownElementXerName(), v.asMemberRef(), r);
    }

    /** Writes {@code m} as element {@code name} at nesting {@code depth} (X.693 §8.3). */
    static void encodeElement(String name, MemberRef m, XerWriter w, int depth) {
        switch (m) {
            case MemberRef.Absent a -> {
            }
            case MemberRef.Unsupported(String reason) -> throw new EncodeException(reason);
            case MemberRef.Primitive(var p) -> {
                w.open(name);
                XerPrimitive.encode(p, w, depth);
                w.close(name);
            }
            case MemberRef.Enumerated(EnumSlot slot, EnumSpec spec) -> {
                w.open(name);
                encodeEnumerated(slot, spec, w);
                w.close(name);
            }
            default -> throw new EncodeException("XER encode of " + m.getClass().getSimpleName() + " is not supported yet");
        }
    }

    /** Decode counterpart of {@link #encodeElement}: consumes element {@code name}. */
    static void decodeElement(String name, MemberRef m, XerReader r) {
        int at = r.position();
        switch (m) {
            case MemberRef.Unsupported(String reason) -> throw new DecodeException(reason, at);
            case MemberRef.Primitive(var p) -> {
                if (r.consumeOpenOrEmptyTag(name)) {
                    XerPrimitive.decode(p, new XerReader(new byte[0], r.lenient()));
                    return;
                }
                XerPrimitive.decode(p, r);
                r.skipWhitespace();
                r.consumeCloseTag(name);
            }
            case MemberRef.Enumerated(EnumSlot slot, EnumSpec spec) -> {
                r.consumeOpenTag(name);
                decodeEnumerated(slot, spec, r);
                r.skipWhitespace();
                r.consumeCloseTag(name);
            }
            default -> throw new DecodeException("XER decode of " + m.getClass().getSimpleName() + " is not supported yet", at);
        }
    }

    /** The item's identifier as an empty element; a value outside the table as its number. */
    private static void encodeEnumerated(EnumSlot slot, EnumSpec spec, XerWriter w) {
        long v = slot.enumGet();
        for (EnumEntry e : spec.entries()) {
            if (e.value() == v) {
                w.empty(e.name());
                return;
            }
        }
        w.ascii(Long.toString(v));
    }

    /** @see "X.693 §8.3.7 — ENUMERATED as an empty element named by its identifier" */
    private static void decodeEnumerated(EnumSlot slot, EnumSpec spec, XerReader r) {
        int at = r.position();
        r.skipWhitespace();
        XerReader.TagInfo peek = r.peekTag();
        if (peek.name().isEmpty() || peek.closing()) {
            String text = r.readTrimmedText();
            long v;
            try {
                v = Long.parseLong(text);
            } catch (NumberFormatException e) {
                throw new DecodeException("XER ENUMERATED " + spec.name() + ": invalid value: " + text, at);
            }
            if (!slot.enumSet(v)) {
                throw new DecodeException("XER ENUMERATED " + spec.name() + ": unknown value " + v, at);
            }
            return;
        }
        XerReader.TagInfo t = r.consumeTag();
        for (EnumEntry e : spec.entries()) {
            if (e.name().equals(t.name())) {
                if (!t.selfClosing()) {
                    r.consumeCloseTag(t.name());
                }
                slot.enumSet(e.value());
                return;
            }
        }
        throw new DecodeException("XER ENUMERATED " + spec.name() + ": unknown identifier " + t.name(), at);
    }
}
