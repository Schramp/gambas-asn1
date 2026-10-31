package io.github.schramp.gambasasn1.wire.xer;

import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.ber.UniversalTag;
import io.github.schramp.gambasasn1.wire.spec.AltMeta;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.Asn1SeqOf;
import io.github.schramp.gambasasn1.wire.spec.EnumEntry;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.EnumSpec;
import io.github.schramp.gambasasn1.wire.spec.MemberMeta;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.types.Asn1Boolean;
import io.github.schramp.gambasasn1.wire.types.Asn1Null;
import java.util.List;

/**
 * The XER walker (X.693, BASIC-XER): one switch over {@link MemberRef},
 * driven by the generated tables. Every element is written as a complete
 * line, {@code <name>…</name>\n}, with its inner lines four spaces per
 * level deeper, the layout of asn1c and the C++ runtime; a document is the
 * value's own element.
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

    /**
     * Writes {@code m} as the complete line {@code <name>…</name>\n}; the
     * caller writes the indent before it. A constructed value's inner lines
     * are indented from {@code depth} (X.693 §8.3, in asn1c's layout).
     */
    static void encodeElement(String name, MemberRef m, XerWriter w, int depth) {
        switch (m) {
            case MemberRef.Absent a -> {
            }
            case MemberRef.Unsupported(String reason) -> throw new EncodeException(reason);
            case MemberRef.Primitive(var p) -> {
                w.open(name);
                XerPrimitive.encode(p, w, depth);
                w.close(name).ascii("\n");
            }
            case MemberRef.Enumerated(EnumSlot slot, EnumSpec spec) -> {
                w.open(name);
                encodeEnumerated(slot, spec, w);
                w.close(name).ascii("\n");
            }
            case MemberRef.Composite(Asn1Seq s) -> encodeSequence(name, s, w, depth);
            case MemberRef.Choice(Asn1Choice c) -> {
                w.open(name);
                encodeChoiceContent(c, w, depth);
                w.indent(depth).close(name).ascii("\n");
            }
            case MemberRef.SeqOf(Asn1SeqOf q) -> encodeSeqOf(name, q, w, depth);
            default -> throw new EncodeException("XER encode of " + m.getClass().getSimpleName() + " is not supported yet");
        }
    }

    /** One line per present member, each named by its identifier (X.693 §8.3.4); an empty element when none is. */
    private static void encodeSequence(String name, Asn1Seq s, XerWriter w, int depth) {
        List<MemberMeta> members = s.spec().members();
        w.open(name);
        boolean any = false;
        for (int i = 0; i < members.size(); i++) {
            MemberRef m = s.getMember(i);
            if (m instanceof MemberRef.Absent) {
                continue;
            }
            if (!any) {
                w.ascii("\n");
                any = true;
            }
            w.indent(depth + 1);
            encodeElement(members.get(i).name(), m, w, depth + 1);
        }
        if (any) {
            w.indent(depth);
        }
        w.close(name).ascii("\n");
    }

    /**
     * The selected alternative as the line after the CHOICE's own tag, one
     * level deeper (X.693 §8.3.6). It starts with the newline and ends with
     * the alternative's own one.
     */
    private static void encodeChoiceContent(Asn1Choice c, XerWriter w, int depth) {
        int i = c.activeIndex();
        if (i < 0) {
            throw new EncodeException("CHOICE " + c.spec().name() + ": no alternative selected");
        }
        w.ascii("\n").indent(depth + 1);
        encodeElement(c.spec().alternatives().get(i).name(), c.getActive(), w, depth + 1);
    }

    /**
     * Each element as its own line, named by the element type
     * (XMLDelimitedItemList, X.693 §8.3.5), or the bare values of a
     * BOOLEAN, ENUMERATED or NULL element type (XMLValueList, X.680 §25.5).
     * A CHOICE element is its alternative's line alone, one level deeper,
     * with an empty line between two of them, as asn1c writes it.
     */
    private static void encodeSeqOf(String name, Asn1SeqOf q, XerWriter w, int depth) {
        int n = q.size();
        w.open(name);
        if (n == 0) {
            w.close(name).ascii("\n");
            return;
        }
        if (isValueList(q.get(0))) {
            encodeValueList(q, w, depth);
        } else {
            String override = q.elemXerName();
            for (int i = 0; i < n; i++) {
                MemberRef el = q.get(i);
                if (el instanceof MemberRef.Choice(Asn1Choice c)) {
                    encodeChoiceContent(c, w, depth + 1);
                    continue;
                }
                if (i == 0) {
                    w.ascii("\n");
                }
                w.indent(depth + 1);
                encodeElement(override != null ? override : elementName(q, i, el), el, w, depth + 1);
            }
        }
        w.indent(depth).close(name).ascii("\n");
    }

    /** An element's own name: its type's name, or {@code SEQUENCE_OF}/{@code SET_OF} for an inline collection. */
    private static String elementName(Asn1SeqOf q, int i, MemberRef el) {
        return switch (el) {
            case MemberRef.Composite(Asn1Seq s) -> s.spec().name();
            case MemberRef.SeqOf(Asn1SeqOf inner) -> inner.ownXerName();
            default -> q.elemNaturalXerName(i);
        };
    }

    private static boolean isValueList(MemberRef el) {
        return el instanceof MemberRef.Enumerated
                || el instanceof MemberRef.Primitive(Asn1Boolean b)
                || el instanceof MemberRef.Primitive(Asn1Null n);
    }

    /**
     * SEQUENCE OF values inline after the opening tag, SET OF and NULL
     * values each on a new line, as asn1c lays them out. A NULL value is
     * the empty element of its type name (X.680 §25.4).
     */
    private static void encodeValueList(Asn1SeqOf q, XerWriter w, int depth) {
        boolean setOf = q.naturalTag().number() == UniversalTag.SET;
        for (int i = 0; i < q.size(); i++) {
            MemberRef el = q.get(i);
            boolean isNull = el instanceof MemberRef.Primitive(Asn1Null n);
            if (isNull || setOf) {
                w.ascii("\n").indent(depth + 2);
            }
            switch (el) {
                case MemberRef.Enumerated(EnumSlot slot, EnumSpec spec) -> encodeEnumerated(slot, spec, w);
                case MemberRef.Primitive(Asn1Boolean b) -> w.empty(b.get() ? "true" : "false");
                default -> w.empty(q.elemNaturalXerName(i));
            }
        }
    }

    /** Decode counterpart of {@link #encodeElement}: consumes element {@code name}. */
    static void decodeElement(String name, MemberRef m, XerReader r) {
        if (!(m instanceof MemberRef.Composite || m instanceof MemberRef.Choice || m instanceof MemberRef.SeqOf)) {
            decodeElementLevel(name, m, r);
            return;
        }
        r.enterLevel();
        try {
            decodeElementLevel(name, m, r);
        } finally {
            r.leaveLevel();
        }
    }

    private static void decodeElementLevel(String name, MemberRef m, XerReader r) {
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
            case MemberRef.Composite(Asn1Seq s) -> {
                boolean empty = r.consumeOpenOrEmptyTag(name);
                decodeSequenceContent(s, r, empty);
                if (!empty) {
                    r.consumeCloseTag(name);
                }
            }
            case MemberRef.Choice(Asn1Choice c) -> {
                r.consumeOpenTag(name);
                decodeChoiceContent(c, r);
                r.consumeCloseTag(name);
            }
            case MemberRef.SeqOf(Asn1SeqOf q) -> {
                q.clear();
                if (!r.consumeOpenOrEmptyTag(name)) {
                    decodeSeqOfContent(q, r);
                    r.consumeCloseTag(name);
                }
            }
            default -> throw new DecodeException("XER decode of " + m.getClass().getSimpleName() + " is not supported yet", at);
        }
    }

    /**
     * Members in table order; an OPTIONAL or DEFAULT member is present when
     * the next element is named by it, and otherwise set to its DEFAULT or
     * to absent.
     */
    private static void decodeSequenceContent(Asn1Seq s, XerReader r, boolean empty) {
        List<MemberMeta> members = s.spec().members();
        for (int i = 0; i < members.size(); i++) {
            MemberMeta meta = members.get(i);
            if (meta.optional()) {
                XerReader.TagInfo peek = empty ? XerReader.TagInfo.NONE : r.peekTag();
                if (!peek.name().equals(meta.name()) || peek.closing()) {
                    s.setDefault(i);
                    continue;
                }
            } else if (empty) {
                throw new DecodeException("XER " + s.spec().name() + ": missing member " + meta.name(), r.position());
            }
            decodeElement(meta.name(), s.presentMember(i), r);
        }
    }

    /** The alternative the next element names (X.693 §8.3.6). */
    private static void decodeChoiceContent(Asn1Choice c, XerReader r) {
        XerReader.TagInfo peek = r.peekTag();
        List<AltMeta> alts = c.spec().alternatives();
        for (int i = 0; i < alts.size(); i++) {
            if (alts.get(i).name().equals(peek.name()) && !peek.closing()) {
                decodeElement(peek.name(), c.select(i), r);
                return;
            }
        }
        throw new DecodeException("XER CHOICE " + c.spec().name() + ": unknown alternative <" + peek.name() + ">", r.position());
    }

    /** Elements up to the collection's closing tag, read as {@link #encodeSeqOf} writes them. */
    private static void decodeSeqOfContent(Asn1SeqOf q, XerReader r) {
        String override = q.elemXerName();
        while (true) {
            XerReader.TagInfo peek = r.peekTag();
            if (peek.closing()) {
                return;
            }
            if (peek.name().isEmpty()) {
                throw new DecodeException("XER SEQUENCE OF " + q.ownXerName() + ": expected an element", r.position());
            }
            MemberRef el = q.addDefault();
            switch (el) {
                case MemberRef.Enumerated(EnumSlot slot, EnumSpec spec) -> decodeEnumerated(slot, spec, r);
                case MemberRef.Primitive(Asn1Boolean b) when peek.name().equals("true") || peek.name().equals("false") -> {
                    r.consumeTag();
                    b.set(peek.name().equals("true"));
                }
                case MemberRef.Choice(Asn1Choice c) -> {
                    r.enterLevel();
                    try {
                        decodeChoiceContent(c, r);
                    } finally {
                        r.leaveLevel();
                    }
                }
                default -> decodeElement(override != null ? override : elementName(q, q.size() - 1, el), el, r);
            }
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
