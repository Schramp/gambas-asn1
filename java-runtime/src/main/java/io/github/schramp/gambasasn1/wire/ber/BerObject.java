package io.github.schramp.gambasasn1.wire.ber;

import io.github.schramp.gambasasn1.wire.DecodeOptions;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.containing.ContainedValues;
import io.github.schramp.gambasasn1.wire.io.ByteSink;
import io.github.schramp.gambasasn1.wire.io.ByteSource;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AltMeta;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.Asn1Contained;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.Asn1SeqOf;
import io.github.schramp.gambasasn1.wire.spec.BerDispatch;
import io.github.schramp.gambasasn1.wire.spec.BerTagging;
import io.github.schramp.gambasasn1.wire.spec.ChoiceSpec;
import io.github.schramp.gambasasn1.wire.spec.ConstraintCheck;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.spec.ContainedEncoding;
import io.github.schramp.gambasasn1.wire.spec.ContainedSpec;
import io.github.schramp.gambasasn1.wire.spec.Decoded;
import io.github.schramp.gambasasn1.wire.spec.EnumSlot;
import io.github.schramp.gambasasn1.wire.spec.MemberMeta;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.spec.Positions;
import io.github.schramp.gambasasn1.wire.spec.SequenceSpec;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import java.util.ArrayList;
import java.util.Arrays;
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
        return encode(v, null);
    }

    /** {@link #encode(AsMemberRef)} with contained-value settings; null for the defaults. */
    public static byte[] encode(AsMemberRef v, ContainedOptions opts) {
        ByteSink out = new ByteSink();
        encodeMemberRef(v.asMemberRef(), v.berFraming(), out, opts);
        return out.toByteArray();
    }

    /**
     * Decodes the first value in {@code data} into {@code v}, with its
     * type's own framing.
     */
    public static void decode(AsMemberRef v, byte[] data) {
        decode(v, new BerReader(data));
    }

    /** {@link #decode(AsMemberRef, byte[])} with contained-value settings; null for the defaults. */
    public static void decode(AsMemberRef v, byte[] data, ContainedOptions opts) {
        decode(v, new BerReader(data).withContained(opts));
    }

    /** {@link #decode(AsMemberRef, byte[])} under the decoder settings {@code opts}; null for the defaults. */
    public static void decode(AsMemberRef v, byte[] data, DecodeOptions opts) {
        decode(v, new BerReader(data).withOptions(opts));
    }

    /**
     * Decodes one value from {@code r} into {@code v}, under the reader's
     * {@link DecodeOptions}; the reader is left after it, so records can
     * be read back to back.
     */
    public static void decode(AsMemberRef v, BerReader r) {
        DecodeOptions o = r.options();
        MemberRef m = v.asMemberRef();
        if (o.plain()) {
            decodeMemberRef(m, v.berFraming(), r);
            return;
        }
        trace(o, r, typeName(m), m);
        try {
            decodeChecked(m, v.berFraming(), v instanceof Asn1Pdu p ? p.pduConstraints() : Constraints.UNCONSTRAINED,
                    o.checkConstraints(), r);
        } catch (DecodeException e) {
            if (!o.richErrors()) {
                throw e;
            }
            throw e.within(typeName(m)).showing(r.source().octetsAt(e.position(), DecodeException.CONTEXT_OCTETS));
        }
    }

    /** The ASN.1 name of {@code m}'s type, for an error path. */
    private static String typeName(MemberRef m) {
        return switch (m) {
            case MemberRef.Composite(var s) -> s.spec().name();
            case MemberRef.Choice(var c) -> c.spec().name();
            case MemberRef.Primitive(var p) -> p.xerElementName();
            case MemberRef.SeqOf(var q) -> q.ownXerName();
            case MemberRef.Enumerated(var e, var spec) -> spec.name();
            default -> m.getClass().getSimpleName();
        };
    }

    /**
     * {@link #decodeMemberRef}, then, when {@code check} is set, a check of
     * the value against {@code c}; a violation is a {@link DecodeException}
     * at the value's first octet.
     */
    private static void decodeChecked(MemberRef m, BerTagging framing, Constraints c, boolean check, BerReader r) {
        int start = r.position();
        decodeMemberRef(m, framing, r);
        if (check) {
            String why = ConstraintCheck.violation(m, c);
            if (why != null) {
                throw new DecodeException("constraint violated: " + why, start);
            }
        }
    }

    /**
     * A member, alternative or element decoded under settings other than
     * the defaults: checked against {@code c} when constraints are
     * checked, and with {@code segment} added to the path of an error when
     * errors are rich.
     */
    private static void decodePart(MemberRef m, BerTagging framing, Constraints c, String segment, BerReader r) {
        DecodeOptions o = r.options();
        trace(o, r, segment, m);
        try {
            decodeChecked(m, framing, c, o.checkConstraints(), r);
        } catch (DecodeException e) {
            throw o.richErrors() ? e.within(segment) : e;
        }
    }

    /** A trace line for {@code m}, about to be decoded as {@code segment}, when tracing is on. */
    private static void trace(DecodeOptions o, BerReader r, String segment, MemberRef m) {
        if (o.trace() != null) {
            o.trace().accept("BER byte " + r.absoluteBit(r.position()) / 8 + " " + segment + " " + typeName(m));
        }
    }

    /**
     * {@link #decode(AsMemberRef, byte[], DecodeOptions)} that also records
     * where every decoded node starts. {@code opts} may be null.
     */
    public static Decoded decodeWithPositions(AsMemberRef v, byte[] data, DecodeOptions opts) {
        return decodeWithPositions(v, new BerReader(data).withOptions(opts));
    }

    /**
     * {@link #decode(AsMemberRef, BerReader)} that also records where every
     * decoded node starts, in bits from the reader's position at the call;
     * records read back to back each get their own positions. The reader is
     * left after the value.
     */
    public static Decoded decodeWithPositions(AsMemberRef v, BerReader r) {
        Positions p = Positions.recording();
        Positions before = r.positions();
        int start = r.position();
        r.withPositions(p);
        try {
            decode(v, r);
        } finally {
            r.withPositions(before);
        }
        return new Decoded(r.position() - start, p.withBase(-r.absoluteBit(start)));
    }

    /** Encodes one member, alternative or element under its row's framing (X.690 §8.14). */
    public static void encodeMemberRef(MemberRef m, BerTagging framing, ByteSink out) {
        encodeMemberRef(m, framing, out, null);
    }

    /**
     * {@link #encodeMemberRef(MemberRef, BerTagging, ByteSink)} with the
     * contained-value settings {@code opts} (null for the defaults), used when
     * a modified contained value is re-encoded.
     */
    public static void encodeMemberRef(MemberRef m, BerTagging framing, ByteSink out, ContainedOptions opts) {
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
            case MemberRef.Composite(Asn1Seq s) -> {
                switch (framing.resolve()) {
                    case BerTagging.Explicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> encodeSequence(s, inner, opts));
                    case BerTagging.Implicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> encodeSequenceContent(s, inner, opts));
                    case BerTagging.Unsupported(String reason) -> throw new EncodeException(reason);
                    default -> encodeSequence(s, out, opts);
                }
            }
            case MemberRef.SeqOf(Asn1SeqOf q) -> {
                Tag natural = q.naturalTag();
                switch (framing.resolve()) {
                    case BerTagging.Explicit(Tag tag) -> BerWriter.writeTagged(out, tag,
                            inner -> BerWriter.writeTagged(inner, natural, content -> encodeSeqOfContent(q, content, opts)));
                    case BerTagging.Implicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> encodeSeqOfContent(q, inner, opts));
                    case BerTagging.Unsupported(String reason) -> throw new EncodeException(reason);
                    default -> BerWriter.writeTagged(out, natural, inner -> encodeSeqOfContent(q, inner, opts));
                }
            }
            case MemberRef.Choice(Asn1Choice c) -> {
                switch (framing.resolve()) {
                    case BerTagging.Explicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> encodeChoice(c, inner, opts));
                    case BerTagging.Implicit(Tag tag) -> BerWriter.writeTagged(out, tag, inner -> encodeChoiceAlternative(c, inner, opts));
                    case BerTagging.Unsupported(String reason) -> throw new EncodeException(reason);
                    default -> encodeChoice(c, out, opts);
                }
            }
            case MemberRef.Contained(Asn1Contained f, ContainedSpec cs) ->
                BerPrimitive.encode(new Asn1OctetString(ContainedValues.wireOctets(f, cs, ContainedEncoding.BER, opts)), framing, out);
            default -> throw new EncodeException("BER encode of " + m.getClass().getSimpleName() + " is not supported yet");
        }
    }

    /**
     * Decode counterpart of {@link #encodeMemberRef}. A SEQUENCE/SET, CHOICE
     * or SEQUENCE OF/SET OF value enters one nesting level of {@code r}, so
     * a recursive type (X.680 §3.6.55) cannot recurse past
     * {@link io.github.schramp.gambasasn1.wire.io.Nesting#MAX_DECODE_DEPTH}.
     */
    public static void decodeMemberRef(MemberRef m, BerTagging framing, BerReader r) {
        Object node = r.positions() == null ? null : Positions.nodeOf(m);
        if (node != null) {
            r.markStart(node);
        }
        if (!(m instanceof MemberRef.Composite || m instanceof MemberRef.Choice || m instanceof MemberRef.SeqOf)) {
            decodeMemberRefLevel(m, framing, r);
        } else {
            r.enterLevel();
            try {
                decodeMemberRefLevel(m, framing, r);
            } finally {
                r.leaveLevel();
            }
        }
        if (node != null) {
            r.markEnd(node);
        }
    }

    /** The per-kind decode {@link #decodeMemberRef} dispatches to once it has counted the level. */
    private static void decodeMemberRefLevel(MemberRef m, BerTagging framing, BerReader r) {
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
                        decodeEnumerated(slot, ENUMERATED_TAG, r.nested(outer.value()));
                    }
                    case BerTagging.Unsupported(String reason) -> throw new DecodeException(reason, r.position());
                    default -> decodeEnumerated(slot, ENUMERATED_TAG, r);
                }
            }
            case MemberRef.Composite(Asn1Seq s) -> {
                switch (framing.resolve()) {
                    case BerTagging.Explicit(Tag tag) -> {
                        BerReader inner = enter(r, tag);
                        decodeSequence(s, inner);
                        expectEnd(inner, tag);
                    }
                    case BerTagging.Implicit(Tag tag) -> decodeSequenceContent(s, enter(r, tag), tag);
                    case BerTagging.Unsupported(String reason) -> throw new DecodeException(reason, r.position());
                    default -> decodeSequence(s, r);
                }
            }
            case MemberRef.SeqOf(Asn1SeqOf q) -> {
                Tag natural = q.naturalTag();
                switch (framing.resolve()) {
                    case BerTagging.Explicit(Tag tag) -> {
                        BerReader inner = enter(r, tag);
                        decodeSeqOfContent(q, enter(inner, natural));
                        expectEnd(inner, tag);
                    }
                    case BerTagging.Implicit(Tag tag) -> decodeSeqOfContent(q, enter(r, tag));
                    case BerTagging.Unsupported(String reason) -> throw new DecodeException(reason, r.position());
                    default -> decodeSeqOfContent(q, enter(r, natural));
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
            case MemberRef.Contained(Asn1Contained f, ContainedSpec cs) -> {
                // The inner value is decoded once the enclosing value is complete.
                Asn1OctetString raw = new Asn1OctetString();
                BerPrimitive.decode(raw, framing, r);
                f.setRawFromWire(raw.get(), ContainedEncoding.BER);
                if (r.positions() != null) {
                    // A primitive TLV ends with its contents (X.690 §8.1.1).
                    long end = r.absoluteEndBit(r.position());
                    r.positions().recordContents(f, end - 8L * raw.get().length, end);
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

    /** A SEQUENCE value under its type's own tag (X.690 §8.9). */
    private static void encodeSequence(Asn1Seq s, ByteSink out, ContainedOptions opts) {
        BerWriter.writeTagged(out, s.spec().tag(), inner -> encodeSequenceContent(s, inner, opts));
    }

    /**
     * A SEQUENCE's contents: each present member in table order under its
     * row's framing. An absent OPTIONAL member writes nothing (X.690 §8.9.2),
     * and neither does a member equal to its DEFAULT (X.690 §11.5).
     */
    private static void encodeSequenceContent(Asn1Seq s, ByteSink out, ContainedOptions opts) {
        List<MemberMeta> rows = s.spec().members();
        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i).optional() && s.isDefaultEqual(i)) {
                continue;
            }
            encodeMemberRef(s.getMember(i), rows.get(i).ber(), out, opts);
        }
    }

    /** Decode counterpart of {@link #encodeSequence}. */
    private static void decodeSequence(Asn1Seq s, BerReader r) {
        Tag tag = s.spec().tag();
        decodeSequenceContent(s, enter(r, tag), tag);
    }

    /**
     * Decodes a SEQUENCE's contents member by member. An OPTIONAL member is
     * present when the next tag is the one its row starts with; otherwise
     * it is set absent. Contained values (X.682 §11.4) are decoded once
     * every member is in place. Extension members are OPTIONAL rows, and BER
     * frames them like root members (X.690 §8.1.1.4). TLVs left after the
     * last member are unknown extension additions of an extensible type,
     * which are delimited and skipped (X.680 §7.1, §7.2); in a type without
     * an extension marker they are an error.
     */
    private static void decodeSequenceContent(Asn1Seq s, BerReader r, Tag tag) {
        SequenceSpec spec = s.spec();
        if (spec.isSet()) {
            r = setInTableOrder(s, r);
        }
        List<MemberMeta> rows = spec.members();
        boolean plain = r.options().plain();
        for (int i = 0; i < rows.size(); i++) {
            MemberMeta row = rows.get(i);
            if (row.optional()) {
                Tag next = r.peekTag();
                if (next == null || !row.ber().startsWith(row.tag(), next)) {
                    s.setDefault(i);
                    continue;
                }
            } else if (r.atEnd()) {
                throw new DecodeException("SEQUENCE " + spec.name() + ": mandatory member '" + row.name() + "' missing", r.position());
            }
            if (plain) {
                decodeMemberRef(s.presentMember(i), row.ber(), r);
            } else {
                decodePart(s.presentMember(i), row.ber(), row.constraints(), "." + row.name(), r);
            }
        }
        if (!spec.containedMembers().isEmpty()) {
            ContainedValues.decodeMembers(s, ContainedEncoding.BER, r);
        }
        if (spec.extAt() >= 0 || r.options().relaxed()) {
            while (!r.atEnd()) {
                r.readTlv();
            }
        } else if (!r.atEnd()) {
            throw new DecodeException("SEQUENCE " + spec.name() + ": unexpected octets after its last member", r.position());
        }
    }

    /**
     * A SET's component TLVs copied into member-table order, so the
     * sequential member walk can decode them: BER allows SET components in
     * any order (X.690 §8.11.2), and the table holds them in canonical tag
     * order (X.680 §8.6). A TLV no member matches goes last, where the walk
     * reports it.
     */
    private static BerReader setInTableOrder(Asn1Seq s, BerReader r) {
        List<MemberMeta> rows = s.spec().members();
        byte[][] slot = new byte[rows.size()][];
        long[] slotAt = new long[rows.size()];
        List<byte[]> unmatched = new ArrayList<>();
        List<Long> unmatchedAt = new ArrayList<>();
        ByteSource src = r.source();
        while (!r.atEnd()) {
            int start = src.position();
            Tag t = r.readTlv().tag();
            byte[] raw = src.bytesSince(start);
            long at = r.absoluteBit(start);
            int i = 0;
            while (i < rows.size() && (slot[i] != null || !setMemberMatches(s, i, t))) {
                i++;
            }
            if (i < rows.size()) {
                slot[i] = raw;
                slotAt[i] = at;
            } else {
                unmatched.add(raw);
                unmatchedAt.add(at);
            }
        }
        ByteSink out = new ByteSink();
        List<Integer> local = new ArrayList<>();
        List<Long> abs = new ArrayList<>();
        int len = 0;
        for (int i = 0; i < slot.length; i++) {
            if (slot[i] != null) {
                local.add(len);
                abs.add(slotAt[i]);
                len += slot[i].length;
                out.write(slot[i]);
            }
        }
        for (int i = 0; i < unmatched.size(); i++) {
            local.add(len);
            abs.add(unmatchedAt.get(i));
            len += unmatched.get(i).length;
            out.write(unmatched.get(i));
        }
        if (r.positions() == null || local.isEmpty()) {
            return r.nested(out.toByteArray());
        }
        return r.nestedPieces(out.toByteArray(), local.stream().mapToInt(Integer::intValue).toArray(),
                abs.stream().mapToLong(Long::longValue).toArray());
    }

    /**
     * Whether SET member {@code i} starts with wire tag {@code t}: an
     * untagged CHOICE member by one of its alternatives' tags, any other
     * member by its row's tag.
     */
    private static boolean setMemberMatches(Asn1Seq s, int i, Tag t) {
        MemberMeta row = s.spec().members().get(i);
        if (row.ber() instanceof BerTagging.Delegate && s.getMember(i) instanceof MemberRef.Choice(Asn1Choice c)
                && c.spec().ownTag() == null) {
            return dispatch(c.spec().berTags(), t) >= 0;
        }
        return row.ber().startsWith(row.tag(), t);
    }

    /**
     * A SEQUENCE OF's contents: each element under the element type's own
     * framing (X.690 §8.10). A SET OF's elements go in DER order, by their
     * encodings as unsigned octet strings (X.690 §11.6).
     */
    private static void encodeSeqOfContent(Asn1SeqOf q, ByteSink out, ContainedOptions opts) {
        BerTagging framing = q.elemBerFraming();
        if (q.naturalTag().number() == UniversalTag.SET && q.size() > 1) {
            List<byte[]> parts = new ArrayList<>(q.size());
            for (int i = 0; i < q.size(); i++) {
                ByteSink part = new ByteSink();
                encodeMemberRef(q.get(i), framing, part, opts);
                parts.add(part.toByteArray());
            }
            parts.sort(Arrays::compareUnsigned);
            for (byte[] p : parts) {
                out.write(p);
            }
            return;
        }
        for (int i = 0; i < q.size(); i++) {
            encodeMemberRef(q.get(i), framing, out, opts);
        }
    }

    /**
     * Decodes a SEQUENCE OF's contents: the collection is emptied, then one
     * element is appended and decoded per TLV until the contents end.
     */
    private static void decodeSeqOfContent(Asn1SeqOf q, BerReader r) {
        BerTagging framing = q.elemBerFraming();
        q.clear();
        if (r.options().plain()) {
            while (!r.atEnd()) {
                decodeMemberRef(q.addDefault(), framing, r);
            }
            return;
        }
        for (int i = 0; !r.atEnd(); i++) {
            decodePart(q.addDefault(), framing, Constraints.UNCONSTRAINED, "[" + i + "]", r);
        }
    }

    /**
     * A CHOICE value: its own tag, when the type has one, wraps the selected
     * alternative (X.680 §31.2.7: a tagged CHOICE is always EXPLICIT).
     */
    private static void encodeChoice(Asn1Choice c, ByteSink out, ContainedOptions opts) {
        Tag own = c.spec().ownTag();
        if (own != null) {
            BerWriter.writeTagged(out, own, inner -> encodeChoiceAlternative(c, inner, opts));
        } else {
            encodeChoiceAlternative(c, out, opts);
        }
    }

    /**
     * The selected alternative under its row's framing (X.690 §8.13), or an
     * unknown extension alternative replayed as it was read (X.680 §6).
     */
    private static void encodeChoiceAlternative(Asn1Choice c, ByteSink out, ContainedOptions opts) {
        int i = c.activeIndex();
        if (i >= 0) {
            encodeMemberRef(c.getActive(), c.spec().alternatives().get(i).ber(), out, opts);
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
            if (r.options().plain()) {
                decodeMemberRef(c.select(alt), row.ber(), r);
            } else {
                decodePart(c.select(alt), row.ber(), row.constraints(), "." + row.name(), r);
            }
            if (spec.hasContained()) {
                ContainedValues.decodeAlternative(c, ContainedEncoding.BER, r);
            }
            return;
        }
        if (spec.extAt() < 0 && !r.options().relaxed()) {
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
        return r.nested(tlv.value());
    }

    /** A tag's contents hold exactly one encoding (X.690 §8.14.2). */
    private static void expectEnd(BerReader inner, Tag tag) {
        if (!inner.atEnd() && !inner.options().relaxed()) {
            throw new DecodeException("trailing octets inside tag " + tag, inner.position());
        }
    }
}
