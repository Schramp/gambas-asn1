package io.github.schramp.gambasasn1.wire.per;

import io.github.schramp.gambasasn1.wire.DecodeOptions;
import io.github.schramp.gambasasn1.wire.ber.BerReader;
import io.github.schramp.gambasasn1.wire.ber.Tag;
import io.github.schramp.gambasasn1.wire.containing.ContainedOptions;
import io.github.schramp.gambasasn1.wire.containing.ContainedValues;
import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.io.Nesting;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.Asn1Contained;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.Asn1SeqOf;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.ConstraintCheck;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.spec.ChoiceSpec;
import io.github.schramp.gambasasn1.wire.spec.ContainedEncoding;
import io.github.schramp.gambasasn1.wire.spec.ContainedSpec;
import io.github.schramp.gambasasn1.wire.spec.Decoded;
import io.github.schramp.gambasasn1.wire.spec.Positions;
import io.github.schramp.gambasasn1.wire.spec.ExtUnit;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import io.github.schramp.gambasasn1.wire.spec.SequenceSpec;
import io.github.schramp.gambasasn1.wire.types.Asn1BitString;
import io.github.schramp.gambasasn1.wire.types.Asn1OctetString;
import io.github.schramp.gambasasn1.wire.types.Asn1Primitive;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The unaligned PER walker (X.691): one complete encoding per value,
 * driven by the reflective {@link MemberRef} shape of the generated tables;
 * no type has PER code of its own. Constructs whose PER fields are not
 * written yet fail the encode or decode.
 */
public final class PerObject {
    private PerObject() {
    }

    /**
     * Encodes {@code v} as one complete encoding, under its own PDU constraints when it is a PDU.
     *
     * @throws EncodeException if {@code v} has no PER encoding: a CHOICE with no alternative
     *         selected, or a value outside its type's PER-visible constraints (X.691)
     */
    public static byte[] encode(AsMemberRef v) {
        return encode(v, rootConstraints(v));
    }

    /**
     * {@link #encode(AsMemberRef)} under the constraints {@code c} of {@code v}'s type.
     *
     * @throws EncodeException if {@code v} has no PER encoding: a CHOICE with no alternative
     *         selected, or a value outside its type's PER-visible constraints (X.691)
     */
    public static byte[] encode(AsMemberRef v, Constraints c) {
        PerWriter w = new PerWriter();
        encodeValue(v.asMemberRef(), c, w);
        return w.toByteArray();
    }

    /**
     * {@link #encode(AsMemberRef)} with contained-value settings; {@code opts} may be null.
     *
     * @throws EncodeException if {@code v} has no PER encoding: a CHOICE with no alternative
     *         selected, or a value outside its type's PER-visible constraints (X.691)
     */
    public static byte[] encode(AsMemberRef v, ContainedOptions opts) {
        PerWriter w = new PerWriter().withContained(opts);
        encodeValue(v.asMemberRef(), rootConstraints(v), w);
        return w.toByteArray();
    }

    /**
     * Decodes one complete encoding into {@code v}; only the padding of
     * X.691 §11.1.3.1 may follow it, or the one zero octet that stands for
     * an empty encoding.
     *
     * @throws DecodeException if {@code data} is not a valid PER encoding of the type of {@code v}
     *         followed by its padding only: malformed or truncated input, nesting deeper than
     *         {@code Nesting.MAX_DECODE_DEPTH} levels, or, with constraint checks on, a value that breaks
     *         its type's constraints; {@link DecodeException#position()} is the byte offset where decoding
     *         stopped
     */
    public static void decode(AsMemberRef v, byte[] data) throws DecodeException {
        decode(v, data, rootConstraints(v));
    }

    /**
     * {@link #decode(AsMemberRef, byte[])} under the constraints {@code c} of {@code v}'s type.
     *
     * @throws DecodeException if {@code data} is not a valid PER encoding of the type of {@code v}
     *         followed by its padding only: malformed or truncated input, nesting deeper than
     *         {@code Nesting.MAX_DECODE_DEPTH} levels, or, with constraint checks on, a value that breaks
     *         its type's constraints; {@link DecodeException#position()} is the byte offset where decoding
     *         stopped
     */
    public static void decode(AsMemberRef v, byte[] data, Constraints c) throws DecodeException {
        decodeWhole(v, data, c, new PerReader(data));
    }

    /**
     * {@link #decode(AsMemberRef, byte[])} under the decoder settings
     * {@code opts} ({@link DecodeOptions#DEFAULT} for the defaults; a null
     * also means the defaults, cast to {@code DecodeOptions}).
     *
     * @throws DecodeException if {@code data} is not a valid PER encoding of the type of {@code v}
     *         followed by its padding only: malformed or truncated input, nesting deeper than
     *         {@code Nesting.MAX_DECODE_DEPTH} levels, or, with constraint checks on, a value that breaks
     *         its type's constraints; {@link DecodeException#position()} is the byte offset where decoding
     *         stopped
     */
    public static void decode(AsMemberRef v, byte[] data, DecodeOptions opts) throws DecodeException {
        decode(v, data, rootConstraints(v), opts);
    }

    /**
     * {@link #decode(AsMemberRef, byte[], DecodeOptions)} under the constraints {@code c} of {@code v}'s type.
     *
     * @throws DecodeException if {@code data} is not a valid PER encoding of the type of {@code v}
     *         followed by its padding only: malformed or truncated input, nesting deeper than
     *         {@code Nesting.MAX_DECODE_DEPTH} levels, or, with constraint checks on, a value that breaks
     *         its type's constraints; {@link DecodeException#position()} is the byte offset where decoding
     *         stopped
     */
    public static void decode(AsMemberRef v, byte[] data, Constraints c, DecodeOptions opts) throws DecodeException {
        decodeWhole(v, data, c, new PerReader(data).withOptions(opts));
    }

    /**
     * Decodes {@code data}, one complete encoding, into {@code v}: after
     * the value only the padding of its last octet may follow, or, relaxed,
     * anything. With rich errors on, an error names the type and shows the
     * input there.
     */
    private static void decodeWhole(AsMemberRef v, byte[] data, Constraints c, PerReader r) throws DecodeException {
        MemberRef m = v.asMemberRef();
        try {
            if (r.options().trace() != null) {
                trace(r, typeName(m), m);
            }
            decodeValue(m, c, r);
            boolean emptyEncoding = r.bitPos() == 0 && data.length == 1 && data[0] == 0;
            if (r.remaining() >= 8 && !emptyEncoding && !r.options().relaxed()) {
                throw r.error("PER: trailing data after the value");
            }
        } catch (DecodeException e) {
            if (!r.options().richErrors()) {
                throw e;
            }
            int at = (int) Math.min(e.position(), data.length);
            throw e.within(typeName(m)).showing(java.util.Arrays.copyOfRange(data, at,
                    Math.min(data.length, at + DecodeException.CONTEXT_OCTETS)));
        }
    }

    /** Writes the trace line for {@code m}, about to be decoded as {@code segment}; tracing must be on. */
    private static void trace(PerReader r, String segment, MemberRef m) {
        r.options().trace().accept("PER bit " + r.absoluteBit(r.bitPos()) + " " + segment + " " + typeName(m));
    }

    /** The ASN.1 name of {@code m}'s type, for an error path. */
    private static String typeName(MemberRef m) {
        return switch (m) {
            case MemberRef.Composite(var s) -> s.spec().name();
            case MemberRef.Choice(var c) -> c.spec().name();
            case MemberRef.Primitive(var p, var owner) -> p.xerElementName();
            case MemberRef.SeqOf(var q) -> q.ownXerName();
            case MemberRef.Enumerated(var e, var spec) -> spec.name();
            default -> m.getClass().getSimpleName();
        };
    }

    /**
     * Decodes one member, alternative or element of the value being
     * decoded ({@link #decodeValue}): traced when tracing is on, and with
     * its path segment added to an error when errors are rich. The segment
     * is only built for a trace line or an error.
     *
     * @param m     the part to fill
     * @param c     the part's constraints
     * @param name  the member or alternative name; null for an element
     * @param index the element's index, when {@code name} is null
     * @param r     the reader at the part's first bit
     */
    private static void decodePart(MemberRef m, Constraints c, String name, int index, PerReader r) throws DecodeException {
        if (r.options().trace() != null) {
            trace(r, segment(name, index), m);
        }
        try {
            decodeValue(m, c, r);
        } catch (DecodeException e) {
            throw r.options().richErrors() ? e.within(segment(name, index)) : e;
        }
    }

    /**
     * The path segment of a part, as {@link DecodeException#path()} shows it.
     *
     * @param name  the member or alternative name; null for an element
     * @param index the element's index, when {@code name} is null
     * @return {@code ".name"} or {@code "[index]"}
     */
    private static String segment(String name, int index) {
        return name != null ? "." + name : "[" + index + "]";
    }

    /**
     * Decodes one complete encoding from the start of {@code r}'s data into
     * {@code v}, for a contained value whose bytes may be followed by
     * padding a decoder removes.
     *
     * @return the octets the encoding takes, its padding included (X.691 §11.1.3.1)
     * @throws DecodeException if the start of the data of {@code r} is not a valid PER encoding of
     *         the type of {@code v}: malformed or truncated input, nesting deeper than
     *         {@code Nesting.MAX_DECODE_DEPTH} levels, or, with constraint checks on, a value that breaks
     *         its type's constraints; {@link DecodeException#position()} is the byte offset where decoding
     *         stopped
     */
    public static int decodePrefix(AsMemberRef v, PerReader r) throws DecodeException {
        decodeValue(v.asMemberRef(), rootConstraints(v), r);
        return (int) Math.max(1, (r.bitPos() + 7) / 8);
    }

    /**
     * {@link #decode(AsMemberRef, byte[], DecodeOptions)} that also records
     * where every decoded node starts, in bits from the start of
     * {@code data}. {@code opts} may be null.
     *
     * @throws DecodeException if {@code data} is not a valid PER encoding of the type of {@code v}
     *         followed by its padding only: malformed or truncated input, nesting deeper than
     *         {@code Nesting.MAX_DECODE_DEPTH} levels, or, with constraint checks on, a value that breaks
     *         its type's constraints; {@link DecodeException#position()} is the byte offset where decoding
     *         stopped
     */
    public static Decoded decodeWithPositions(AsMemberRef v, byte[] data, DecodeOptions opts) throws DecodeException {
        Positions p = Positions.recording();
        PerReader r = new PerReader(data).withOptions(opts).withPositions(p, 0);
        decodeWhole(v, data, rootConstraints(v), r);
        return new Decoded((int) Math.max(1, (r.bitPos() + 7) / 8), p);
    }

    private static Constraints rootConstraints(AsMemberRef v) {
        return v instanceof Asn1Pdu p ? p.pduConstraints() : Constraints.UNCONSTRAINED;
    }

    /**
     * Appends {@code m}'s fields.
     *
     * @param c the value's own constraints
     */
    static void encodeValue(MemberRef m, Constraints c, PerWriter w) {
        switch (m) {
            case MemberRef.Unsupported(String reason) -> throw new EncodeException(reason);
            case MemberRef.Primitive(var p, var owner) -> PerPrimitive.encode(p, c, w);
            case MemberRef.Enumerated(var slot, var spec) -> PerPrimitive.encodeEnumerated(slot, spec, w);
            case MemberRef.Composite(Asn1Seq s) -> encodeSequence(s, w);
            case MemberRef.Choice(Asn1Choice ch) -> encodeChoice(ch, w);
            case MemberRef.SeqOf(Asn1SeqOf q) -> encodeSeqOf(q, c, w);
            case MemberRef.Contained(Asn1Contained f, ContainedSpec cs) -> PerPrimitive.encode(
                    new Asn1OctetString(ContainedValues.wireOctets(f, cs, ContainedEncoding.PER_UNALIGNED, w.contained())), c, w);
            default -> throw new EncodeException("PER: " + m.getClass().getSimpleName() + " is not supported yet");
        }
    }

    /** Decode counterpart of {@link #encodeValue}; a constructed value counts one nesting level. */
    static void decodeValue(MemberRef m, Constraints c, PerReader r) throws DecodeException {
        Object node = r.positions() == null ? null : Positions.nodeOf(m);
        if (node != null) {
            r.markStart(node);
            r.positions().recordOwner(Positions.ownerOf(m), node);
        }
        long start = r.bitPos();
        if (!(m instanceof MemberRef.Composite || m instanceof MemberRef.Choice || m instanceof MemberRef.SeqOf)) {
            decodeLevel(m, c, r);
        } else {
            r.enterLevel();
            try {
                decodeLevel(m, c, r);
            } finally {
                r.leaveLevel();
            }
        }
        if (node != null) {
            r.markEnd(node);
        }
        if (r.options().checkConstraints()) {
            String why = ConstraintCheck.violation(m, c);
            if (why != null) {
                long at = r.absoluteBit(start);
                throw new DecodeException("constraint violated: " + why + " (bit " + at + ")", (int) (at >>> 3));
            }
        }
    }

    /**
     * Records where the value of an OCTET STRING or BIT STRING just read
     * lies: its octets or bits come last, after any length determinant
     * (X.691 §16, §17). A length of 16K or more is sent in fragments with a
     * length determinant before each (X.691 §11.9.3.8), so no single span
     * holds the value and none is recorded.
     */
    private static void markValue(Asn1Primitive p, PerReader r) {
        long n = switch (p) {
            case Asn1OctetString o -> o.get().length < 16384 ? 8L * o.get().length : -1;
            case Asn1BitString b -> b.bitCount() < 16384 ? b.bitCount() : -1;
            default -> -1;
        };
        if (n >= 0) {
            long end = r.absoluteBit(r.bitPos());
            r.positions().recordValue(p, end - n, end);
        }
    }

    private static void decodeLevel(MemberRef m, Constraints c, PerReader r) throws DecodeException {
        switch (m) {
            case MemberRef.Unsupported(String reason) -> throw r.error(reason);
            case MemberRef.Primitive(var p, var owner) -> {
                PerPrimitive.decode(p, c, r);
                if (r.positions() != null) {
                    markValue(p, r);
                }
            }
            case MemberRef.Enumerated(var slot, var spec) -> PerPrimitive.decodeEnumerated(slot, spec, r);
            case MemberRef.Composite(Asn1Seq s) -> decodeSequence(s, r);
            case MemberRef.Choice(Asn1Choice ch) -> decodeChoice(ch, r);
            case MemberRef.SeqOf(Asn1SeqOf q) -> decodeSeqOf(q, c, r);
            case MemberRef.Contained(Asn1Contained f, ContainedSpec cs) -> {
                // The inner value is decoded once the enclosing value is complete.
                Asn1OctetString raw = new Asn1OctetString();
                PerPrimitive.decode(raw, c, r);
                f.setRawFromWire(raw.get(), ContainedEncoding.PER_UNALIGNED);
                if (r.positions() != null) {
                    // The octets follow their length determinant (X.691 §17.8).
                    long end = r.absoluteBit(r.bitPos());
                    r.positions().recordContents(f, end - 8L * raw.get().length, end);
                }
            }
            default -> throw r.error("PER: " + m.getClass().getSimpleName() + " is not supported yet");
        }
    }

    /** The members before the extension marker. */
    private static int rootEnd(SequenceSpec spec) {
        return spec.extAt() >= 0 ? spec.extAt() : spec.members().size();
    }

    /** Present and, for a DEFAULT member, not equal to its default: written on the wire (X.691 §19.5). */
    private static boolean sent(Asn1Seq s, int i) {
        return !(s.getMember(i) instanceof MemberRef.Absent) && !s.isDefaultEqual(i);
    }

    /** One extension addition (X.691 §19.9): its members {@code begin..end}, a group or one component. */
    private record Addition(int begin, int end, boolean group) {
    }

    /** The extension additions from the table's precomputed units; without units, one per extension member. */
    private static List<Addition> additions(SequenceSpec spec) {
        int begin = rootEnd(spec);
        List<Addition> out = new ArrayList<>();
        if (spec.extUnits().isEmpty()) {
            for (int i = begin; i < spec.members().size(); i++) {
                out.add(new Addition(i, i + 1, false));
            }
            return out;
        }
        for (ExtUnit u : spec.extUnits()) {
            out.add(new Addition(begin, u.end(), u.group()));
            begin = u.end();
        }
        return out;
    }

    private static boolean anySent(Asn1Seq s, Addition a) {
        for (int i = a.begin(); i < a.end(); i++) {
            if (sent(s, i)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A SEQUENCE, or a SET in the table's canonical member order (X.691 §21):
     * the extension bit (§19.1), one presence bit per OPTIONAL or DEFAULT
     * root member (§19.2; {@code romsCount} of them), the root members
     * present (§19.4), then, with the extension bit set, the additions' count
     * as a normally small length, their presence bits (§19.7, §19.8) and each
     * present addition as an open-type field (§19.9).
     */
    static void encodeSequence(Asn1Seq s, PerWriter w) {
        SequenceSpec spec = s.spec();
        int end = rootEnd(spec);
        List<Addition> additions = spec.extAt() >= 0 ? additions(spec) : List.of();
        boolean extended = false;
        for (Addition a : additions) {
            extended |= anySent(s, a);
        }
        if (spec.extAt() >= 0) {
            w.putBits(extended ? 1 : 0, 1);
        }
        if (spec.romsCount() >= 65536) {
            throw new EncodeException("PER: " + spec.name() + " has 64K or more optional root members");
        }
        for (int i = 0; i < end; i++) {
            if (spec.members().get(i).optional()) {
                w.putBits(sent(s, i) ? 1 : 0, 1);
            }
        }
        for (int i = 0; i < end; i++) {
            if (spec.members().get(i).optional() ? sent(s, i) : true) {
                encodeMember(s, i, w);
            }
        }
        if (!extended) {
            return;
        }
        PerLength.putNormallySmallLength(w, additions.size());
        for (Addition a : additions) {
            w.putBits(anySent(s, a) ? 1 : 0, 1);
        }
        for (Addition a : additions) {
            if (!anySent(s, a)) {
                continue;
            }
            PerWriter field = new PerWriter().withContained(w.contained());
            if (a.group()) {
                encodeGroup(s, a, field);
            } else {
                encodeMember(s, a.begin(), field);
            }
            PerLength.putOctets(w, field.toByteArray());
        }
    }

    private static void encodeMember(Asn1Seq s, int i, PerWriter w) {
        MemberRef m = s.getMember(i);
        if (m instanceof MemberRef.Absent) {
            throw new EncodeException("PER: " + s.spec().name() + "." + s.spec().members().get(i).name()
                    + " is absent but not OPTIONAL");
        }
        encodeValue(m, s.spec().members().get(i).constraints(), w);
    }

    /**
     * An extension addition group as the sequence of its members (X.691
     * §19.9): a presence bit per member declared OPTIONAL or DEFAULT inside
     * the group, then the members present. A present group carries all its
     * mandatory members (X.680 §25.13).
     */
    private static void encodeGroup(Asn1Seq s, Addition a, PerWriter w) {
        List<Boolean> optional = s.spec().groupMemberOptional();
        for (int i = a.begin(); i < a.end(); i++) {
            if (optional.get(i)) {
                w.putBits(sent(s, i) ? 1 : 0, 1);
            }
        }
        for (int i = a.begin(); i < a.end(); i++) {
            if (sent(s, i)) {
                encodeMember(s, i, w);
            } else if (!optional.get(i)) {
                throw new EncodeException("PER: extension group member " + s.spec().members().get(i).name() + " is absent");
            }
        }
    }

    /**
     * Decode counterpart of {@link #encodeSequence}. An absent OPTIONAL or
     * DEFAULT member takes its DEFAULT; an addition this table does not know
     * is skipped by its length (X.691 §19.9).
     */
    static void decodeSequence(Asn1Seq s, PerReader r) throws DecodeException {
        SequenceSpec spec = s.spec();
        int end = rootEnd(spec);
        boolean extended = spec.extAt() >= 0 && r.getBits(1) == 1;
        boolean[] present = new boolean[spec.romsCount()];
        for (int k = 0; k < present.length; k++) {
            present[k] = r.getBits(1) == 1;
        }
        int k = 0;
        for (int i = 0; i < end; i++) {
            if (spec.members().get(i).optional() && !present[k++]) {
                s.setDefault(i);
                continue;
            }
            decodePart(s.presentMember(i), spec.members().get(i).constraints(), spec.members().get(i).name(), i, r);
        }
        List<Addition> additions = spec.extAt() >= 0 ? additions(spec) : List.of();
        boolean[] sent = new boolean[0];
        if (extended) {
            int n = PerLength.getNormallySmallLength(r);
            sent = new boolean[n];
            for (int j = 0; j < n; j++) {
                sent[j] = r.getBits(1) == 1;
            }
            for (int j = 0; j < n; j++) {
                if (!sent[j]) {
                    continue;
                }
                byte[] field = PerLength.getOctets(r);
                if (j >= additions.size()) {
                    continue;
                }
                Addition a = additions.get(j);
                PerReader in = r.subJustRead(field);
                if (a.group()) {
                    decodeGroup(s, a, in);
                } else {
                    decodePart(s.presentMember(a.begin()), spec.members().get(a.begin()).constraints(),
                            spec.members().get(a.begin()).name(), a.begin(), in);
                }
            }
        }
        for (int j = 0; j < additions.size(); j++) {
            if (j >= sent.length || !sent[j]) {
                Addition a = additions.get(j);
                for (int i = a.begin(); i < a.end(); i++) {
                    s.setDefault(i);
                }
            }
        }
        if (!spec.containedMembers().isEmpty()) {
            ContainedValues.decodeMembers(s, ContainedEncoding.PER_UNALIGNED, berAnchor(r));
        }
    }

    /**
     * The decode context a contained value's inner decode starts from: this
     * decode's nesting depth and contained-value settings.
     */
    private static BerReader berAnchor(PerReader r) throws DecodeException {
        BerReader b = new BerReader(new byte[0]).withOptions(r.options()).withPositions(r.positions());
        for (int i = 0; i < r.depth(); i++) {
            b.enterLevel();
        }
        return b;
    }

    /**
     * Decodes an extension addition group from its open type: a presence
     * bit for each optional member, then the present members in order;
     * absent ones take their default.
     *
     * @param s the SEQUENCE being decoded
     * @param a the group's members
     * @param r a reader over the group's open-type octets
     * @see "X.691 §19.9"
     */
    private static void decodeGroup(Asn1Seq s, Addition a, PerReader r) throws DecodeException {
        List<Boolean> optional = s.spec().groupMemberOptional();
        boolean[] present = new boolean[a.end() - a.begin()];
        for (int i = a.begin(); i < a.end(); i++) {
            present[i - a.begin()] = !optional.get(i) || r.getBits(1) == 1;
        }
        for (int i = a.begin(); i < a.end(); i++) {
            if (present[i - a.begin()]) {
                decodePart(s.presentMember(i), s.spec().members().get(i).constraints(),
                        s.spec().members().get(i).name(), i, r);
            } else {
                s.setDefault(i);
            }
        }
    }

    /** The alternatives before the extension marker. */
    private static int rootCount(ChoiceSpec spec) {
        return spec.extAt() >= 0 ? spec.extAt() : spec.alternatives().size();
    }

    /**
     * A CHOICE (X.691 §23): the extension bit of an extensible type, then a
     * root alternative's index in the table's {@code rangeBits} (§23.6) and
     * its value, or an extension alternative's index as a normally small
     * number and its value as an open-type field (§23.8). The alternatives
     * are in the table in the canonical order of their tags (§23.3).
     */
    static void encodeChoice(Asn1Choice ch, PerWriter w) {
        ChoiceSpec spec = ch.spec();
        int i = ch.activeIndex();
        if (i < 0) {
            throw new EncodeException("CHOICE " + spec.name() + ": no alternative selected");
        }
        int root = rootCount(spec);
        boolean inExt = spec.extAt() >= 0 && i >= root;
        if (spec.extAt() >= 0) {
            w.putBits(inExt ? 1 : 0, 1);
        }
        Constraints c = spec.alternatives().get(i).constraints();
        if (!inExt) {
            w.putBits(i, spec.rangeBits());
            encodeValue(ch.getActive(), c, w);
            return;
        }
        PerLength.putNormallySmall(w, i - root);
        PerWriter field = new PerWriter().withContained(w.contained());
        encodeValue(ch.getActive(), c, field);
        PerLength.putOctets(w, field.toByteArray());
    }

    /**
     * Decode counterpart of {@link #encodeChoice}. An extension alternative
     * this table does not know is kept as an unknown extension: its open-type
     * contents under a context tag numbered by its extension index.
     */
    static void decodeChoice(Asn1Choice ch, PerReader r) throws DecodeException {
        ChoiceSpec spec = ch.spec();
        int root = rootCount(spec);
        boolean inExt = spec.extAt() >= 0 && r.getBits(1) == 1;
        if (!inExt) {
            long i = r.getBits(spec.rangeBits());
            if (i >= root) {
                throw r.error("PER: CHOICE " + spec.name() + " index " + i + " outside its " + root + " root alternatives");
            }
            decodePart(ch.select((int) i), spec.alternatives().get((int) i).constraints(),
                    spec.alternatives().get((int) i).name(), (int) i, r);
            decodeContainedAlternative(ch, r);
            return;
        }
        long ext = PerLength.getNormallySmall(r);
        byte[] field = PerLength.getOctets(r);
        if (ext >= spec.alternatives().size() - root) {
            if (ext > Integer.MAX_VALUE) {
                throw r.error("PER: CHOICE " + spec.name() + " extension index " + ext + " beyond any table");
            }
            ch.setUnknownExtension(new Asn1Choice.UnknownExtension(Tag.context((int) ext, false), field));
            return;
        }
        int i = root + (int) ext;
        decodePart(ch.select(i), spec.alternatives().get(i).constraints(), spec.alternatives().get(i).name(), i,
                r.subJustRead(field));
        decodeContainedAlternative(ch, r);
    }

    private static void decodeContainedAlternative(Asn1Choice ch, PerReader r) throws DecodeException {
        if (ch.spec().hasContained()) {
            ContainedValues.decodeAlternative(ch, ContainedEncoding.PER_UNALIGNED, berAnchor(r));
        }
    }

    /** An element's encoding and its exact length in bits. */
    private record Part(byte[] bytes, long bits) {
    }

    /**
     * A SEQUENCE OF or SET OF (X.691 §20, §22): the count under the type's
     * SIZE, with the extension bit of an extensible SIZE (§20.4), then the
     * elements under the element constraints; a SET OF's elements in the
     * order of §22.1.
     *
     * @param c the collection's own constraints
     */
    static void encodeSeqOf(Asn1SeqOf q, Constraints c, PerWriter w) {
        Constraints elem = c.element() != null ? c.element() : Constraints.UNCONSTRAINED;
        if (q.naturalTag().number() == 17 && q.size() > 1) {
            List<Part> parts = sortedSetOfParts(q, elem, w);
            PerLength.putExtSize(w, c, parts.size(), (out, from, to) -> {
                for (Part p : parts.subList(from, to)) {
                    out.putBitString(p.bytes(), p.bits());
                }
            });
            return;
        }
        PerLength.putExtSize(w, c, q.size(), (out, from, to) -> {
            for (int i = from; i < to; i++) {
                encodeValue(q.get(i), elem, out);
            }
        });
    }

    /**
     * A SET OF's element encodings in ascending order, compared as octet
     * strings padded with zero bits and the shorter extended with zero
     * octets (X.691 §22.1, the CANONICAL-PER order, also valid BASIC-PER);
     * asn1c and the C++ and Rust runtimes write the same order.
     */
    private static List<Part> sortedSetOfParts(Asn1SeqOf q, Constraints elem, PerWriter w) {
        List<Part> parts = new ArrayList<>(q.size());
        for (int i = 0; i < q.size(); i++) {
            PerWriter one = new PerWriter().withContained(w.contained());
            encodeValue(q.get(i), elem, one);
            parts.add(new Part(one.toByteArray(), one.bitPos()));
        }
        parts.sort((a, b) -> {
            int n = Math.max(a.bytes().length, b.bytes().length);
            byte[] x = Arrays.copyOf(a.bytes(), n);
            byte[] y = Arrays.copyOf(b.bytes(), n);
            return Arrays.compareUnsigned(x, y);
        });
        return parts;
    }

    /**
     * Decode counterpart of {@link #encodeSeqOf}; a SET OF is taken in any
     * order. A list counting more than {@link Nesting#MAX_ZERO_WIDTH_ITEMS}
     * items fails when its first element is encoded in zero bits (checked
     * once per length fragment).
     *
     * @param q the collection the elements are appended to, emptied first
     * @param c the list's constraints, its element constraints included
     * @param r the reader at the length determinant
     * @throws DecodeException for a malformed or bomb-sized list
     * @see "X.691 §20.6, §11.9.3.8"
     */
    static void decodeSeqOf(Asn1SeqOf q, Constraints c, PerReader r) throws DecodeException {
        Constraints elem = c.element() != null ? c.element() : Constraints.UNCONSTRAINED;
        q.clear();
        // A length of 16K items or more comes in fragments (X.691 §11.9.3.8),
        // each handed over on its own, so an element's index is the count so far.
        PerLength.getExtSize(r, c, (in, count) -> {
            if (count == 0) {
                return;
            }
            // Only a type with a single value encodes in zero bits, so the
            // first element tells for all of them.
            long before = in.bitPos();
            int first = q.size();
            decodePart(q.addDefault(), elem, null, first, in);
            if (count > Nesting.MAX_ZERO_WIDTH_ITEMS && in.bitPos() == before) {
                throw in.error("PER: more than " + Nesting.MAX_ZERO_WIDTH_ITEMS + " items encoded in zero bits");
            }
            for (int i = 1; i < count; i++) {
                int index = q.size();
                decodePart(q.addDefault(), elem, null, index, in);
            }
        });
    }
}
