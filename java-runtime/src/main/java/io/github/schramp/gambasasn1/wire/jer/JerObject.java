package io.github.schramp.gambasasn1.wire.jer;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AltMeta;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Choice;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.Asn1Seq;
import io.github.schramp.gambasasn1.wire.spec.Asn1SeqOf;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.spec.MemberMeta;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;
import java.util.List;

/**
 * The JER walker (X.697): one JSON value per ASN.1 value, driven by the
 * reflective {@link MemberRef} shape of the generated tables; no type has
 * JER code of its own.
 */
public final class JerObject {
    private JerObject() {
    }

    /** Encodes {@code v} as one JER text, under its own PDU constraints when it is a PDU. */
    public static byte[] encode(AsMemberRef v) {
        return encode(v, rootConstraints(v));
    }

    /** {@link #encode(AsMemberRef)} under the constraints {@code c} of {@code v}'s type. */
    public static byte[] encode(AsMemberRef v, Constraints c) {
        JerWriter w = new JerWriter();
        encodeValue(v.asMemberRef(), c, w);
        return w.toByteArray();
    }

    /** Decodes one JER text into {@code v}; only whitespace may follow it. */
    public static void decode(AsMemberRef v, byte[] data) {
        decode(v, data, rootConstraints(v));
    }

    /** {@link #decode(AsMemberRef, byte[])} under the constraints {@code c} of {@code v}'s type. */
    public static void decode(AsMemberRef v, byte[] data, Constraints c) {
        JerReader r = new JerReader(data);
        decodeValue(v.asMemberRef(), c, r);
        if (!r.atEnd()) {
            throw new DecodeException("JER: trailing data after the value", r.position());
        }
    }

    private static Constraints rootConstraints(AsMemberRef v) {
        return v instanceof Asn1Pdu p ? p.pduConstraints() : Constraints.UNCONSTRAINED;
    }

    /**
     * Writes {@code m} as one JSON value.
     *
     * @param c the value's own constraints; a SEQUENCE OF passes its
     *          element entry on to every element
     */
    static void encodeValue(MemberRef m, Constraints c, JerWriter w) {
        switch (m) {
            case MemberRef.Absent a -> {
            }
            case MemberRef.Unsupported(String reason) -> throw new EncodeException(reason);
            case MemberRef.Primitive(var p) -> JerPrimitive.encode(p, c, w);
            case MemberRef.Enumerated(var slot, var spec) -> JerPrimitive.encodeEnumerated(slot, spec, w);
            case MemberRef.Composite(Asn1Seq s) -> encodeSequence(s, w);
            case MemberRef.Choice(Asn1Choice ch) -> encodeChoice(ch, w);
            case MemberRef.SeqOf(Asn1SeqOf q) -> encodeSeqOf(q, c, w);
            case MemberRef.Contained cv -> throw new EncodeException("JER: contained values are not encoded yet");
        }
    }

    /**
     * Decode counterpart of {@link #encodeValue}; a SEQUENCE, CHOICE or
     * SEQUENCE OF counts one nesting level.
     */
    static void decodeValue(MemberRef m, Constraints c, JerReader r) {
        if (!(m instanceof MemberRef.Composite || m instanceof MemberRef.Choice || m instanceof MemberRef.SeqOf)) {
            decodeLevel(m, c, r);
            return;
        }
        r.enterLevel();
        try {
            decodeLevel(m, c, r);
        } finally {
            r.leaveLevel();
        }
    }

    private static void decodeLevel(MemberRef m, Constraints c, JerReader r) {
        switch (m) {
            case MemberRef.Absent a -> {
            }
            case MemberRef.Unsupported(String reason) -> throw new DecodeException(reason, r.position());
            case MemberRef.Primitive(var p) -> JerPrimitive.decode(p, c, r);
            case MemberRef.Enumerated(var slot, var spec) -> JerPrimitive.decodeEnumerated(slot, spec, r);
            case MemberRef.Composite(Asn1Seq s) -> decodeSequence(s, r);
            case MemberRef.Choice(Asn1Choice ch) -> decodeChoice(ch, r);
            case MemberRef.SeqOf(Asn1SeqOf q) -> decodeSeqOf(q, c, r);
            case MemberRef.Contained cv -> throw new DecodeException("JER: contained values are not decoded yet", r.position());
        }
    }

    /** An object of the present members, each named by its identifier (X.697 §27.3). */
    private static void encodeSequence(Asn1Seq s, JerWriter w) {
        List<MemberMeta> members = s.spec().members();
        w.ascii("{");
        boolean first = true;
        for (int i = 0; i < members.size(); i++) {
            MemberRef m = s.getMember(i);
            if (m instanceof MemberRef.Absent) {
                continue;
            }
            if (!first) {
                w.ascii(",");
            }
            first = false;
            w.string(members.get(i).name()).ascii(":");
            encodeValue(m, members.get(i).constraints(), w);
        }
        w.ascii("}");
    }

    /**
     * Members in any order; a key no member has is skipped (an extension
     * this table does not know). An OPTIONAL or DEFAULT member left out is
     * set to absent or its DEFAULT; any other is an error.
     */
    private static void decodeSequence(Asn1Seq s, JerReader r) {
        List<MemberMeta> members = s.spec().members();
        boolean[] seen = new boolean[members.size()];
        r.expect('{');
        while (true) {
            int c = r.peek();
            if (c == '}') {
                r.expect('}');
                break;
            }
            if (c == ',') {
                r.expect(',');
                continue;
            }
            if (c == 0) {
                throw new DecodeException("JER: unexpected end in object", r.position());
            }
            String key = r.readStringText();
            r.expect(':');
            int i = indexOf(members, key);
            if (i < 0) {
                r.skipValue();
                continue;
            }
            decodeValue(s.presentMember(i), members.get(i).constraints(), r);
            seen[i] = true;
        }
        for (int i = 0; i < members.size(); i++) {
            if (seen[i]) {
                continue;
            }
            if (!members.get(i).optional()) {
                throw new DecodeException("JER: missing required member: " + members.get(i).name(), r.position());
            }
            s.setDefault(i);
        }
    }

    private static int indexOf(List<MemberMeta> members, String key) {
        for (int i = 0; i < members.size(); i++) {
            if (members.get(i).name().equals(key)) {
                return i;
            }
        }
        return -1;
    }

    /** A one-member object named by the selected alternative (X.697 §31.3). */
    private static void encodeChoice(Asn1Choice ch, JerWriter w) {
        int i = ch.activeIndex();
        if (i < 0) {
            throw new EncodeException("CHOICE " + ch.spec().name() + ": no alternative selected");
        }
        AltMeta alt = ch.spec().alternatives().get(i);
        w.ascii("{").string(alt.name()).ascii(":");
        encodeValue(ch.getActive(), alt.constraints(), w);
        w.ascii("}");
    }

    private static void decodeChoice(Asn1Choice ch, JerReader r) {
        r.expect('{');
        if (r.consumeIf('}')) {
            return;
        }
        String key = r.readStringText();
        r.expect(':');
        List<AltMeta> alts = ch.spec().alternatives();
        for (int i = 0; i < alts.size(); i++) {
            if (alts.get(i).name().equals(key)) {
                decodeValue(ch.select(i), alts.get(i).constraints(), r);
                r.expect('}');
                return;
            }
        }
        throw new DecodeException("JER: CHOICE " + ch.spec().name() + ": unknown alternative: " + key, r.position());
    }

    /** An array of the elements (X.697 §28, §30), each under the collection's element constraints. */
    private static void encodeSeqOf(Asn1SeqOf q, Constraints c, JerWriter w) {
        Constraints elem = c.element() != null ? c.element() : Constraints.UNCONSTRAINED;
        w.ascii("[");
        for (int i = 0; i < q.size(); i++) {
            if (i > 0) {
                w.ascii(",");
            }
            encodeValue(q.get(i), elem, w);
        }
        w.ascii("]");
    }

    private static void decodeSeqOf(Asn1SeqOf q, Constraints c, JerReader r) {
        Constraints elem = c.element() != null ? c.element() : Constraints.UNCONSTRAINED;
        q.clear();
        r.expect('[');
        while (true) {
            int ch = r.peek();
            if (ch == ']') {
                r.expect(']');
                return;
            }
            if (ch == ',') {
                r.expect(',');
                continue;
            }
            if (ch == 0) {
                throw new DecodeException("JER: unexpected end in array", r.position());
            }
            decodeValue(q.addDefault(), elem, r);
        }
    }
}
