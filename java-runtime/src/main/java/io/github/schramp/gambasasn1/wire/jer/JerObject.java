package io.github.schramp.gambasasn1.wire.jer;

import io.github.schramp.gambasasn1.wire.io.DecodeException;
import io.github.schramp.gambasasn1.wire.io.EncodeException;
import io.github.schramp.gambasasn1.wire.spec.AsMemberRef;
import io.github.schramp.gambasasn1.wire.spec.Asn1Pdu;
import io.github.schramp.gambasasn1.wire.spec.Constraints;
import io.github.schramp.gambasasn1.wire.spec.MemberRef;

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

    /** Writes {@code m} as one JSON value. */
    static void encodeValue(MemberRef m, Constraints c, JerWriter w) {
        switch (m) {
            case MemberRef.Primitive(var p) -> JerPrimitive.encode(p, c, w);
            case MemberRef.Enumerated(var slot, var spec) -> JerPrimitive.encodeEnumerated(slot, spec, w);
            case MemberRef.Unsupported(String reason) -> throw new EncodeException(reason);
            default -> throw new EncodeException("JER: " + m.getClass().getSimpleName() + " values are not encoded yet");
        }
    }

    /** Decode counterpart of {@link #encodeValue}. */
    static void decodeValue(MemberRef m, Constraints c, JerReader r) {
        switch (m) {
            case MemberRef.Primitive(var p) -> JerPrimitive.decode(p, c, r);
            case MemberRef.Enumerated(var slot, var spec) -> JerPrimitive.decodeEnumerated(slot, spec, r);
            case MemberRef.Unsupported(String reason) -> throw new DecodeException(reason, r.position());
            default -> throw new DecodeException(
                    "JER: " + m.getClass().getSimpleName() + " values are not decoded yet", r.position());
        }
    }
}
